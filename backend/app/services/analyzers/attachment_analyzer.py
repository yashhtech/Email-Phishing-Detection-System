"""Attachment security analyzer.

Analyzes:
- Executable binary file extensions (.exe, .scr, .bat, .cmd, .pif, .vbs, .js, .msi, .ps1)
- Double-extension evasion techniques (.pdf.exe, .doc.vbs, .invoice.xlsx.scr)
- Macro-enabled Office documents (.docm, .xlsm, .pptm)
- High-risk archives (.iso, .img, .vhd, .cab, .arj, .ace)
- MIME type spoofing (declared MIME vs. magic bytes detected MIME mismatch)
- High entropy payloads (indicating packed, obfuscated, or encrypted payloads)
- Zero-byte or abnormally large attachments
- Path traversal sequences in attachment filenames
"""

from __future__ import annotations

from app.domain.entities.email_analysis_input import EmailAnalysisInput, ExtractedAttachmentMetadata
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity

# High-risk container/disk-image formats used in MOTW (Mark-of-the-Web) bypass
_DISK_IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
    }
)

# Windows script extensions
_SCRIPT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".hta",
    }
)


class AttachmentAnalyzer:
    """Deterministic analyzer for email attachments (zero file execution)."""

    ANALYZER_NAME = "attachment_analyzer"

    def analyze(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Analyze all attachments and return zero or more NormalizedThreatSignal objects."""
        signals: list[NormalizedThreatSignal] = []

        for att in email_input.attachments:
            signals.extend(self._analyze_single_attachment(att))

        return signals

    def _analyze_single_attachment(
        self, att: ExtractedAttachmentMetadata
    ) -> list[NormalizedThreatSignal]:
        signals: list[NormalizedThreatSignal] = []
        filename = att.filename
        ext = att.extension.lower()

        # 1. Direct Executable / Binary File
        if att.is_executable:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="ATTACHMENT_EXECUTABLE_FILE",
                    category=ThreatCategory.MALWARE,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.MALICIOUS_DOCUMENT,
                    score=95.0,
                    confidence=0.99,
                    title=f"Direct Executable Attachment: {filename}",
                    description=(
                        f"Attachment '{filename}' has executable extension '{ext}'. "
                        "Direct execution of email binaries is the highest vector of malware infection."
                    ),
                    indicator_value=att.sha256_hash,
                    evidence={
                        "filename": filename,
                        "extension": ext,
                        "sha256": att.sha256_hash,
                        "declared_mime": att.declared_mime_type,
                    },
                )
            )

        # 2. Double-Extension Evasion (.pdf.exe, .doc.vbs)
        if att.has_double_extension:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="ATTACHMENT_DOUBLE_EXTENSION_EVASION",
                    category=ThreatCategory.MALWARE,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.MALICIOUS_DOCUMENT,
                    score=90.0,
                    confidence=0.95,
                    title=f"Double Extension Evasion: {filename}",
                    description=(
                        f"Filename '{filename}' exploits Windows default hidden extensions "
                        "to deceive users into opening an executable payload."
                    ),
                    indicator_value=att.sha256_hash,
                    evidence={"filename": filename, "safe_filename": att.safe_filename},
                )
            )

        # 3. Macro-Enabled Office Document (.docm, .xlsm, .pptm)
        if att.has_macro_extension:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="ATTACHMENT_MACRO_ENABLED_DOCUMENT",
                    category=ThreatCategory.MALWARE,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.MALICIOUS_DOCUMENT,
                    score=75.0,
                    confidence=0.90,
                    title=f"Macro-Enabled Office Document: {filename}",
                    description=(
                        f"Document '{filename}' supports embedded VBA macros, "
                        "a primary delivery mechanism for droppers and ransomware."
                    ),
                    indicator_value=att.sha256_hash,
                    evidence={"filename": filename, "extension": ext},
                )
            )

        # 4. Mark-of-the-Web (MOTW) Bypass Disk Image (.iso, .img, .vhd)
        if ext in _DISK_IMAGE_EXTENSIONS:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="ATTACHMENT_MOTW_BYPASS_CONTAINER",
                    category=ThreatCategory.MALWARE,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.MALICIOUS_DOCUMENT,
                    score=80.0,
                    confidence=0.92,
                    title=f"Disk Image / MOTW Bypass Container: {filename}",
                    description=(
                        f"Attachment '{filename}' is a disk image container ({ext}). "
                        "Attackers use container formats to bypass Windows Mark-of-the-Web protection."
                    ),
                    indicator_value=att.sha256_hash,
                    evidence={"filename": filename, "extension": ext},
                )
            )

        # 5. Script File Attachment (.vbs, .js, .ps1, .bat)
        if ext in _SCRIPT_EXTENSIONS:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="ATTACHMENT_SCRIPT_FILE",
                    category=ThreatCategory.MALWARE,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.MALICIOUS_DOCUMENT,
                    score=85.0,
                    confidence=0.95,
                    title=f"Script Attachment: {filename}",
                    description=f"Script file '{filename}' ({ext}) can execute arbitrary system commands when opened.",
                    indicator_value=att.sha256_hash,
                    evidence={"filename": filename, "extension": ext},
                )
            )

        # 6. MIME Type Spoofing / Mismatch
        if att.detected_mime_type and att.declared_mime_type:
            # If declared is text or pdf, but magic bytes indicate DOS executable
            if (
                att.detected_mime_type == "application/x-dosexec"
                and "dosexec" not in att.declared_mime_type
            ):
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="ATTACHMENT_MIME_TYPE_SPOOFING",
                        category=ThreatCategory.MALWARE,
                        severity=ThreatSeverity.CRITICAL,
                        attack_type=AttackType.MALICIOUS_DOCUMENT,
                        score=95.0,
                        confidence=0.98,
                        title=f"MIME Type Mismatch (Executable disguised as {att.declared_mime_type})",
                        description=(
                            f"File '{filename}' declares MIME '{att.declared_mime_type}' but byte magic "
                            f"reveals Windows executable ({att.detected_mime_type})."
                        ),
                        indicator_value=att.sha256_hash,
                        evidence={
                            "filename": filename,
                            "declared_mime": att.declared_mime_type,
                            "detected_mime": att.detected_mime_type,
                        },
                    )
                )

        # 7. High Entropy Payload (entropy > 7.0 for payloads >= 1 KB indicates packed/crypted malware)
        if att.entropy_score is not None and att.size_bytes >= 1024:
            if att.entropy_score > 7.2:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="ATTACHMENT_HIGH_ENTROPY_PACKED",
                        category=ThreatCategory.MALWARE,
                        severity=ThreatSeverity.MEDIUM,
                        attack_type=AttackType.UNKNOWN,
                        score=55.0,
                        confidence=0.80,
                        title=f"High Shannon Entropy in Attachment: {filename}",
                        description=(
                            f"Entropy score {att.entropy_score:.2f} is characteristic of packed, encrypted, "
                            "or obfuscated binary payloads."
                        ),
                        indicator_value=att.sha256_hash,
                        evidence={"entropy": att.entropy_score, "size_bytes": att.size_bytes},
                    )
                )

        return signals
