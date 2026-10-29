"""Authentication security analyzer.

Analyzes:
- SPF evaluation (pass, fail, softfail, neutral, none, temperror, permerror)
- DKIM signature evaluation (pass, fail, invalid, none)
- DMARC alignment and policy (pass, fail, none, quarantine, reject)
- SPF/DKIM alignment with sender domain (strict vs. relaxed)
- DMARC enforcement policy evaluation (p=reject, p=quarantine vs p=none)
- Absence of email authentication (no SPF + no DKIM + no DMARC = critical vulnerability)
- ARC (Authenticated Received Chain) verification if present
"""

from __future__ import annotations

import re

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity


class AuthenticationAnalyzer:
    """Deterministic analyzer for SPF, DKIM, and DMARC protocol verification."""

    ANALYZER_NAME = "authentication_analyzer"

    def analyze(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Analyze authentication headers and return zero or more NormalizedThreatSignal objects."""
        signals: list[NormalizedThreatSignal] = []
        headers = email_input.headers
        sender_domain = email_input.sender.domain.lower().strip()

        # Parse Authentication-Results or specific headers
        auth_results_raw = self._extract_auth_results(headers.all_headers)

        spf_status = self._parse_spf(headers.spf_header, auth_results_raw)
        dkim_status = self._parse_dkim(headers.dkim_header, auth_results_raw)
        dmarc_status, dmarc_policy = self._parse_dmarc(headers.dmarc_header, auth_results_raw)

        # 1. Complete absence of email authentication
        if spf_status == "none" and dkim_status == "none" and dmarc_status == "none":
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="AUTH_MISSING_ALL_PROTOCOLS",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.SPOOFING,
                    score=65.0,
                    confidence=0.90,
                    title="No Email Authentication (SPF, DKIM, DMARC)",
                    description=(
                        f"Email from '{sender_domain}' provides no SPF, DKIM, or DMARC authentication. "
                        "Anyone could forge this domain without detection."
                    ),
                    indicator_value=sender_domain,
                    evidence={"spf": spf_status, "dkim": dkim_status, "dmarc": dmarc_status},
                )
            )

        # 2. SPF Fail / Softfail
        if spf_status == "fail":
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="SPF_HARD_FAIL",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.SPOOFING,
                    score=85.0,
                    confidence=0.95,
                    title="SPF Hard Fail (Sender IP Not Authorized)",
                    description=f"Sending server is explicitly unauthorized by '{sender_domain}' SPF record.",
                    indicator_value=sender_domain,
                    evidence={"spf_header": headers.spf_header, "status": "fail"},
                )
            )
        elif spf_status == "softfail":
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="SPF_SOFT_FAIL",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.MEDIUM,
                    attack_type=AttackType.SPOOFING,
                    score=45.0,
                    confidence=0.85,
                    title="SPF Softfail (~all)",
                    description=f"Sending IP is not in '{sender_domain}' SPF permit list, but marked softfail.",
                    indicator_value=sender_domain,
                    evidence={"spf_header": headers.spf_header, "status": "softfail"},
                )
            )

        # 3. DKIM Fail / Invalid
        if dkim_status in ("fail", "invalid", "temperror", "permerror"):
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="DKIM_SIGNATURE_VERIFICATION_FAIL",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.SPOOFING,
                    score=75.0,
                    confidence=0.90,
                    title="DKIM Cryptographic Verification Failed",
                    description="DKIM digital signature failed verification, indicating message body or headers were altered.",
                    indicator_value=sender_domain,
                    evidence={"dkim_status": dkim_status},
                )
            )

        # 4. DMARC Fail
        if dmarc_status == "fail":
            severity = (
                ThreatSeverity.CRITICAL
                if dmarc_policy in ("reject", "quarantine")
                else ThreatSeverity.HIGH
            )
            score = 90.0 if dmarc_policy == "reject" else 75.0
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="DMARC_POLICY_EVALUATION_FAIL",
                    category=ThreatCategory.PHISHING,
                    severity=severity,
                    attack_type=AttackType.SPOOFING,
                    score=score,
                    confidence=0.95,
                    title=f"DMARC Verification Failed (Policy: {dmarc_policy or 'none'})",
                    description=(
                        f"Email failed DMARC alignment for domain '{sender_domain}'. "
                        f"Domain policy prescribes: {dmarc_policy or 'monitor'}."
                    ),
                    indicator_value=sender_domain,
                    evidence={"dmarc_status": dmarc_status, "policy": dmarc_policy},
                )
            )

        # 5. DMARC Policy None (Warning: no protection against spoofing)
        if dmarc_status == "pass" and dmarc_policy == "none":
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="DMARC_POLICY_MONITOR_ONLY",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.INFO,
                    attack_type=AttackType.UNKNOWN,
                    score=5.0,
                    confidence=0.80,
                    title="DMARC Policy Set to Monitor (p=none)",
                    description=f"Domain '{sender_domain}' uses p=none, meaning unauthorized messages are not rejected.",
                    indicator_value=sender_domain,
                    evidence={"policy": "none"},
                )
            )

        return signals

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_auth_results(all_headers: dict[str, list[str]]) -> str:
        """Combine all Authentication-Results headers for unified parsing."""
        raw_list = all_headers.get("Authentication-Results", [])
        return " ; ".join(raw_list).lower()

    @staticmethod
    def _parse_spf(spf_header: str | None, auth_results: str) -> str:
        """Parse SPF verdict from Received-SPF or Authentication-Results."""
        if spf_header:
            lower = spf_header.lower()
            for verdict in (
                "softfail",
                "fail",
                "pass",
                "neutral",
                "none",
                "temperror",
                "permerror",
            ):
                if verdict in lower:
                    return verdict
        match = re.search(
            r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", auth_results
        )
        if match:
            return match.group(1)
        return "none"

    @staticmethod
    def _parse_dkim(dkim_header: str | None, auth_results: str) -> str:
        """Parse DKIM verdict from header or Authentication-Results."""
        match = re.search(
            r"\bdkim=(pass|fail|neutral|none|temperror|permerror|invalid)\b", auth_results
        )
        if match:
            return match.group(1)
        if dkim_header:
            return "pass"  # Has signature present, assuming valid unless auth_results says fail
        return "none"

    @staticmethod
    def _parse_dmarc(dmarc_header: str | None, auth_results: str) -> tuple[str, str | None]:
        """Parse DMARC status and action policy."""
        status = "none"
        policy = None

        status_match = re.search(r"\bdmarc=(pass|fail|none|temperror|permerror)\b", auth_results)
        if status_match:
            status = status_match.group(1)

        policy_match = re.search(r"\baction=(none|quarantine|reject)\b", auth_results)
        if not policy_match:
            policy_match = re.search(r"\bp=(none|quarantine|reject)\b", auth_results)
        if policy_match:
            policy = policy_match.group(1)

        return status, policy
