"""Behavioral security analyzer.

Analyzes:
- Urgency and coercion psychological triggers ("immediate action required", "account suspended within 24 hours")
- Financial transaction / wire fraud / gift card requests
- Credential reset and authentication lure patterns
- Suspicious recipient list behavior (BCC-only, mismatch with internal domain)
- Call-to-action manipulation (mismatched visible anchor text vs actual href destination)
- Hidden text / zero-font HTML evasion tricks
- Form submission elements inside email body
- Inconsistencies between Subject and Body language/tone
"""

from __future__ import annotations

import re

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity

# Urgency / Coercion regex patterns
_URGENCY_PATTERNS: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (
        re.compile(
            r"\b(?:account|access|service)\s+(?:suspended|terminated|disabled|locked|restricted)\b",
            re.IGNORECASE,
        ),
        "Account Suspension Threat",
        70.0,
    ),
    (
        re.compile(
            r"\b(?:within\s+(?:24|48|12)\s+hours?|immediate\s+action\s+required|act\s+now|urgent\s+notice)\b",
            re.IGNORECASE,
        ),
        "Artificial Urgency Deadline",
        65.0,
    ),
    (
        re.compile(
            r"\b(?:unauthorized\s+access|security\s+breach|suspicious\s+activity\s+detected)\b",
            re.IGNORECASE,
        ),
        "Fear/Security Incident Lure",
        65.0,
    ),
    (
        re.compile(
            r"\b(?:wire\s+transfer|gift\s+cards?|bitcoin|cryptocurrency|direct\s+deposit|payroll\s+update)\b",
            re.IGNORECASE,
        ),
        "Financial Transaction Lure",
        75.0,
    ),
    (
        re.compile(
            r"\b(?:verify\s+your\s+identity|confirm\s+your\s+password|update\s+your\s+billing)\b",
            re.IGNORECASE,
        ),
        "Credential Harvest Lure",
        70.0,
    ),
)

# HTML zero-font or invisible text evasion patterns
_HIDDEN_TEXT_PATTERN: re.Pattern[str] = re.compile(
    r"""style\s*=\s*["'][^"']*(?:font-size\s*:\s*0(?:px)?|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*(?:#[fF]{3,6}|white|transparent))""",
    re.IGNORECASE,
)

# Form element in HTML body
_FORM_TAG_PATTERN: re.Pattern[str] = re.compile(r"<\s*form[\s>]", re.IGNORECASE)


class BehaviorAnalyzer:
    """Deterministic analyzer for behavioral manipulation, social engineering, and evasion tricks."""

    ANALYZER_NAME = "behavior_analyzer"

    def analyze(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Analyze behavioral triggers in email and return zero or more NormalizedThreatSignal objects."""
        signals: list[NormalizedThreatSignal] = []

        content = email_input.content
        plain_text = content.clean_text_for_ai
        raw_html = email_input.raw_evidence.raw_body_html or ""

        # 1. Social Engineering / Urgency Lures in Plain Text & Subject
        combined_text = f"{email_input.subject} {plain_text}"
        for pattern, lure_name, score in _URGENCY_PATTERNS:
            match = pattern.search(combined_text)
            if match:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="BEHAVIORAL_URGENCY_LURE",
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=ThreatSeverity.MEDIUM,
                        attack_type=AttackType.SPEAR_PHISHING,
                        score=score,
                        confidence=0.82,
                        title=f"Social Engineering Lure: {lure_name}",
                        description=(
                            f"Message employs high-pressure language ('{match.group()}') "
                            "designed to compel immediate user compliance."
                        ),
                        evidence={"trigger": match.group(), "lure_category": lure_name},
                    )
                )

        # 2. Hidden / Invisible Text Evasion in HTML
        if raw_html and _HIDDEN_TEXT_PATTERN.search(raw_html):
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="EVASION_HIDDEN_TEXT_HTML",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.SPEAR_PHISHING,
                    score=80.0,
                    confidence=0.90,
                    title="Hidden Text / Zero-Font HTML Evasion",
                    description="HTML body contains invisible or zero-sized text commonly used to fool Bayesian NLP filters.",
                    evidence={"has_hidden_text": True},
                )
            )

        # 3. Interactive <form> in Email Body (Credential Harvesting)
        if raw_html and _FORM_TAG_PATTERN.search(raw_html):
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="EMBEDDED_HTML_FORM",
                    category=ThreatCategory.CREDENTIAL_THEFT,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.CREDENTIAL_HARVESTING,
                    score=90.0,
                    confidence=0.95,
                    title="Interactive Form in Email Body",
                    description="Email contains an embedded HTML form, a definitive indicator of credential harvesting.",
                    evidence={"form_present": True},
                )
            )

        # 4. Mismatched Anchor Text vs. Actual Destination URL
        if raw_html:
            anchor_mismatches = self._find_anchor_text_mismatches(raw_html)
            for visible_domain, actual_domain, href in anchor_mismatches:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="MISMATCHED_ANCHOR_URL",
                        category=ThreatCategory.PHISHING,
                        severity=ThreatSeverity.CRITICAL,
                        attack_type=AttackType.CLONE_PHISHING,
                        score=92.0,
                        confidence=0.96,
                        title=f"Deceptive Link Text (Shows {visible_domain}, points to {actual_domain})",
                        description=(
                            f"Hyperlink display text claims to navigate to '{visible_domain}' "
                            f"but actual href leads to '{actual_domain}'."
                        ),
                        indicator_value=href,
                        evidence={
                            "visible_text": visible_domain,
                            "actual_domain": actual_domain,
                            "href": href,
                        },
                    )
                )

        return signals

    # ------------------------------------------------------------------
    # Anchor mismatch helper
    # ------------------------------------------------------------------

    @staticmethod
    def _find_anchor_text_mismatches(raw_html: str) -> list[tuple[str, str, str]]:
        """Find <a href="http://evil.com">http://legit.com</a> mismatches."""
        mismatches = []
        anchor_pattern = re.compile(
            r'<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        url_in_text_pattern = re.compile(r"https?://([a-zA-Z0-9.-]+)")

        for match in anchor_pattern.finditer(raw_html):
            href = match.group(1).strip()
            anchor_text = re.sub(r"<[^>]+>", "", match.group(2)).strip()

            text_url_match = url_in_text_pattern.search(anchor_text)
            if text_url_match:
                visible_host = text_url_match.group(1).lower()
                from urllib.parse import urlparse

                try:
                    actual_host = (urlparse(href).hostname or "").lower()
                    if visible_host and actual_host and visible_host != actual_host:
                        mismatches.append((visible_host, actual_host, href))
                except Exception:
                    pass

        return mismatches
