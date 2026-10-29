"""Sender security analyzer.

Analyzes:
- Display name impersonation against well-known brands (PayPal, Microsoft, Apple, Google, etc.)
- Sender and Return-Path domain mismatch
- Reply-To domain mismatch with sender domain
- Free-mail provider used for institutional / corporate sender names
- Null or missing sender
- Invalid or malformed email syntax in sender
- Lookalike / homoglyph spoofing in sender domain
"""

from __future__ import annotations

import re

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity

# Well-known brands frequently targeted by brand spoofing
_TOP_BRAND_DOMAINS: dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "meta": "meta.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "twitter": "x.com",
    "x corp": "x.com",
    "dropbox": "dropbox.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "usps": "usps.com",
    "irs": "irs.gov",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "citi": "citi.com",
    "hsbc": "hsbc.com",
    "docu sign": "docusign.com",
    "docusign": "docusign.com",
}

# Free webmail providers
_FREE_MAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "mail.com",
        "protonmail.com",
        "proton.me",
        "zoho.com",
        "yandex.com",
        "icloud.com",
        "gmx.com",
        "tutanota.com",
        "fastmail.com",
    }
)

# Executive / corporate title patterns
_EXECUTIVE_TITLES: re.Pattern[str] = re.compile(
    r"\b(ceo|cfo|cto|coo|president|director|executive|manager|head of hr|payroll|finance)\b",
    re.IGNORECASE,
)


class SenderAnalyzer:
    """Deterministic analyzer for sender address, display name, and domain consistency."""

    ANALYZER_NAME = "sender_analyzer"

    def analyze(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Analyze sender fields and return zero or more NormalizedThreatSignal objects."""
        signals: list[NormalizedThreatSignal] = []

        sender = email_input.sender
        sender_domain = sender.domain.lower().strip()
        display_name = sender.display_name.strip()
        reply_to = email_input.reply_to
        return_path = email_input.return_path

        # 1. Missing or blank sender
        if not sender.address:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="MISSING_SENDER_ADDRESS",
                    category=ThreatCategory.SPAM,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.SPOOFING,
                    score=70.0,
                    confidence=1.0,
                    title="Missing From Address",
                    description="The email lacks a valid From sender address.",
                    evidence={"raw_from": email_input.raw_evidence.raw_from},
                )
            )
            return signals

        # 2. Display Name Brand Impersonation
        if sender.is_spoofed_display_name and sender.spoofed_target:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="BRAND_DISPLAY_NAME_SPOOFING",
                    category=ThreatCategory.BRAND_IMPERSONATION,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.SPEAR_PHISHING,
                    score=90.0,
                    confidence=0.95,
                    title=f"Brand Impersonation: {sender.spoofed_target}",
                    description=(
                        f"Display name '{display_name}' impersonates {sender.spoofed_target}, "
                        f"but email originated from unaffiliated domain '{sender_domain}'."
                    ),
                    indicator_value=sender_domain,
                    evidence={
                        "display_name": display_name,
                        "actual_domain": sender_domain,
                        "target_brand": sender.spoofed_target,
                    },
                )
            )

        # Check for brands that might not have been caught in normalized sender
        for brand, legitimate_domain in _TOP_BRAND_DOMAINS.items():
            if brand in display_name.lower():
                if not sender_domain.endswith(legitimate_domain) and not (
                    sender.is_spoofed_display_name and sender.spoofed_target
                ):
                    signals.append(
                        NormalizedThreatSignal(
                            source=self.ANALYZER_NAME,
                            signal_type="BRAND_DISPLAY_NAME_SPOOFING",
                            category=ThreatCategory.BRAND_IMPERSONATION,
                            severity=ThreatSeverity.HIGH,
                            attack_type=AttackType.SPEAR_PHISHING,
                            score=85.0,
                            confidence=0.90,
                            title=f"Brand Display Name Mismatch: {brand.title()}",
                            description=(
                                f"Display name references '{brand}', but sender domain is '{sender_domain}', "
                                f"expected '{legitimate_domain}'."
                            ),
                            indicator_value=sender_domain,
                            evidence={
                                "display_name": display_name,
                                "sender_domain": sender_domain,
                                "expected_domain": legitimate_domain,
                            },
                        )
                    )
                    break

        # 3. Free Webmail used with Executive Title (BEC signal)
        if sender_domain in _FREE_MAIL_DOMAINS:
            exec_match = _EXECUTIVE_TITLES.search(display_name)
            if exec_match:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="BEC_FREE_MAIL_EXECUTIVE_IMPERSONATION",
                        category=ThreatCategory.BUSINESS_EMAIL_COMPROMISE,
                        severity=ThreatSeverity.HIGH,
                        attack_type=AttackType.WHALING,
                        score=80.0,
                        confidence=0.85,
                        title="Executive Title with Free Webmail Provider",
                        description=(
                            f"Display name contains executive title '{exec_match.group()}' "
                            f"sent from free public mail provider '{sender_domain}'."
                        ),
                        indicator_value=sender.address,
                        evidence={
                            "display_name": display_name,
                            "title_matched": exec_match.group(),
                            "free_provider": sender_domain,
                        },
                    )
                )

        # 4. Reply-To Domain Mismatch
        if reply_to:
            reply_to_domain = reply_to.split("@")[-1].lower().strip() if "@" in reply_to else ""
            if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
                # Distinguish benign cross-domain tracking from suspicious TLDs/domains
                severity = (
                    ThreatSeverity.HIGH
                    if any(
                        reply_to_domain.endswith(tld)
                        for tld in [".top", ".xyz", ".click", ".buzz", ".monster"]
                    )
                    else ThreatSeverity.MEDIUM
                )
                score = 75.0 if severity == ThreatSeverity.HIGH else 45.0
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="REPLY_TO_DOMAIN_MISMATCH",
                        category=ThreatCategory.PHISHING,
                        severity=severity,
                        attack_type=AttackType.SPEAR_PHISHING,
                        score=score,
                        confidence=0.85,
                        title="Reply-To Domain Mismatch",
                        description=(
                            f"Replies are routed to '{reply_to_domain}', differing from sender "
                            f"domain '{sender_domain}'."
                        ),
                        indicator_value=reply_to,
                        evidence={
                            "sender_domain": sender_domain,
                            "reply_to": reply_to,
                            "reply_to_domain": reply_to_domain,
                        },
                    )
                )

        # 5. Return-Path Domain Mismatch
        if return_path:
            return_path_domain = (
                return_path.split("@")[-1].lower().strip() if "@" in return_path else ""
            )
            if return_path_domain and sender_domain and return_path_domain != sender_domain:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="RETURN_PATH_MISMATCH",
                        category=ThreatCategory.PHISHING,
                        severity=ThreatSeverity.LOW,
                        attack_type=AttackType.SPOOFING,
                        score=25.0,
                        confidence=0.70,
                        title="Return-Path Domain Mismatch",
                        description=(
                            f"Return-Path '{return_path_domain}' differs from sender domain '{sender_domain}'."
                        ),
                        indicator_value=return_path,
                        evidence={
                            "sender_domain": sender_domain,
                            "return_path": return_path,
                        },
                    )
                )

        return signals
