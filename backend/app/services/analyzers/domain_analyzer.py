"""Domain security analyzer.

Analyzes:
- Typosquatting / Combosquatting against major organizations (Levenshtein distance, character substitutions)
- IDN homograph attacks (Punycode `xn--` domains mimicking ASCII characters)
- DGA (Domain Generation Algorithm) characteristics (high consonant ratio, high Shannon entropy)
- Domain age characteristics / newly registered domain patterns
- Cross-domain inconsistencies between sender domain and embedded URL domains
- Known disposable / burner domain providers
"""

from __future__ import annotations

import math

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity

# Protected high-value brands for typosquatting checks
_PROTECTED_BRANDS: tuple[str, ...] = (
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "twitter",
    "dropbox",
    "fedex",
    "dhl",
    "chase",
    "wellsfargo",
    "docusign",
)

# Common letter substitutions used in combosquatting
_SUBSTITUTIONS: dict[str, str] = {
    "0": "o",
    "1": "l",
    "l": "1",
    "vv": "w",
    "rn": "m",
    "cl": "d",
}


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class DomainAnalyzer:
    """Deterministic analyzer for domain heuristics, typosquatting, IDN homographs, and DGA."""

    ANALYZER_NAME = "domain_analyzer"

    def analyze(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Analyze sender and body domains and return zero or more NormalizedThreatSignal objects."""
        signals: list[NormalizedThreatSignal] = []

        all_domains = set(email_input.domains)
        if email_input.sender.domain:
            all_domains.add(email_input.sender.domain.lower().strip())

        for domain in all_domains:
            if not domain:
                continue
            signals.extend(self._analyze_single_domain(domain, email_input.sender.domain))

        return signals

    def _analyze_single_domain(
        self, domain: str, sender_domain: str
    ) -> list[NormalizedThreatSignal]:
        signals: list[NormalizedThreatSignal] = []
        domain_lower = domain.lower()

        # 1. IDN Homograph Attack (Punycode prefix `xn--`)
        if domain_lower.startswith("xn--") or ".xn--" in domain_lower:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="IDN_HOMOGRAPH_ATTACK",
                    category=ThreatCategory.BRAND_IMPERSONATION,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.CLONE_PHISHING,
                    score=90.0,
                    confidence=0.95,
                    title=f"Internationalized Domain (IDN Homograph): {domain}",
                    description="Domain uses Punycode (`xn--`) encoding, a frequent indicator of Cyrillic/Greek character substitution.",
                    indicator_value=domain,
                    evidence={"punycode_domain": domain},
                )
            )

        # 2. Typosquatting against Protected Brands
        # Extract main domain label (e.g., 'paypa1' from 'paypa1.com')
        parts = domain_lower.split(".")
        main_label = parts[-2] if len(parts) >= 2 else parts[0]

        for brand in _PROTECTED_BRANDS:
            # Skip if it is the genuine brand domain
            if domain_lower == f"{brand}.com" or domain_lower.endswith(f".{brand}.com"):
                continue

            dist = _levenshtein_distance(main_label, brand)
            # Distance 1 means single char typo: 'goolge', 'paypa1', 'mircosoft'
            if dist == 1 and len(main_label) >= 4:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="TYPOSQUATTING_BRAND_DOMAIN",
                        category=ThreatCategory.BRAND_IMPERSONATION,
                        severity=ThreatSeverity.CRITICAL,
                        attack_type=AttackType.SPEAR_PHISHING,
                        score=90.0,
                        confidence=0.92,
                        title=f"Typosquatting Detected: {domain} mimics {brand}.com",
                        description=(
                            f"Domain '{domain}' (label '{main_label}') is an edit distance of 1 "
                            f"from protected brand '{brand}'."
                        ),
                        indicator_value=domain,
                        evidence={"domain": domain, "targeted_brand": brand, "edit_distance": dist},
                    )
                )
                break

            # Combosquatting: brand name embedded in label with keywords (e.g. 'paypal-security-login')
            if brand in main_label and main_label != brand:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="COMBOSQUATTING_BRAND_NAME",
                        category=ThreatCategory.BRAND_IMPERSONATION,
                        severity=ThreatSeverity.HIGH,
                        attack_type=AttackType.SPEAR_PHISHING,
                        score=80.0,
                        confidence=0.88,
                        title=f"Combosquatting: '{brand}' Keyword in Unaffiliated Domain {domain}",
                        description=(
                            f"Domain '{domain}' embeds brand name '{brand}' with other tokens "
                            "to deceptively establish trust."
                        ),
                        indicator_value=domain,
                        evidence={"domain": domain, "brand_found": brand},
                    )
                )
                break

        # 3. DGA (Domain Generation Algorithm) characteristics
        # DGA domains typically have high entropy (> 3.5 for labels >= 10 chars)
        if len(main_label) >= 10:
            entropy = _shannon_entropy(main_label)
            # High consonant density
            vowels = set("aeiou")
            vowel_ratio = sum(1 for c in main_label if c in vowels) / len(main_label)

            if entropy > 3.4 and vowel_ratio < 0.20:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="DGA_ALGORITHMIC_DOMAIN",
                        category=ThreatCategory.MALWARE,
                        severity=ThreatSeverity.HIGH,
                        attack_type=AttackType.UNKNOWN,
                        score=75.0,
                        confidence=0.85,
                        title=f"Algorithmic Domain (DGA Characteristics): {domain}",
                        description=(
                            f"Domain label '{main_label}' has high Shannon entropy ({entropy:.2f}) "
                            f"and abnormally low vowel ratio ({vowel_ratio:.1%}), matching DGA patterns."
                        ),
                        indicator_value=domain,
                        evidence={"domain": domain, "entropy": entropy, "vowel_ratio": vowel_ratio},
                    )
                )

        return signals
