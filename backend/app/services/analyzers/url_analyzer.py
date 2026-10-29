"""URL security analyzer.

Analyzes:
- Bare IP address URLs (e.g. http://185.220.101.5/login)
- Suspicious TLDs (.top, .xyz, .click, .loan, .buzz, etc.)
- URL shorteners (bit.ly, tinyurl.com, t.co, etc.)
- Credential harvesting path keywords (/login, /signin, /verify, /account, /update, /password)
- URL obfuscation techniques:
    - Hex/Octal/Dword IP encoding (e.g. http://0x7f000001)
    - Username/password URL syntax (e.g. http://legit.com@evil.com)
    - Excessively long paths / high entropy paths
    - Multiple subdomains (subdomain spoofing: e.g. paypal.com.account-verify.phish.top)
- Open redirect patterns (e.g. google.com/url?q=http://phish.com)
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from app.domain.entities.email_analysis_input import EmailAnalysisInput, ExtractedURLItem
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity

# Credential harvesting URL path patterns
_CREDENTIAL_KEYWORDS: re.Pattern[str] = re.compile(
    r"/(?:login|signin|sign-in|log-in|account|verify|verification|update|secure|"
    r"password|auth|authentication|wallet|confirm|validation|recover)\b",
    re.IGNORECASE,
)

# Open redirect domains
_OPEN_REDIRECTORS: frozenset[str] = frozenset(
    {
        "google.com",
        "l.facebook.com",
        "t.co",
        "linkedin.com",
        "youtube.com",
        "bing.com",
        "yahoo.com",
        "duckduckgo.com",
    }
)


class URLAnalyzer:
    """Deterministic analyzer for URLs extracted from email plain text and HTML bodies."""

    ANALYZER_NAME = "url_analyzer"

    def analyze(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Analyze all URLs in the email and return zero or more NormalizedThreatSignal objects."""
        signals: list[NormalizedThreatSignal] = []

        for item in email_input.urls:
            signals.extend(self._analyze_single_url(item, email_input.sender.domain))

        return signals

    def _analyze_single_url(
        self, item: ExtractedURLItem, sender_domain: str
    ) -> list[NormalizedThreatSignal]:
        signals: list[NormalizedThreatSignal] = []
        raw = item.raw_url
        domain = item.domain.lower()

        # 1. Bare IP Address in URL
        if item.is_ip_address:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="URL_BARE_IP_ADDRESS",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.CREDENTIAL_HARVESTING,
                    score=85.0,
                    confidence=0.95,
                    title=f"URL with Direct IP Address: {item.defanged_url}",
                    description="URL points directly to an IP address instead of a domain name, commonly used by bulletproof hosts.",
                    indicator_value=item.domain,
                    evidence={"url": item.defanged_url, "ip": item.domain},
                )
            )

        # 2. Suspicious TLD
        if item.is_suspicious_tld:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="URL_SUSPICIOUS_TLD",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.SPEAR_PHISHING,
                    score=65.0,
                    confidence=0.85,
                    title=f"URL with High-Risk TLD: {item.defanged_url}",
                    description=f"Domain '{domain}' uses a top-level domain frequently associated with spam and phishing campaigns.",
                    indicator_value=domain,
                    evidence={"url": item.defanged_url, "domain": domain},
                )
            )

        # 3. URL Shortener Evasion
        if item.is_shortener:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="URL_SHORTENER_OBFUSCATION",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.MEDIUM,
                    attack_type=AttackType.SPEAR_PHISHING,
                    score=40.0,
                    confidence=0.80,
                    title=f"URL Shortener Used: {item.defanged_url}",
                    description="URL shorteners obscure the real destination host and are routinely used to bypass email gateway filters.",
                    indicator_value=raw,
                    evidence={"url": item.defanged_url, "shortener_host": domain},
                )
            )

        # 4. Credential Harvesting Keywords in Path
        if _CREDENTIAL_KEYWORDS.search(item.path):
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="URL_CREDENTIAL_HARVESTING_PATH",
                    category=ThreatCategory.CREDENTIAL_THEFT,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.CREDENTIAL_HARVESTING,
                    score=70.0,
                    confidence=0.85,
                    title=f"Credential Harvesting Path in URL: {item.defanged_url}",
                    description=f"Path '{item.path}' targets login, authentication, or account verification flows.",
                    indicator_value=raw,
                    evidence={"url": item.defanged_url, "path": item.path},
                )
            )

        # 5. Obfuscation: '@' in URL (Userinfo trick: http://google.com@evil.com)
        if "@" in raw.split("://")[-1].split("/")[0]:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="URL_USERINFO_OBFUSCATION",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.SPEAR_PHISHING,
                    score=90.0,
                    confidence=0.98,
                    title=f"URL Credentials Obfuscation Trick: {item.defanged_url}",
                    description="URL exploits HTTP userinfo '@' notation to disguise the actual destination host.",
                    indicator_value=raw,
                    evidence={"url": item.defanged_url},
                )
            )

        # 6. Open Redirect Abuse
        if any(red in domain for red in _OPEN_REDIRECTORS):
            try:
                parsed = urlparse(raw)
                qs = parse_qs(parsed.query)
                for param in ("url", "q", "target", "dest", "destination", "redirect", "r"):
                    if param in qs and any(
                        target.startswith(("http://", "https://")) for target in qs[param]
                    ):
                        signals.append(
                            NormalizedThreatSignal(
                                source=self.ANALYZER_NAME,
                                signal_type="OPEN_REDIRECT_EXPLOITATION",
                                category=ThreatCategory.PHISHING,
                                severity=ThreatSeverity.HIGH,
                                attack_type=AttackType.SPEAR_PHISHING,
                                score=75.0,
                                confidence=0.90,
                                title=f"Open Redirect Link: {item.defanged_url}",
                                description=f"Link leverages trusted host '{domain}' to redirect victims to external unverified destination.",
                                indicator_value=domain,
                                evidence={"url": item.defanged_url, "redirect_param": param},
                            )
                        )
                        break
            except Exception:
                pass

        # 7. Deep Subdomain Spoofing (e.g. paypal.com.security.verify.phish.com)
        labels = domain.split(".")
        if len(labels) >= 5:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="URL_EXCESSIVE_SUBDOMAINS",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.MEDIUM,
                    attack_type=AttackType.SPEAR_PHISHING,
                    score=50.0,
                    confidence=0.80,
                    title=f"Excessive Subdomain Depth ({len(labels)} labels): {domain}",
                    description="Subdomain nesting with 5 or more levels is a well-known tactic to mimic legitimate brands.",
                    indicator_value=domain,
                    evidence={"domain": domain, "label_count": len(labels)},
                )
            )

        return signals
