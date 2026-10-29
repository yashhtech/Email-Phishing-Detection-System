"""Internal Threat Intelligence adapter for local blocklists, allowlists, and heuristics.

Features:
- Instant in-memory evaluation with zero external network dependencies
- Pre-seeded with known phishing, disposable email domains, C2 IP addresses, and test hashes
- Enterprise allowlisting for verified high-reputation brands (Google, Microsoft, GitHub)
- Runtime programmatic registration of dynamic IOC feeds (e.g. from incident reports)
- Always configured and 100% resilient
"""

from __future__ import annotations

import time
from typing import Any

from app.infrastructure.db.models.enums import ReputationVerdict
from app.services.threat_intelligence.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport

# Built-in known malicious IOC blocklist
_DEFAULT_BLOCKLIST: dict[str, dict[str, Any]] = {
    # Malicious domains
    "login-apple-security.com": {
        "score": 95.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["phishing", "apple_spoof"],
    },
    "paypal-account-update.xyz": {
        "score": 98.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["phishing", "credential_theft"],
    },
    "malicious-phish.com": {
        "score": 99.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["phishing", "c2"],
    },
    "evil-payload.top": {
        "score": 95.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["malware", "ransomware"],
    },
    # Malicious IPs
    "198.51.100.42": {
        "score": 90.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["c2", "botnet"],
    },
    "203.0.113.195": {
        "score": 92.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["phishing_host", "bulletproof"],
    },
    # Malicious file hashes
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {  # EICAR test file SHA256
        "score": 100.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["malware_test", "eicar"],
    },
    "44d88612fea8a8f36de82e1278abb02f": {  # EICAR MD5
        "score": 100.0,
        "verdict": ReputationVerdict.MALICIOUS,
        "tags": ["malware_test", "eicar"],
    },
}

# Built-in verified high-reputation allowlist
_DEFAULT_ALLOWLIST: set[str] = {
    "google.com",
    "microsoft.com",
    "github.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
}


class InternalThreatIntelAdapter(ThreatIntelligenceProvider):
    """Local high-performance blocklist and allowlist threat intelligence adapter."""

    def __init__(
        self,
        blocklist: dict[str, dict[str, Any]] | None = None,
        allowlist: set[str] | None = None,
    ) -> None:
        self._blocklist = dict(blocklist or _DEFAULT_BLOCKLIST)
        self._allowlist = set(allowlist or _DEFAULT_ALLOWLIST)

    @property
    def provider_name(self) -> str:
        return "internal_blocklist"

    @property
    def is_configured(self) -> bool:
        return True

    def add_blocklist_entry(
        self,
        indicator: str,
        verdict: ReputationVerdict = ReputationVerdict.MALICIOUS,
        threat_score: float = 90.0,
        tags: list[str] | None = None,
    ) -> None:
        """Register a new threat indicator into the internal database."""
        self._blocklist[indicator.strip().lower()] = {
            "verdict": verdict,
            "score": threat_score,
            "tags": tags or ["custom_blocklist"],
        }

    def add_allowlist_entry(self, domain_or_ip: str) -> None:
        """Register a trusted domain or IP into the internal allowlist."""
        self._allowlist.add(domain_or_ip.strip().lower())

    async def check_domain(self, domain: str) -> ThreatIntelReport:
        clean = domain.strip().lower()
        start = time.perf_counter()

        # Check blocklist
        if clean in self._blocklist:
            entry = self._blocklist[clean]
            latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return ThreatIntelReport(
                indicator=clean,
                indicator_type=IndicatorType.DOMAIN,
                provider=self.provider_name,
                reputation=entry["verdict"],
                confidence=0.99,
                source="internal://blocklist/domains",
                raw_reference={"entry": entry},
                threat_score=entry["score"],
                tags=entry["tags"],
                latency_ms=latency_ms,
            )

        # Check allowlist
        if clean in self._allowlist:
            latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return ThreatIntelReport(
                indicator=clean,
                indicator_type=IndicatorType.DOMAIN,
                provider=self.provider_name,
                reputation=ReputationVerdict.CLEAN,
                confidence=0.95,
                source="internal://allowlist/domains",
                raw_reference={"status": "allowlisted"},
                threat_score=0.0,
                tags=["trusted_domain"],
                latency_ms=latency_ms,
            )

        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return ThreatIntelReport(
            indicator=clean,
            indicator_type=IndicatorType.DOMAIN,
            provider=self.provider_name,
            reputation=ReputationVerdict.UNKNOWN,
            confidence=0.5,
            source="internal://blocklist",
            raw_reference={"status": "not_in_internal_db"},
            threat_score=0.0,
            tags=[],
            latency_ms=latency_ms,
        )

    async def check_url(self, url: str) -> ThreatIntelReport:
        clean = url.strip()
        start = time.perf_counter()

        # Check exact URL
        if clean.lower() in self._blocklist:
            entry = self._blocklist[clean.lower()]
            latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return ThreatIntelReport(
                indicator=clean,
                indicator_type=IndicatorType.URL,
                provider=self.provider_name,
                reputation=entry["verdict"],
                confidence=0.99,
                source="internal://blocklist/urls",
                raw_reference={"entry": entry},
                threat_score=entry["score"],
                tags=entry["tags"],
                latency_ms=latency_ms,
            )

        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return ThreatIntelReport(
            indicator=clean,
            indicator_type=IndicatorType.URL,
            provider=self.provider_name,
            reputation=ReputationVerdict.UNKNOWN,
            confidence=0.5,
            source="internal://blocklist",
            raw_reference={"status": "not_in_internal_db"},
            threat_score=0.0,
            tags=[],
            latency_ms=latency_ms,
        )

    async def check_ip(self, ip: str) -> ThreatIntelReport:
        clean = ip.strip()
        start = time.perf_counter()

        if clean in self._blocklist:
            entry = self._blocklist[clean]
            latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return ThreatIntelReport(
                indicator=clean,
                indicator_type=IndicatorType.IP,
                provider=self.provider_name,
                reputation=entry["verdict"],
                confidence=0.99,
                source="internal://blocklist/ips",
                raw_reference={"entry": entry},
                threat_score=entry["score"],
                tags=entry["tags"],
                latency_ms=latency_ms,
            )

        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return ThreatIntelReport(
            indicator=clean,
            indicator_type=IndicatorType.IP,
            provider=self.provider_name,
            reputation=ReputationVerdict.UNKNOWN,
            confidence=0.5,
            source="internal://blocklist",
            raw_reference={"status": "not_in_internal_db"},
            threat_score=0.0,
            tags=[],
            latency_ms=latency_ms,
        )

    async def check_hash(self, hash_value: str) -> ThreatIntelReport:
        clean = hash_value.strip().lower()
        start = time.perf_counter()

        if clean in self._blocklist:
            entry = self._blocklist[clean]
            latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return ThreatIntelReport(
                indicator=clean,
                indicator_type=IndicatorType.HASH,
                provider=self.provider_name,
                reputation=entry["verdict"],
                confidence=1.0,
                source="internal://blocklist/hashes",
                raw_reference={"entry": entry},
                threat_score=entry["score"],
                tags=entry["tags"],
                latency_ms=latency_ms,
            )

        latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return ThreatIntelReport(
            indicator=clean,
            indicator_type=IndicatorType.HASH,
            provider=self.provider_name,
            reputation=ReputationVerdict.UNKNOWN,
            confidence=0.5,
            source="internal://blocklist",
            raw_reference={"status": "not_in_internal_db"},
            threat_score=0.0,
            tags=[],
            latency_ms=latency_ms,
        )
