"""Threat Intelligence service package.

Public Exports:
- ThreatIntelligenceService: High-level coordinator for multi-provider intelligence operations.
- ThreatIntelligenceProvider: Abstract base class for all threat intel adapters.
- ThreatIntelReport: Normalized indicator finding contract.
- IndicatorType: Taxonomy of supported indicators (domain, url, ip, hash).
- ThreatIntelCache: Resilient thread-safe TTL cache.
- Adapters: VirusTotalAdapter, AbuseIPDBAdapter, InternalThreatIntelAdapter, MockThreatIntelAdapter.
"""

from app.services.threat_intelligence.adapters.abuseipdb import AbuseIPDBAdapter
from app.services.threat_intelligence.adapters.internal import InternalThreatIntelAdapter
from app.services.threat_intelligence.adapters.mock import MockThreatIntelAdapter
from app.services.threat_intelligence.adapters.virustotal import VirusTotalAdapter
from app.services.threat_intelligence.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.cache import ThreatIntelCache
from app.services.threat_intelligence.manager import ThreatIntelligenceService
from app.services.threat_intelligence.schemas import IndicatorType, ThreatIntelReport

__all__ = [
    "AbuseIPDBAdapter",
    "IndicatorType",
    "InternalThreatIntelAdapter",
    "MockThreatIntelAdapter",
    "ThreatIntelCache",
    "ThreatIntelReport",
    "ThreatIntelligenceProvider",
    "ThreatIntelligenceService",
    "VirusTotalAdapter",
]
