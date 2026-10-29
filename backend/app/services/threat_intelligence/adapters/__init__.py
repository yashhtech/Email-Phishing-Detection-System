"""Provider adapters for Threat Intelligence.

Exports:
- VirusTotalAdapter: Real-time queries for domains, URLs, IPs, and hashes.
- AbuseIPDBAdapter: IP address reputation and abuse confidence checks.
- InternalThreatIntelAdapter: High-speed local blocklists, allowlists, and heuristic IOCs.
- MockThreatIntelAdapter: Controllable adapter for testing and simulation.
"""

from app.services.threat_intelligence.adapters.abuseipdb import AbuseIPDBAdapter
from app.services.threat_intelligence.adapters.internal import InternalThreatIntelAdapter
from app.services.threat_intelligence.adapters.mock import MockThreatIntelAdapter
from app.services.threat_intelligence.adapters.virustotal import VirusTotalAdapter

__all__ = [
    "AbuseIPDBAdapter",
    "InternalThreatIntelAdapter",
    "MockThreatIntelAdapter",
    "VirusTotalAdapter",
]
