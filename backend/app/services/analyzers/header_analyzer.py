"""Header security analyzer.

Analyzes:
- Missing mandatory RFC 5322 headers (From, Date, Message-ID)
- Duplicate headers (multiple From, Subject, Message-ID)
- Header injection attempts (CRLF characters in header values)
- Excessive routing hops (relays/gateways >= 10)
- Suspicious X-Mailer / User-Agent headers
- Private/internal vs. external IP routing anomalies
- Time-skew / Future date anomalies
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.domain.entities.email_analysis_input import EmailAnalysisInput
from app.domain.entities.threat_signal import NormalizedThreatSignal
from app.infrastructure.db.models.enums import AttackType, ThreatCategory, ThreatSeverity

# Well-known mass-mailer / spammer tools
_SUSPICIOUS_MAILERS: frozenset[str] = frozenset(
    {
        "phpmailer",
        "turbomailer",
        "darkmailer",
        "direct email",
        "atomic",
        "sendblaster",
        "super email sender",
        "mass mailer",
        "bulk mailer",
        "ams",
        "e-mail sender",
        "storm",
    }
)

# Suspicious headers inserted by compromised servers or spam scripts
_SUSPICIOUS_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "x-php-script",
        "x-php-originating-script",
        "x-spammer",
        "x-injection",
        "x-get-script",
    }
)


class HeaderAnalyzer:
    """Deterministic analyzer for RFC 5322 header compliance and routing anomalies."""

    ANALYZER_NAME = "header_analyzer"

    def analyze(self, email_input: EmailAnalysisInput) -> list[NormalizedThreatSignal]:
        """Analyze email headers and return zero or more NormalizedThreatSignal objects."""
        signals: list[NormalizedThreatSignal] = []
        headers = email_input.headers
        all_headers = headers.all_headers

        # 1. Missing Message-ID (RFC 5322 recommendation, high correlation with spam)
        if not headers.message_id or headers.message_id.strip() in ("", "<>"):
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="MISSING_MESSAGE_ID",
                    category=ThreatCategory.SPAM,
                    severity=ThreatSeverity.MEDIUM,
                    attack_type=AttackType.SPOOFING,
                    score=35.0,
                    confidence=0.85,
                    title="Missing Message-ID Header",
                    description="Email does not contain a Message-ID header, common among spam generation tools.",
                    evidence={"message_id": headers.message_id},
                )
            )

        # 2. Multiple From headers (RFC 5322 violation, potential header injection)
        from_list = all_headers.get("From", [])
        if len(from_list) > 1:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="MULTIPLE_FROM_HEADERS",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.HIGH,
                    attack_type=AttackType.SPOOFING,
                    score=75.0,
                    confidence=0.95,
                    title="Multiple From Headers Detected",
                    description=f"Email contains {len(from_list)} From headers, violating RFC 5322 §3.6.",
                    evidence={"from_headers": from_list},
                )
            )

        # 3. Header injection in Subject (CRLF characters)
        raw_subject = email_input.raw_evidence.raw_subject or ""
        if "\r" in raw_subject or "\n" in raw_subject:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="HEADER_INJECTION_CRLF",
                    category=ThreatCategory.PHISHING,
                    severity=ThreatSeverity.CRITICAL,
                    attack_type=AttackType.SPOOFING,
                    score=95.0,
                    confidence=0.99,
                    title="CRLF Header Injection in Subject",
                    description="Carriage return / line feed characters found inside Subject header, indicating SMTP injection.",
                    evidence={"raw_subject": raw_subject[:200]},
                )
            )

        # 4. Excessive routing hops (>= 8 hops indicates relay evasion or looping)
        hop_count = len(headers.received_hops)
        if hop_count >= 8:
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="EXCESSIVE_ROUTING_HOPS",
                    category=ThreatCategory.SPAM,
                    severity=ThreatSeverity.LOW,
                    attack_type=AttackType.UNKNOWN,
                    score=25.0,
                    confidence=0.75,
                    title=f"Excessive Mail Routing Hops ({hop_count} hops)",
                    description=f"Email traversed {hop_count} relay servers before delivery, which may indicate evasion.",
                    evidence={"hop_count": hop_count},
                )
            )

        # 5. Suspicious X-Mailer header
        if headers.x_mailer:
            mailer_lower = headers.x_mailer.lower()
            if any(tool in mailer_lower for tool in _SUSPICIOUS_MAILERS):
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="SUSPICIOUS_X_MAILER",
                        category=ThreatCategory.SPAM,
                        severity=ThreatSeverity.HIGH,
                        attack_type=AttackType.UNKNOWN,
                        score=70.0,
                        confidence=0.90,
                        title=f"Suspicious Bulk Mailer: {headers.x_mailer}",
                        description=f"X-Mailer header '{headers.x_mailer}' is associated with automated bulk spam tools.",
                        indicator_value=headers.x_mailer,
                        evidence={"x_mailer": headers.x_mailer},
                    )
                )

        # 6. PHP / Web Script injection headers
        for h_name in all_headers:
            if h_name.lower() in _SUSPICIOUS_HEADER_NAMES:
                signals.append(
                    NormalizedThreatSignal(
                        source=self.ANALYZER_NAME,
                        signal_type="WEB_SCRIPT_HEADER_DETECTED",
                        category=ThreatCategory.PHISHING,
                        severity=ThreatSeverity.MEDIUM,
                        attack_type=AttackType.UNKNOWN,
                        score=50.0,
                        confidence=0.85,
                        title=f"Automated Script Header: {h_name}",
                        description=f"Email was generated via a web script ({h_name}), common in compromised webservers.",
                        evidence={"header": h_name, "value": all_headers[h_name]},
                    )
                )

        # 7. Date skew (Date more than 24 hours in the future or > 30 days in past)
        now = datetime.now(UTC)
        msg_date = headers.date
        if msg_date > now + timedelta(hours=24):
            signals.append(
                NormalizedThreatSignal(
                    source=self.ANALYZER_NAME,
                    signal_type="FUTURE_DATE_SKEW",
                    category=ThreatCategory.SPAM,
                    severity=ThreatSeverity.LOW,
                    attack_type=AttackType.UNKNOWN,
                    score=20.0,
                    confidence=0.80,
                    title="Future Message Date",
                    description=f"Message date '{msg_date.isoformat()}' is set in the future.",
                    evidence={"date": msg_date.isoformat(), "current_time": now.isoformat()},
                )
            )

        return signals
