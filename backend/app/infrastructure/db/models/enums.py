"""Database enumerations for security analysis and platform operations."""

from __future__ import annotations

from enum import StrEnum


class UserRoleType(StrEnum):
    """User access control role.

    Hierarchy (lowest → highest privilege):
        VIEWER < USER < SECURITY_ANALYST < ADMIN
    """

    VIEWER = "viewer"
    USER = "user"
    SECURITY_ANALYST = "security_analyst"
    ADMIN = "admin"


class EmailStatus(StrEnum):
    """Lifecycle status of submitted emails."""

    QUEUED = "queued"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"


class EmailPriority(StrEnum):
    """Processing priority for email analysis queue."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class AnalysisStatus(StrEnum):
    """Status of the automated analysis pipeline."""

    QUEUED = "queued"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"


class RiskLevel(StrEnum):
    """Calculated risk tier for an email message."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisVerdict(StrEnum):
    """Final automated security decision."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class ThreatSeverity(StrEnum):
    """Severity classification for threat signals."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(StrEnum):
    """Primary category of threat signal."""

    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    CREDENTIAL_THEFT = "credential_theft"
    BRAND_IMPERSONATION = "brand_impersonation"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    RANSOMWARE = "ransomware"
    SOCIAL_ENGINEERING = "social_engineering"
    UNKNOWN = "unknown"


class AttackType(StrEnum):
    """Specific attack methodology detected."""

    SPEAR_PHISHING = "spear_phishing"
    CLONE_PHISHING = "clone_phishing"
    WHALING = "whaling"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALICIOUS_DOCUMENT = "malicious_document"
    CALLBACK_PHISHING = "callback_phishing"
    RANSOMWARE_DELIVERY = "ransomware_delivery"
    EXTORTION = "extortion"
    SPOOFING = "spoofing"
    UNKNOWN = "unknown"


class ReputationVerdict(StrEnum):
    """Reputation outcome from external or internal intelligence engines."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class AuthResultStatus(StrEnum):
    """Email authentication protocol evaluation result."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class AuditAction(StrEnum):
    """Type of action performed for audit records."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_LOGIN = "failed_login"
    TOKEN_REFRESH = "token_refresh"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    TRIGGER = "trigger"
    EXPORT = "export"
    ANNOTATE = "annotate"


class MetricType(StrEnum):
    """System metric type."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
