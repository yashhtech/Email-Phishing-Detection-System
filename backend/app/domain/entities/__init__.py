"""Domain entities."""

from app.domain.entities.analysis import AnalysisResult, AnalysisStatus, RiskLevel
from app.domain.entities.audit import AuditAction, AuditEvent
from app.domain.entities.email import Email, EmailPriority, EmailStatus
from app.domain.entities.email_analysis_input import (
    EmailAnalysisInput,
    ExtractedAttachmentMetadata,
    ExtractedURLItem,
    NormalizedContent,
    NormalizedHeaders,
    NormalizedRecipient,
    NormalizedSender,
    RawEvidence,
    StructuralAnomaly,
    StructuralIntegrity,
)
from app.domain.entities.risk import RiskFactor, RiskScore
from app.domain.entities.threat import IOCType, ThreatCategory, ThreatIndicator
from app.domain.entities.user import User, UserRole

__all__ = [
    "AnalysisResult",
    "AnalysisStatus",
    "AuditAction",
    "AuditEvent",
    "Email",
    "EmailAnalysisInput",
    "EmailPriority",
    "EmailStatus",
    "ExtractedAttachmentMetadata",
    "ExtractedURLItem",
    "IOCType",
    "NormalizedContent",
    "NormalizedHeaders",
    "NormalizedRecipient",
    "NormalizedSender",
    "RawEvidence",
    "RiskFactor",
    "RiskLevel",
    "RiskScore",
    "StructuralAnomaly",
    "StructuralIntegrity",
    "ThreatCategory",
    "ThreatIndicator",
    "User",
    "UserRole",
]
