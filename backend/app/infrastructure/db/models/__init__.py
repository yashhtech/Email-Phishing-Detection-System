"""SQLAlchemy models registry for Alembic discovery and metadata management."""

from app.infrastructure.db.models.analysis import (
    Analysis,
    AnalysisEvent,
    LLMAnalysis,
    MLPrediction,
    RiskScore,
    ThreatIntelligenceResult,
    ThreatSignal,
)
from app.infrastructure.db.models.audit import AuditLog
from app.infrastructure.db.models.base_model import BaseModel, SoftDeleteMixin
from app.infrastructure.db.models.email import (
    Attachment,
    Email,
    EmailHeader,
    EmailURL,
)
from app.infrastructure.db.models.enums import (
    AnalysisStatus,
    AnalysisVerdict,
    AttackType,
    AuditAction,
    AuthResultStatus,
    EmailPriority,
    EmailStatus,
    MetricType,
    ReputationVerdict,
    RiskLevel,
    ThreatCategory,
    ThreatSeverity,
    UserRoleType,
)
from app.infrastructure.db.models.metrics import SystemMetric
from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.models.role import Role
from app.infrastructure.db.models.user import User

__all__ = [
    "Analysis",
    "AnalysisEvent",
    # Enums
    "AnalysisStatus",
    "AnalysisVerdict",
    "Attachment",
    "AttackType",
    "AuditAction",
    "AuditLog",
    "AuthResultStatus",
    # Base
    "BaseModel",
    "Email",
    "EmailHeader",
    "EmailPriority",
    "EmailStatus",
    "EmailURL",
    "LLMAnalysis",
    "MLPrediction",
    "MetricType",
    # Core Models (16 total)
    "Organization",
    "ReputationVerdict",
    "RiskLevel",
    "RiskScore",
    "Role",
    "SoftDeleteMixin",
    "SystemMetric",
    "ThreatCategory",
    "ThreatIntelligenceResult",
    "ThreatSeverity",
    "ThreatSignal",
    "User",
    "UserRoleType",
]
