"""Unit tests for SQLAlchemy models, UUID keys, soft deletion, and enums."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.infrastructure.db.models import (
    Analysis,
    AnalysisEvent,
    AnalysisStatus,
    AnalysisVerdict,
    Attachment,
    AttackType,
    AuditAction,
    AuditLog,
    AuthResultStatus,
    Email,
    EmailHeader,
    EmailPriority,
    EmailStatus,
    EmailURL,
    LLMAnalysis,
    MetricType,
    MLPrediction,
    Organization,
    ReputationVerdict,
    RiskLevel,
    RiskScore,
    Role,
    SystemMetric,
    ThreatCategory,
    ThreatIntelligenceResult,
    ThreatSeverity,
    ThreatSignal,
    User,
    UserRoleType,
)


def test_organization_model_instantiation() -> None:
    """Organization model should initialize with UUID and defaults."""
    org = Organization(
        name="Acme Corp",
        slug="acme-corp",
        primary_domain="acme.com",
        is_active=True,
        settings={},
    )
    assert org.id is not None
    assert isinstance(org.id, uuid.UUID)
    assert org.is_active is True
    assert org.is_deleted is False
    assert org.deleted_at is None
    assert org.settings == {}


def test_soft_delete_mixin_behavior() -> None:
    """SoftDeleteMixin tracks deleted_at and exposes is_deleted property."""
    org = Organization(name="Target Org", slug="target-org")
    assert org.is_deleted is False

    now = datetime.now(UTC)
    org.deleted_at = now
    assert org.is_deleted is True
    assert org.deleted_at == now


def test_role_and_user_models() -> None:
    """Role and User models with UUID, role_type, and security state."""
    role = Role(
        name="Security Analyst",
        role_type=UserRoleType.SECURITY_ANALYST,
        permissions=["emails:read", "analyses:read", "threats:annotate"],
    )
    assert isinstance(role.id, uuid.UUID)
    assert role.role_type == UserRoleType.SECURITY_ANALYST
    assert "emails:read" in role.permissions

    user = User(
        org_id=uuid.uuid4(),
        role_id=role.id,
        email="analyst@acme.com",
        full_name="Jane Doe",
        hashed_password="$argon2id$v=19$m=65536,t=3,p=4$fakehash",
        is_active=True,
        failed_login_attempts=0,
    )
    assert isinstance(user.id, uuid.UUID)
    assert user.is_active is True
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


def test_email_with_forensic_components() -> None:
    """Email, EmailHeader, EmailURL, Attachment model instantiations."""
    email_id = uuid.uuid4()
    org_id = uuid.uuid4()
    now = datetime.now(UTC)

    email = Email(
        id=email_id,
        org_id=org_id,
        message_id="<xyz123@suspicious.com>",
        from_address="billing@suspicious.com",
        from_domain="suspicious.com",
        to_addresses=["ceo@acme.com"],
        received_at=now,
        priority=EmailPriority.HIGH,
        status=EmailStatus.ANALYZING,
        has_attachments=False,
    )
    assert email.priority == EmailPriority.HIGH
    assert email.status == EmailStatus.ANALYZING
    assert email.has_attachments is False

    header = EmailHeader(
        email_id=email_id,
        spf_verdict=AuthResultStatus.FAIL,
        dkim_verdict=AuthResultStatus.NONE,
        dmarc_verdict=AuthResultStatus.FAIL,
        x_originating_ip="198.51.100.42",
        raw_headers={"Received": ["from bad.server"]},
    )
    assert header.spf_verdict == AuthResultStatus.FAIL
    assert header.x_originating_ip == "198.51.100.42"

    url = EmailURL(
        email_id=email_id,
        raw_url="https://paypa1-security-check.com/login",
        domain="paypa1-security-check.com",
        reputation=ReputationVerdict.MALICIOUS,
        is_shortened=False,
        homoglyph_score=0.94,
        homoglyph_target="paypal.com",
    )
    assert url.reputation == ReputationVerdict.MALICIOUS
    assert url.homoglyph_score == 0.94

    attachment = Attachment(
        email_id=email_id,
        filename="invoice_urgent.xlsm",
        extension="xlsm",
        mime_type="application/vnd.ms-excel.sheet.macroEnabled.12",
        file_size_bytes=1048576,
        md5_hash="d41d8cd98f00b204e9800998ecf8427e",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        has_macros=True,
        reputation=ReputationVerdict.SUSPICIOUS,
    )
    assert attachment.has_macros is True
    assert attachment.reputation == ReputationVerdict.SUSPICIOUS


def test_analysis_pipeline_models() -> None:
    """Analysis, ThreatSignal, MLPrediction, LLMAnalysis, RiskScore, TI, and Event models."""
    analysis_id = uuid.uuid4()
    org_id = uuid.uuid4()

    analysis = Analysis(
        id=analysis_id,
        email_id=uuid.uuid4(),
        org_id=org_id,
        status=AnalysisStatus.COMPLETE,
        verdict=AnalysisVerdict.MALICIOUS,
        overall_risk_score=92,
        risk_level=RiskLevel.CRITICAL,
    )
    assert analysis.verdict == AnalysisVerdict.MALICIOUS
    assert analysis.overall_risk_score == 92
    assert analysis.risk_level == RiskLevel.CRITICAL

    signal = ThreatSignal(
        analysis_id=analysis_id,
        org_id=org_id,
        signal_type="homoglyph_domain_detection",
        category=ThreatCategory.BRAND_IMPERSONATION,
        severity=ThreatSeverity.CRITICAL,
        attack_type=AttackType.SPEAR_PHISHING,
        confidence=0.98,
        source_engine="url_analyzer",
        title="PayPal Brand Impersonation Detected",
    )
    assert signal.severity == ThreatSeverity.CRITICAL
    assert signal.attack_type == AttackType.SPEAR_PHISHING

    ml = MLPrediction(
        analysis_id=analysis_id,
        model_name="etd_ensemble_classifier",
        model_version="2.4.0",
        prediction_label="phishing",
        confidence_score=0.96,
        phishing_probability=0.98,
    )
    assert ml.prediction_label == "phishing"

    llm = LLMAnalysis(
        analysis_id=analysis_id,
        model_name="llama-3.3-70b-versatile",
        prompt_version="v1.2",
        threat_narrative="Targeted credential harvesting attack using fake PayPal authentication gateway.",
        recommended_action="quarantine",
        confidence_score=0.95,
    )
    assert llm.recommended_action == "quarantine"

    risk = RiskScore(
        analysis_id=analysis_id,
        org_id=org_id,
        composite_score=92,
        risk_level=RiskLevel.CRITICAL,
        spf_subscore=100.0,
        url_subscore=95.0,
        ml_subscore=96.0,
    )
    assert risk.composite_score == 92
    assert risk.risk_level == RiskLevel.CRITICAL

    ti = ThreatIntelligenceResult(
        analysis_id=analysis_id,
        indicator_type="domain",
        indicator_value="paypa1-security-check.com",
        provider="virustotal",
        reputation_verdict=ReputationVerdict.MALICIOUS,
        threat_score=88,
        last_checked_at=datetime.now(UTC),
    )
    assert ti.provider == "virustotal"
    assert ti.reputation_verdict == ReputationVerdict.MALICIOUS

    event = AnalysisEvent(
        analysis_id=analysis_id,
        event_type="stage_completed",
        stage="scoring",
        status="completed",
        duration_ms=45,
    )
    assert event.stage == "scoring"
    assert event.duration_ms == 45


def test_audit_log_and_system_metric_models() -> None:
    """AuditLog and SystemMetric model instantiations."""
    audit = AuditLog(
        org_id=uuid.uuid4(),
        actor_email="admin@acme.com",
        event_type="EMAIL_QUARANTINED",
        resource_type="email",
        resource_id=str(uuid.uuid4()),
        action=AuditAction.UPDATE,
        correlation_id=uuid.uuid4(),
    )
    assert audit.action == AuditAction.UPDATE
    assert audit.event_type == "EMAIL_QUARANTINED"

    metric = SystemMetric(
        metric_name="email_analysis_duration_ms",
        metric_type=MetricType.HISTOGRAM,
        value=320.5,
        unit="ms",
        recorded_at=datetime.now(UTC),
    )
    assert metric.metric_name == "email_analysis_duration_ms"
    assert metric.value == 320.5
