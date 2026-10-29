"""Integration and unit tests for repositories and transactional Unit of Work."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Analysis,
    AnalysisEvent,
    AnalysisVerdict,
    Attachment,
    AttackType,
    AuditAction,
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
    ThreatCategory,
    ThreatIntelligenceResult,
    ThreatSeverity,
    ThreatSignal,
    User,
    UserRoleType,
)
from app.infrastructure.db.repositories.unit_of_work import UnitOfWork


@pytest.fixture
async def test_session_factory() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """Create an in-memory SQLite async engine and initialize all 16 tables."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    yield session_factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_unit_of_work_transaction_commit(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """UOW should commit entities on clean context manager exit."""
    org_id = uuid.uuid4()
    async with UnitOfWork(test_session_factory) as uow:
        org = Organization(id=org_id, name="Secure Corp", slug="secure-corp")
        await uow.organizations.create(org)

    # Verify persisted in new session
    async with UnitOfWork(test_session_factory) as uow:
        fetched = await uow.organizations.get_by_id(org_id)
        assert fetched is not None
        assert fetched.name == "Secure Corp"
        assert fetched.slug == "secure-corp"


@pytest.mark.asyncio
async def test_unit_of_work_transaction_rollback(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """UOW should automatically roll back changes when an exception is raised."""
    org_id = uuid.uuid4()
    with pytest.raises(RuntimeError):
        async with UnitOfWork(test_session_factory) as uow:
            org = Organization(id=org_id, name="Rollback Corp", slug="rollback-corp")
            await uow.organizations.create(org)
            raise RuntimeError("Simulated failure inside transaction")

    # Verify NOT persisted
    async with UnitOfWork(test_session_factory) as uow:
        fetched = await uow.organizations.get_by_id(org_id)
        assert fetched is None


@pytest.mark.asyncio
async def test_organization_and_user_repositories(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Test Organization and User repositories with role foreign keys and soft deletes."""
    async with UnitOfWork(test_session_factory) as uow:
        org = Organization(name="FinTech Ltd", slug="fintech-ltd", primary_domain="fintech.com")
        await uow.organizations.create(org)

        role = Role(
            name="Security Admin",
            role_type=UserRoleType.ADMIN,
            permissions=["*"],
        )
        uow.session.add(role)
        await uow.session.flush()

        user = User(
            org_id=org.id,
            role_id=role.id,
            email="secadmin@fintech.com",
            full_name="Alex Security",
            hashed_password="hashed_pwd_value",
        )
        await uow.users.create(user)

    async with UnitOfWork(test_session_factory) as uow:
        # User lookup by email
        fetched_user = await uow.users.get_by_email("secadmin@fintech.com")
        assert fetched_user is not None
        assert fetched_user.full_name == "Alex Security"
        assert fetched_user.organization.name == "FinTech Ltd"
        assert fetched_user.role.name == "Security Admin"

        # Record login
        await uow.users.record_login(fetched_user.id)
        updated_user = await uow.users.get_by_id(fetched_user.id)
        assert updated_user is not None
        assert updated_user.last_login_at is not None

        # Test soft delete organization
        await uow.organizations.delete(org.id, soft=True)
        active_org = await uow.organizations.get_by_id(org.id)
        assert active_org is None  # soft deleted filtered out by default

        deleted_org = await uow.organizations.get_by_id(org.id, include_deleted=True)
        assert deleted_org is not None
        assert deleted_org.is_deleted is True


@pytest.mark.asyncio
async def test_email_repository_with_forensic_relations(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Test EmailRepository persisting and eager-loading headers, URLs, and attachments."""
    org_id = uuid.uuid4()
    email_id = uuid.uuid4()

    async with UnitOfWork(test_session_factory) as uow:
        org = Organization(id=org_id, name="Bank Corp", slug="bank-corp")
        await uow.organizations.create(org)

        email = Email(
            id=email_id,
            org_id=org_id,
            message_id="<phish-01@attacker.com>",
            from_address="security-alert@attacker.com",
            from_domain="attacker.com",
            to_addresses=["employee@bank-corp.com"],
            subject="Urgent Account Verification",
            received_at=datetime.now(UTC),
            priority=EmailPriority.HIGH,
            has_attachments=True,
            attachment_count=1,
        )
        await uow.emails.create(email)

        header = EmailHeader(
            email_id=email_id,
            spf_verdict=AuthResultStatus.FAIL,
            dkim_verdict=AuthResultStatus.NONE,
            dmarc_verdict=AuthResultStatus.FAIL,
            x_originating_ip="203.0.113.195",
        )
        await uow.emails.add_header(header)

        urls = [
            EmailURL(
                email_id=email_id,
                raw_url="https://bank-corp.verify-portal.top/login",
                domain="bank-corp.verify-portal.top",
                reputation=ReputationVerdict.MALICIOUS,
                is_shortened=False,
                homoglyph_score=0.91,
                homoglyph_target="bank-corp.com",
            )
        ]
        await uow.emails.add_urls(urls)

        attachments = [
            Attachment(
                email_id=email_id,
                filename="statement.pdf.exe",
                extension="exe",
                mime_type="application/x-dosexec",
                file_size_bytes=65536,
                md5_hash="098f6bcd4621d373cade4e832627b4f6",
                sha256_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                is_executable=True,
                reputation=ReputationVerdict.MALICIOUS,
            )
        ]
        await uow.emails.add_attachments(attachments)

    async with UnitOfWork(test_session_factory) as uow:
        fetched = await uow.emails.get_with_relations(email_id)
        assert fetched is not None
        assert fetched.subject == "Urgent Account Verification"
        assert fetched.header is not None
        assert fetched.header.spf_verdict == AuthResultStatus.FAIL
        assert len(fetched.urls) == 1
        assert fetched.urls[0].reputation == ReputationVerdict.MALICIOUS
        assert len(fetched.attachments) == 1
        assert fetched.attachments[0].is_executable is True


@pytest.mark.asyncio
async def test_analysis_repository_lifecycle_and_submodels(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Test full analysis record with ML, LLM, RiskScore, ThreatSignals, and Events."""
    org_id = uuid.uuid4()
    email_id = uuid.uuid4()
    analysis_id = uuid.uuid4()

    async with UnitOfWork(test_session_factory) as uow:
        org = Organization(id=org_id, name="Test Org", slug="test-org")
        await uow.organizations.create(org)

        email = Email(
            id=email_id,
            org_id=org_id,
            message_id="<msg-77@test.com>",
            from_address="test@test.com",
            from_domain="test.com",
            received_at=datetime.now(UTC),
        )
        await uow.emails.create(email)

        analysis = Analysis(
            id=analysis_id,
            email_id=email_id,
            org_id=org_id,
            status=EmailStatus.QUEUED,
        )
        await uow.analyses.create(analysis)

        # Add submodels
        risk = RiskScore(
            analysis_id=analysis_id,
            org_id=org_id,
            composite_score=87,
            risk_level=RiskLevel.HIGH,
            spf_subscore=100.0,
            ml_subscore=88.0,
        )
        await uow.analyses.save_risk_score(risk)

        ml = MLPrediction(
            analysis_id=analysis_id,
            model_name="etd_bert_phishing",
            model_version="1.0.0",
            prediction_label="phishing",
            confidence_score=0.92,
            phishing_probability=0.94,
        )
        await uow.analyses.save_ml_prediction(ml)

        llm = LLMAnalysis(
            analysis_id=analysis_id,
            model_name="llama-3.3-70b-versatile",
            prompt_version="v2",
            threat_narrative="Credential harvesting attempt detected with high confidence.",
            recommended_action="quarantine",
            confidence_score=0.91,
        )
        await uow.analyses.save_llm_analysis(llm)

        signal = ThreatSignal(
            analysis_id=analysis_id,
            org_id=org_id,
            signal_type="auth_failure_combo",
            category=ThreatCategory.BRAND_IMPERSONATION,
            severity=ThreatSeverity.HIGH,
            attack_type=AttackType.SPOOFING,
            confidence=0.95,
            source_engine="header_analyzer",
            title="SPF and DMARC Alignment Failure",
        )
        await uow.threat_signals.create(signal)

        event = AnalysisEvent(
            analysis_id=analysis_id,
            event_type="pipeline_started",
            stage="initialization",
            status="completed",
            duration_ms=12,
        )
        await uow.analyses.record_event(event)

        # Mark completed
        await uow.analyses.record_completion(
            analysis_id,
            verdict=AnalysisVerdict.MALICIOUS,
            overall_risk_score=87,
            risk_level=RiskLevel.HIGH,
            duration_ms=450,
        )

    # Verification
    async with UnitOfWork(test_session_factory) as uow:
        fetched = await uow.analyses.get_with_full_details(analysis_id)
        assert fetched is not None
        assert fetched.verdict == AnalysisVerdict.MALICIOUS
        assert fetched.overall_risk_score == 87
        assert fetched.risk_score is not None
        assert fetched.risk_score.composite_score == 87
        assert fetched.ml_prediction is not None
        assert fetched.ml_prediction.phishing_probability == 0.94
        assert fetched.llm_analysis is not None
        assert fetched.llm_analysis.recommended_action == "quarantine"
        assert len(fetched.threat_signals) == 1
        assert fetched.threat_signals[0].severity == ThreatSeverity.HIGH
        assert len(fetched.events) == 1


@pytest.mark.asyncio
async def test_threat_signal_and_ti_repositories(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Test threat signal queries by attack type and cached threat intelligence."""
    org_id = uuid.uuid4()
    analysis_id = uuid.uuid4()

    async with UnitOfWork(test_session_factory) as uow:
        org = Organization(id=org_id, name="Threat Org", slug="threat-org")
        await uow.organizations.create(org)

        email = Email(
            org_id=org_id,
            message_id="<threat@test.com>",
            from_address="threat@test.com",
            from_domain="test.com",
            received_at=datetime.now(UTC),
        )
        await uow.emails.create(email)

        analysis = Analysis(id=analysis_id, email_id=email.id, org_id=org_id)
        await uow.analyses.create(analysis)

        s1 = ThreatSignal(
            analysis_id=analysis_id,
            org_id=org_id,
            signal_type="spear_phish_rule",
            category=ThreatCategory.PHISHING,
            severity=ThreatSeverity.CRITICAL,
            attack_type=AttackType.SPEAR_PHISHING,
            confidence=0.99,
            source_engine="ml_classifier",
            title="Spear Phishing Targeted at Finance",
        )
        s2 = ThreatSignal(
            analysis_id=analysis_id,
            org_id=org_id,
            signal_type="malware_rule",
            category=ThreatCategory.MALWARE,
            severity=ThreatSeverity.HIGH,
            attack_type=AttackType.MALICIOUS_DOCUMENT,
            confidence=0.91,
            source_engine="attachment_scanner",
            title="Malicious Document Payload",
        )
        await uow.threat_signals.create(s1)
        await uow.threat_signals.create(s2)

        # Add cached TI result with future expiration
        future = datetime.now(UTC) + timedelta(hours=24)
        ti = ThreatIntelligenceResult(
            analysis_id=analysis_id,
            indicator_type="ip",
            indicator_value="198.51.100.99",
            provider="virustotal",
            reputation_verdict=ReputationVerdict.MALICIOUS,
            last_checked_at=datetime.now(UTC),
            expires_at=future,
        )
        await uow.threat_intel.create(ti)

    async with UnitOfWork(test_session_factory) as uow:
        # Attack type filtering
        spear_phish = await uow.threat_signals.list_by_attack_type(
            org_id, AttackType.SPEAR_PHISHING
        )
        assert len(spear_phish) == 1
        assert spear_phish[0].title == "Spear Phishing Targeted at Finance"

        # Severity filtering
        criticals = await uow.threat_signals.list_by_org_and_severity(
            org_id, ThreatSeverity.CRITICAL
        )
        assert len(criticals) == 1

        # TI cache hit
        cached_ti = await uow.threat_intel.find_active_by_indicator("ip", "198.51.100.99")
        assert cached_ti is not None
        assert cached_ti.reputation_verdict == ReputationVerdict.MALICIOUS


@pytest.mark.asyncio
async def test_audit_log_and_system_metrics_repositories(
    test_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Test compliance audit logging and time-series telemetry storage."""
    org_id = uuid.uuid4()
    corr_id = uuid.uuid4()

    async with UnitOfWork(test_session_factory) as uow:
        org = Organization(id=org_id, name="Audit Org", slug="audit-org")
        await uow.organizations.create(org)

        await uow.audit_logs.create_entry(
            org_id=org_id,
            event_type="EMAIL_SUBMITTED",
            action=AuditAction.CREATE,
            resource_type="email",
            resource_id="eml_test123",
            actor_email="analyst@audit-org.com",
            correlation_id=corr_id,
            metadata_payload={"client": "web_dashboard"},
        )

        now = datetime.now(UTC)
        await uow.metrics.record(
            org_id=org_id,
            metric_name="threats_detected_total",
            metric_type=MetricType.COUNTER,
            value=12.0,
            recorded_at=now,
        )

    async with UnitOfWork(test_session_factory) as uow:
        # Audit log lookup by correlation ID
        audits = await uow.audit_logs.list_by_correlation_id(corr_id)
        assert len(audits) == 1
        assert audits[0].event_type == "EMAIL_SUBMITTED"
        assert audits[0].action == AuditAction.CREATE

        # Metric time series lookup
        start = datetime.now(UTC) - timedelta(minutes=5)
        end = datetime.now(UTC) + timedelta(minutes=5)
        samples = await uow.metrics.get_time_series(
            "threats_detected_total", org_id=org_id, start_time=start, end_time=end
        )
        assert len(samples) == 1
        assert samples[0].value == 12.0
