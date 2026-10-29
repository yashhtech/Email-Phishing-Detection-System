"""Unit of Work implementation managing database transactions across repositories."""

from __future__ import annotations

from types import TracebackType
from typing import Self

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.infrastructure.db.repositories.analysis_repo import AnalysisRepository
from app.infrastructure.db.repositories.analytics_repo import AnalyticsRepository
from app.infrastructure.db.repositories.audit_repo import AuditLogRepository
from app.infrastructure.db.repositories.dashboard_repo import DashboardRepository
from app.infrastructure.db.repositories.email_repo import EmailRepository
from app.infrastructure.db.repositories.metrics_repo import SystemMetricRepository
from app.infrastructure.db.repositories.organization_repo import OrganizationRepository
from app.infrastructure.db.repositories.threat_repo import (
    ThreatIntelligenceRepository,
    ThreatSignalRepository,
)
from app.infrastructure.db.repositories.user_repo import UserRepository
from app.infrastructure.db.session import AsyncSessionLocal


class UnitOfWork:
    """Manages transactional boundaries and coordinates repositories over a shared session."""

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] = AsyncSessionLocal
    ) -> None:
        self._session_factory = session_factory
        self.session: AsyncSession | None = None

        # Repository attributes instantiated during context entry
        self._organizations: OrganizationRepository | None = None
        self._users: UserRepository | None = None
        self._emails: EmailRepository | None = None
        self._analyses: AnalysisRepository | None = None
        self._threat_signals: ThreatSignalRepository | None = None
        self._threat_intel: ThreatIntelligenceRepository | None = None
        self._audit_logs: AuditLogRepository | None = None
        self._metrics: SystemMetricRepository | None = None
        self._dashboard: DashboardRepository | None = None
        self._analytics: AnalyticsRepository | None = None

    async def __aenter__(self) -> Self:
        self.session = self._session_factory()
        self._organizations = OrganizationRepository(self.session)
        self._users = UserRepository(self.session)
        self._emails = EmailRepository(self.session)
        self._analyses = AnalysisRepository(self.session)
        self._threat_signals = ThreatSignalRepository(self.session)
        self._threat_intel = ThreatIntelligenceRepository(self.session)
        self._audit_logs = AuditLogRepository(self.session)
        self._metrics = SystemMetricRepository(self.session)
        self._dashboard = DashboardRepository(self.session)
        self._analytics = AnalyticsRepository(self.session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self.session is not None:
            try:
                if exc_type is not None:
                    await self.rollback()
                else:
                    await self.commit()
            finally:
                await self.session.close()

    async def commit(self) -> None:
        """Commit all pending database changes."""
        if self.session is not None:
            await self.session.commit()

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        if self.session is not None:
            await self.session.rollback()

    @property
    def organizations(self) -> OrganizationRepository:
        """Access OrganizationRepository."""
        assert self._organizations is not None, "UnitOfWork not initialized with context manager"
        return self._organizations

    @property
    def users(self) -> UserRepository:
        """Access UserRepository."""
        assert self._users is not None, "UnitOfWork not initialized with context manager"
        return self._users

    @property
    def emails(self) -> EmailRepository:
        """Access EmailRepository."""
        assert self._emails is not None, "UnitOfWork not initialized with context manager"
        return self._emails

    @property
    def analyses(self) -> AnalysisRepository:
        """Access AnalysisRepository."""
        assert self._analyses is not None, "UnitOfWork not initialized with context manager"
        return self._analyses

    @property
    def threat_signals(self) -> ThreatSignalRepository:
        """Access ThreatSignalRepository."""
        assert self._threat_signals is not None, "UnitOfWork not initialized with context manager"
        return self._threat_signals

    @property
    def threat_intel(self) -> ThreatIntelligenceRepository:
        """Access ThreatIntelligenceRepository."""
        assert self._threat_intel is not None, "UnitOfWork not initialized with context manager"
        return self._threat_intel

    @property
    def audit_logs(self) -> AuditLogRepository:
        """Access AuditLogRepository."""
        assert self._audit_logs is not None, "UnitOfWork not initialized with context manager"
        return self._audit_logs

    @property
    def metrics(self) -> SystemMetricRepository:
        """Access SystemMetricRepository."""
        assert self._metrics is not None, "UnitOfWork not initialized with context manager"
        return self._metrics

    @property
    def dashboard(self) -> DashboardRepository:
        """Access DashboardRepository for PostgreSQL-backed aggregations."""
        assert self._dashboard is not None, "UnitOfWork not initialized with context manager"
        return self._dashboard

    @property
    def analytics(self) -> AnalyticsRepository:
        """Access AnalyticsRepository for analytics queries and aggregations."""
        assert self._analytics is not None, "UnitOfWork not initialized with context manager"
        return self._analytics
