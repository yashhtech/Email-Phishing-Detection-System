"""Add performance indexes for search, analysis events, and active status.

Revision ID: 20261007_0001
Revises: 20260930_0001
Create Date: 2026-10-07 00:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "20261007_0001"
down_revision: str | None = "20260930_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Partial index: fast lookup for non-deleted analyses by org
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_analyses_org_active_created "
        "ON analyses (org_id, created_at DESC) WHERE deleted_at IS NULL"
    )

    # Analysis event timeline queries: fast sequential access by stage event
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_analysis_events_analysis_created "
        "ON analysis_events (analysis_id, created_at ASC)"
    )

    # ThreatIntel: fast lookup by indicator value for cache misses / queries
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_ti_indicator_value "
        "ON threat_intelligence_results (indicator_value)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_ti_indicator_value")
    op.execute("DROP INDEX IF EXISTS ix_analysis_events_analysis_created")
    op.execute("DROP INDEX IF EXISTS ix_analyses_org_active_created")
