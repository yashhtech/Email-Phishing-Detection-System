"""Add performance indexes for analysis history filtering and pagination.

Revision ID: 20260929_0002
Revises: 20260929_0001
Create Date: 2026-09-29 23:25:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260929_0002"
down_revision: str | None = "20260929_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Analyses indexes for history search, date-range, and severity sorting
    op.create_index("ix_analyses_org_created_at", "analyses", ["org_id", "created_at"])
    op.create_index(
        "ix_analyses_org_risk_level_created", "analyses", ["org_id", "risk_level", "created_at"]
    )
    op.create_index(
        "ix_analyses_org_verdict_created", "analyses", ["org_id", "verdict", "created_at"]
    )

    # 2. ThreatSignal index for attack_type filtering
    op.create_index(
        "ix_threat_signals_analysis_attack", "threat_signals", ["analysis_id", "attack_type"]
    )

    # 3. Email index for sender filtering
    op.create_index("ix_emails_org_from_address", "emails", ["org_id", "from_address"])


def downgrade() -> None:
    op.drop_index("ix_emails_org_from_address", table_name="emails")
    op.drop_index("ix_threat_signals_analysis_attack", table_name="threat_signals")
    op.drop_index("ix_analyses_org_verdict_created", table_name="analyses")
    op.drop_index("ix_analyses_org_risk_level_created", table_name="analyses")
    op.drop_index("ix_analyses_org_created_at", table_name="analyses")
