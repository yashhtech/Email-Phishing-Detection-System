"""Add performance composite indexes for analytics aggregations.

Revision ID: 20260930_0001
Revises: 20260929_0002
Create Date: 2026-09-30 08:30:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260930_0001"
down_revision: str | None = "20260929_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_ml_predictions_analysis_latency", "ml_predictions", ["analysis_id", "latency_ms"]
    )
    op.create_index(
        "ix_llm_analyses_analysis_latency",
        "llm_analyses",
        ["analysis_id", "latency_ms", "confidence_score"],
    )
    op.create_index(
        "ix_ti_analysis_provider_verdict",
        "threat_intelligence_results",
        ["analysis_id", "provider", "reputation_verdict"],
    )
    op.create_index(
        "ix_analyses_org_risk_score_created",
        "analyses",
        ["org_id", "overall_risk_score", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_analyses_org_risk_score_created", table_name="analyses")
    op.drop_index("ix_ti_analysis_provider_verdict", table_name="threat_intelligence_results")
    op.drop_index("ix_llm_analyses_analysis_latency", table_name="llm_analyses")
    op.drop_index("ix_ml_predictions_analysis_latency", table_name="ml_predictions")
