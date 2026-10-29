"""Initial schema baseline with 16 core platform models.

Revision ID: 20260929_0001
Revises: None
Create Date: 2026-09-29 17:35:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20260929_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Organizations
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), nullable=False, comment="UUID primary key"),
        sa.Column(
            "name", sa.String(length=255), nullable=False, comment="Organization display name"
        ),
        sa.Column(
            "slug", sa.String(length=100), nullable=False, comment="Unique URL/tenant identifier"
        ),
        sa.Column(
            "primary_domain",
            sa.String(length=255),
            nullable=True,
            comment="Primary domain of the organization",
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default="true",
            comment="Account active status",
        ),
        sa.Column("settings", sa.JSON(), nullable=False, comment="Tenant-specific configuration"),
        sa.Column(
            "deleted_at",
            sa.DateTime(timezone=True),
            nullable=True,
            comment="Soft deletion timestamp",
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"])
    op.create_index("ix_organizations_primary_domain", "organizations", ["primary_domain"])
    op.create_index("ix_organizations_is_active", "organizations", ["is_active"])
    op.create_index("ix_organizations_active_slug", "organizations", ["is_active", "slug"])
    op.create_index("ix_organizations_deleted_at", "organizations", ["deleted_at"])
    op.create_index("ix_organizations_created_at", "organizations", ["created_at"])

    # 2. Roles
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False, comment="UUID primary key"),
        sa.Column("name", sa.String(length=50), nullable=False, comment="Role name"),
        sa.Column(
            "role_type", sa.String(length=50), nullable=False, comment="Base system role level"
        ),
        sa.Column("description", sa.String(length=255), nullable=True),
        sa.Column("permissions", sa.JSON(), nullable=False, comment="Granular permission codes"),
        sa.Column("is_system_role", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_roles_name", "roles", ["name"])
    op.create_index("ix_roles_role_type", "roles", ["role_type"])
    op.create_index("ix_roles_role_type_name", "roles", ["role_type", "name"])
    op.create_index("ix_roles_created_at", "roles", ["created_at"])

    # 3. Users
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False, comment="UUID primary key"),
        sa.Column("org_id", sa.Uuid(), nullable=False, comment="Associated organization tenant ID"),
        sa.Column("role_id", sa.Uuid(), nullable=False, comment="Assigned security role ID"),
        sa.Column("email", sa.String(length=255), nullable=False, comment="User email address"),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_index("ix_users_role_id", "users", ["role_id"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_is_active", "users", ["is_active"])
    op.create_index("ix_users_deleted_at", "users", ["deleted_at"])
    op.create_index("ix_users_org_active", "users", ["org_id", "is_active"])
    op.create_index("ix_users_org_email", "users", ["org_id", "email"])
    op.create_index("ix_users_role_org", "users", ["role_id", "org_id"])
    op.create_index("ix_users_created_at", "users", ["created_at"])

    # 4. Emails
    op.create_table(
        "emails",
        sa.Column("id", sa.Uuid(), nullable=False, comment="UUID primary key"),
        sa.Column("org_id", sa.Uuid(), nullable=False, comment="Owning organization tenant ID"),
        sa.Column("submitted_by_user_id", sa.Uuid(), nullable=True, comment="User submitter"),
        sa.Column(
            "message_id", sa.String(length=998), nullable=False, comment="RFC 5322 Message-ID"
        ),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("from_address", sa.String(length=998), nullable=False),
        sa.Column("from_domain", sa.String(length=255), nullable=False),
        sa.Column("to_addresses", sa.JSON(), nullable=False),
        sa.Column("cc_addresses", sa.JSON(), nullable=False),
        sa.Column("reply_to", sa.String(length=998), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_eml_path", sa.Text(), nullable=True),
        sa.Column("body_plain", sa.Text(), nullable=True),
        sa.Column("body_html", sa.Text(), nullable=True),
        sa.Column("body_preview", sa.String(length=500), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=False, server_default="api"),
        sa.Column("priority", sa.String(length=20), nullable=False, server_default="normal"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("has_attachments", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("attachment_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["submitted_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_emails_org_id", "emails", ["org_id"])
    op.create_index("ix_emails_submitted_by_user_id", "emails", ["submitted_by_user_id"])
    op.create_index("ix_emails_message_id", "emails", ["message_id"])
    op.create_index("ix_emails_from_address", "emails", ["from_address"])
    op.create_index("ix_emails_from_domain", "emails", ["from_domain"])
    op.create_index("ix_emails_received_at", "emails", ["received_at"])
    op.create_index("ix_emails_source", "emails", ["source"])
    op.create_index("ix_emails_status", "emails", ["status"])
    op.create_index("ix_emails_has_attachments", "emails", ["has_attachments"])
    op.create_index("ix_emails_deleted_at", "emails", ["deleted_at"])
    op.create_index("ix_emails_org_received_at", "emails", ["org_id", "received_at"])
    op.create_index("ix_emails_org_status", "emails", ["org_id", "status"])
    op.create_index("ix_emails_from_domain_received", "emails", ["from_domain", "received_at"])
    op.create_index("ix_emails_user_received", "emails", ["submitted_by_user_id", "received_at"])
    op.create_index("ix_emails_message_id_org", "emails", ["message_id", "org_id"])
    op.create_index("ix_emails_created_at", "emails", ["created_at"])

    # 5. EmailHeaders
    op.create_table(
        "email_headers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email_id", sa.Uuid(), nullable=False),
        sa.Column("spf_verdict", sa.String(length=20), nullable=True),
        sa.Column("spf_record", sa.Text(), nullable=True),
        sa.Column("dkim_verdict", sa.String(length=20), nullable=True),
        sa.Column("dkim_selector", sa.String(length=255), nullable=True),
        sa.Column("dkim_domain", sa.String(length=255), nullable=True),
        sa.Column("dmarc_verdict", sa.String(length=20), nullable=True),
        sa.Column("dmarc_policy", sa.String(length=50), nullable=True),
        sa.Column("return_path", sa.String(length=998), nullable=True),
        sa.Column("x_mailer", sa.String(length=255), nullable=True),
        sa.Column("x_originating_ip", sa.String(length=64), nullable=True),
        sa.Column("authentication_results_raw", sa.Text(), nullable=True),
        sa.Column("routing_hops", sa.JSON(), nullable=False),
        sa.Column("raw_headers", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email_id"),
    )
    op.create_index("ix_email_headers_email_id", "email_headers", ["email_id"])
    op.create_index("ix_email_headers_spf_verdict", "email_headers", ["spf_verdict"])
    op.create_index("ix_email_headers_dkim_verdict", "email_headers", ["dkim_verdict"])
    op.create_index("ix_email_headers_dmarc_verdict", "email_headers", ["dmarc_verdict"])
    op.create_index("ix_email_headers_x_originating_ip", "email_headers", ["x_originating_ip"])
    op.create_index("ix_email_headers_created_at", "email_headers", ["created_at"])

    # 6. EmailURLs
    op.create_table(
        "email_urls",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email_id", sa.Uuid(), nullable=False),
        sa.Column("raw_url", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("expanded_url", sa.Text(), nullable=True),
        sa.Column("is_shortened", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("reputation", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column("homoglyph_score", sa.Float(), nullable=True),
        sa.Column("homoglyph_target", sa.String(length=255), nullable=True),
        sa.Column("virustotal_positives", sa.Integer(), nullable=True),
        sa.Column("virustotal_total", sa.Integer(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_email_urls_email_id", "email_urls", ["email_id"])
    op.create_index("ix_email_urls_domain", "email_urls", ["domain"])
    op.create_index("ix_email_urls_reputation", "email_urls", ["reputation"])
    op.create_index("ix_email_urls_is_shortened", "email_urls", ["is_shortened"])
    op.create_index("ix_email_urls_domain_reputation", "email_urls", ["domain", "reputation"])
    op.create_index("ix_email_urls_email_reputation", "email_urls", ["email_id", "reputation"])
    op.create_index("ix_email_urls_created_at", "email_urls", ["created_at"])

    # 7. Attachments
    op.create_table(
        "attachments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email_id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("extension", sa.String(length=50), nullable=True),
        sa.Column("mime_type", sa.String(length=255), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=False),
        sa.Column("md5_hash", sa.String(length=32), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column("reputation", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column("virustotal_positives", sa.Integer(), nullable=True),
        sa.Column("virustotal_total", sa.Integer(), nullable=True),
        sa.Column("is_executable", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("has_macros", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("storage_path", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attachments_email_id", "attachments", ["email_id"])
    op.create_index("ix_attachments_extension", "attachments", ["extension"])
    op.create_index("ix_attachments_mime_type", "attachments", ["mime_type"])
    op.create_index("ix_attachments_md5_hash", "attachments", ["md5_hash"])
    op.create_index("ix_attachments_sha256_hash", "attachments", ["sha256_hash"])
    op.create_index("ix_attachments_reputation", "attachments", ["reputation"])
    op.create_index("ix_attachments_is_executable", "attachments", ["is_executable"])
    op.create_index("ix_attachments_has_macros", "attachments", ["has_macros"])
    op.create_index(
        "ix_attachments_sha256_reputation", "attachments", ["sha256_hash", "reputation"]
    )
    op.create_index("ix_attachments_email_reputation", "attachments", ["email_id", "reputation"])
    op.create_index("ix_attachments_mime_reputation", "attachments", ["mime_type", "reputation"])
    op.create_index("ix_attachments_created_at", "attachments", ["created_at"])

    # 8. Analyses
    op.create_table(
        "analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("verdict", sa.String(length=20), nullable=True),
        sa.Column("overall_risk_score", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(length=20), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("model_versions", sa.JSON(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email_id"),
    )
    op.create_index("ix_analyses_email_id", "analyses", ["email_id"])
    op.create_index("ix_analyses_org_id", "analyses", ["org_id"])
    op.create_index("ix_analyses_status", "analyses", ["status"])
    op.create_index("ix_analyses_verdict", "analyses", ["verdict"])
    op.create_index("ix_analyses_overall_risk_score", "analyses", ["overall_risk_score"])
    op.create_index("ix_analyses_risk_level", "analyses", ["risk_level"])
    op.create_index("ix_analyses_completed_at", "analyses", ["completed_at"])
    op.create_index("ix_analyses_deleted_at", "analyses", ["deleted_at"])
    op.create_index("ix_analyses_org_completed", "analyses", ["org_id", "completed_at"])
    op.create_index("ix_analyses_org_risk_score", "analyses", ["org_id", "overall_risk_score"])
    op.create_index("ix_analyses_org_status", "analyses", ["org_id", "status"])
    op.create_index("ix_analyses_verdict_completed", "analyses", ["verdict", "completed_at"])
    op.create_index("ix_analyses_risk_level_completed", "analyses", ["risk_level", "completed_at"])
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])

    # 9. ThreatSignals
    op.create_table(
        "threat_signals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("signal_type", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("attack_type", sa.String(length=50), nullable=False, server_default="unknown"),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source_engine", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("indicator_value", sa.String(length=500), nullable=True),
        sa.Column("raw_evidence", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_signals_analysis_id", "threat_signals", ["analysis_id"])
    op.create_index("ix_threat_signals_org_id", "threat_signals", ["org_id"])
    op.create_index("ix_threat_signals_signal_type", "threat_signals", ["signal_type"])
    op.create_index("ix_threat_signals_category", "threat_signals", ["category"])
    op.create_index("ix_threat_signals_severity", "threat_signals", ["severity"])
    op.create_index("ix_threat_signals_attack_type", "threat_signals", ["attack_type"])
    op.create_index("ix_threat_signals_confidence", "threat_signals", ["confidence"])
    op.create_index("ix_threat_signals_source_engine", "threat_signals", ["source_engine"])
    op.create_index("ix_threat_signals_indicator_value", "threat_signals", ["indicator_value"])
    op.create_index(
        "ix_threat_signals_severity_category_attack",
        "threat_signals",
        ["severity", "category", "attack_type"],
    )
    op.create_index(
        "ix_threat_signals_org_severity_created",
        "threat_signals",
        ["org_id", "severity", "created_at"],
    )
    op.create_index(
        "ix_threat_signals_analysis_severity", "threat_signals", ["analysis_id", "severity"]
    )
    op.create_index("ix_threat_signals_created_at", "threat_signals", ["created_at"])

    # 10. MLPredictions
    op.create_table(
        "ml_predictions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("model_name", sa.String(length=100), nullable=False),
        sa.Column("model_version", sa.String(length=50), nullable=False),
        sa.Column("prediction_label", sa.String(length=50), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("phishing_probability", sa.Float(), nullable=False),
        sa.Column("spam_probability", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("malware_probability", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("feature_weights", sa.JSON(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id"),
    )
    op.create_index("ix_ml_predictions_analysis_id", "ml_predictions", ["analysis_id"])
    op.create_index("ix_ml_predictions_prediction_label", "ml_predictions", ["prediction_label"])
    op.create_index("ix_ml_predictions_confidence_score", "ml_predictions", ["confidence_score"])
    op.create_index(
        "ix_ml_predictions_phishing_probability", "ml_predictions", ["phishing_probability"]
    )
    op.create_index("ix_ml_predictions_created_at", "ml_predictions", ["created_at"])

    # 11. LLMAnalyses
    op.create_table(
        "llm_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("model_name", sa.String(length=100), nullable=False),
        sa.Column("prompt_version", sa.String(length=50), nullable=False),
        sa.Column("threat_narrative", sa.Text(), nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("recommended_action", sa.String(length=50), nullable=False),
        sa.Column("reasoning", sa.Text(), nullable=True),
        sa.Column("extracted_iocs", sa.JSON(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("token_usage", sa.JSON(), nullable=False),
        sa.Column("safety_passed", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id"),
    )
    op.create_index("ix_llm_analyses_analysis_id", "llm_analyses", ["analysis_id"])
    op.create_index("ix_llm_analyses_recommended_action", "llm_analyses", ["recommended_action"])
    op.create_index("ix_llm_analyses_created_at", "llm_analyses", ["created_at"])

    # 12. RiskScores
    op.create_table(
        "risk_scores",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("composite_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("spf_subscore", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("dkim_subscore", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("dmarc_subscore", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("ml_subscore", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("url_subscore", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("attachment_subscore", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("sender_reputation_subscore", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("factor_breakdown", sa.JSON(), nullable=False),
        sa.Column("scoring_version", sa.String(length=20), nullable=False, server_default="1.0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id"),
    )
    op.create_index("ix_risk_scores_analysis_id", "risk_scores", ["analysis_id"])
    op.create_index("ix_risk_scores_org_id", "risk_scores", ["org_id"])
    op.create_index("ix_risk_scores_composite_score", "risk_scores", ["composite_score"])
    op.create_index("ix_risk_scores_risk_level", "risk_scores", ["risk_level"])
    op.create_index("ix_risk_scores_org_score", "risk_scores", ["org_id", "composite_score"])
    op.create_index(
        "ix_risk_scores_org_level_created", "risk_scores", ["org_id", "risk_level", "created_at"]
    )
    op.create_index(
        "ix_risk_scores_composite_level", "risk_scores", ["composite_score", "risk_level"]
    )
    op.create_index("ix_risk_scores_created_at", "risk_scores", ["created_at"])

    # 13. ThreatIntelligenceResults
    op.create_table(
        "threat_intelligence_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=True),
        sa.Column("indicator_type", sa.String(length=50), nullable=False),
        sa.Column("indicator_value", sa.String(length=500), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column(
            "reputation_verdict", sa.String(length=20), nullable=False, server_default="unknown"
        ),
        sa.Column("threat_score", sa.Integer(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("raw_response", sa.JSON(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_threat_intelligence_results_analysis_id", "threat_intelligence_results", ["analysis_id"]
    )
    op.create_index(
        "ix_threat_intelligence_results_indicator_type",
        "threat_intelligence_results",
        ["indicator_type"],
    )
    op.create_index(
        "ix_threat_intelligence_results_indicator_value",
        "threat_intelligence_results",
        ["indicator_value"],
    )
    op.create_index(
        "ix_threat_intelligence_results_provider", "threat_intelligence_results", ["provider"]
    )
    op.create_index(
        "ix_threat_intelligence_results_reputation_verdict",
        "threat_intelligence_results",
        ["reputation_verdict"],
    )
    op.create_index(
        "ix_threat_intelligence_results_last_checked_at",
        "threat_intelligence_results",
        ["last_checked_at"],
    )
    op.create_index(
        "ix_threat_intelligence_results_expires_at", "threat_intelligence_results", ["expires_at"]
    )
    op.create_index(
        "ix_ti_type_value", "threat_intelligence_results", ["indicator_type", "indicator_value"]
    )
    op.create_index(
        "ix_ti_provider_verdict", "threat_intelligence_results", ["provider", "reputation_verdict"]
    )
    op.create_index("ix_ti_expires_at", "threat_intelligence_results", ["expires_at"])
    op.create_index(
        "ix_threat_intelligence_results_created_at", "threat_intelligence_results", ["created_at"]
    )

    # 14. AnalysisEvents
    op.create_table(
        "analysis_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("stage", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analysis_events_analysis_id", "analysis_events", ["analysis_id"])
    op.create_index("ix_analysis_events_event_type", "analysis_events", ["event_type"])
    op.create_index("ix_analysis_events_stage", "analysis_events", ["stage"])
    op.create_index(
        "ix_analysis_events_analysis_stage", "analysis_events", ["analysis_id", "stage"]
    )
    op.create_index("ix_analysis_events_created_at", "analysis_events", ["created_at"])

    # 15. AuditLogs
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("actor_ip", sa.String(length=64), nullable=True),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=20), nullable=False),
        sa.Column("before_state", sa.JSON(), nullable=True),
        sa.Column("after_state", sa.JSON(), nullable=True),
        sa.Column("metadata_payload", sa.JSON(), nullable=False),
        sa.Column("correlation_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_org_id", "audit_logs", ["org_id"])
    op.create_index("ix_audit_logs_actor_user_id", "audit_logs", ["actor_user_id"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_resource_type", "audit_logs", ["resource_type"])
    op.create_index("ix_audit_logs_resource_id", "audit_logs", ["resource_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_correlation_id", "audit_logs", ["correlation_id"])
    op.create_index("ix_audit_logs_org_created_desc", "audit_logs", ["org_id", "created_at"])
    op.create_index(
        "ix_audit_logs_actor_created_desc", "audit_logs", ["actor_user_id", "created_at"]
    )
    op.create_index("ix_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"])
    op.create_index("ix_audit_logs_event_created_desc", "audit_logs", ["event_type", "created_at"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # 16. SystemMetrics
    op.create_table(
        "system_metrics",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=True),
        sa.Column("metric_name", sa.String(length=100), nullable=False),
        sa.Column("metric_type", sa.String(length=20), nullable=False, server_default="gauge"),
        sa.Column("value", sa.Float(), nullable=False),
        sa.Column("unit", sa.String(length=30), nullable=True),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_system_metrics_org_id", "system_metrics", ["org_id"])
    op.create_index("ix_system_metrics_metric_name", "system_metrics", ["metric_name"])
    op.create_index("ix_system_metrics_metric_type", "system_metrics", ["metric_type"])
    op.create_index("ix_system_metrics_recorded_at", "system_metrics", ["recorded_at"])
    op.create_index(
        "ix_system_metrics_name_recorded", "system_metrics", ["metric_name", "recorded_at"]
    )
    op.create_index(
        "ix_system_metrics_org_name_recorded",
        "system_metrics",
        ["org_id", "metric_name", "recorded_at"],
    )
    op.create_index("ix_system_metrics_created_at", "system_metrics", ["created_at"])


def downgrade() -> None:
    op.drop_table("system_metrics")
    op.drop_table("audit_logs")
    op.drop_table("analysis_events")
    op.drop_table("threat_intelligence_results")
    op.drop_table("risk_scores")
    op.drop_table("llm_analyses")
    op.drop_table("ml_predictions")
    op.drop_table("threat_signals")
    op.drop_table("analyses")
    op.drop_table("attachments")
    op.drop_table("email_urls")
    op.drop_table("email_headers")
    op.drop_table("emails")
    op.drop_table("users")
    op.drop_table("roles")
    op.drop_table("organizations")
