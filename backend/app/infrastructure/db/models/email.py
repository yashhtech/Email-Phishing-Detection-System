"""Email entity models including headers, URLs, and attachments."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.infrastructure.db.models.base_model import BaseModel, SoftDeleteMixin
from app.infrastructure.db.models.enums import (
    AuthResultStatus,
    EmailPriority,
    EmailStatus,
    ReputationVerdict,
)

if TYPE_CHECKING:
    from app.infrastructure.db.models.analysis import Analysis
    from app.infrastructure.db.models.organization import Organization
    from app.infrastructure.db.models.user import User


class Email(BaseModel, SoftDeleteMixin):
    """Submitted email message record."""

    __tablename__ = "emails"

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owning organization tenant ID",
    )
    submitted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who submitted this email if submitted via UI/API",
    )
    message_id: Mapped[str] = mapped_column(
        String(998),
        nullable=False,
        index=True,
        comment="RFC 5322 Message-ID header",
    )
    subject: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Subject line text",
    )
    from_address: Mapped[str] = mapped_column(
        String(998),
        nullable=False,
        index=True,
        comment="Raw sender email address",
    )
    from_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Extracted sender domain",
    )
    to_addresses: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Recipient addresses",
    )
    cc_addresses: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="CC addresses",
    )
    reply_to: Mapped[str | None] = mapped_column(
        String(998),
        nullable=True,
        comment="Reply-To header address",
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Original email arrival timestamp",
    )
    raw_eml_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Storage path for raw EML payload",
    )
    body_plain: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Decoded plain-text body content",
    )
    body_html: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Decoded HTML body content",
    )
    body_preview: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Sanitized snippet for preview lists",
    )
    source: Mapped[str] = mapped_column(
        String(50),
        default="api",
        nullable=False,
        index=True,
        comment="Origin source (api, imap, forward, emlsync)",
    )
    priority: Mapped[EmailPriority] = mapped_column(
        Enum(EmailPriority, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=EmailPriority.NORMAL,
        nullable=False,
        comment="Analysis priority queue tier",
    )
    status: Mapped[EmailStatus] = mapped_column(
        Enum(EmailStatus, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=EmailStatus.QUEUED,
        nullable=False,
        index=True,
        comment="Lifecycle status of email",
    )
    has_attachments: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="Whether email has file attachments",
    )
    attachment_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Count of attachments",
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="emails",
    )
    submitted_by_user: Mapped[User | None] = relationship(
        "User",
        back_populates="submitted_emails",
    )
    header: Mapped[EmailHeader | None] = relationship(
        "EmailHeader",
        back_populates="email",
        uselist=False,
        cascade="all, delete-orphan",
    )
    urls: Mapped[list[EmailURL]] = relationship(
        "EmailURL",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    attachments: Mapped[list[Attachment]] = relationship(
        "Attachment",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    analysis: Mapped[Analysis | None] = relationship(
        "Analysis",
        back_populates="email",
        uselist=False,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_emails_org_received_at", "org_id", "received_at"),
        Index("ix_emails_org_status", "org_id", "status"),
        Index("ix_emails_from_domain_received", "from_domain", "received_at"),
        Index("ix_emails_user_received", "submitted_by_user_id", "received_at"),
        Index("ix_emails_message_id_org", "message_id", "org_id"),
        Index("ix_emails_org_from_address", "org_id", "from_address"),
    )


class EmailHeader(BaseModel):
    """Detailed forensic email header analysis."""

    __tablename__ = "email_headers"

    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("emails.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
        comment="Target email ID",
    )
    spf_verdict: Mapped[AuthResultStatus | None] = mapped_column(
        Enum(AuthResultStatus, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=True,
        index=True,
        comment="SPF verification outcome",
    )
    spf_record: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Queried SPF TXT record",
    )
    dkim_verdict: Mapped[AuthResultStatus | None] = mapped_column(
        Enum(AuthResultStatus, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=True,
        index=True,
        comment="DKIM signature verification outcome",
    )
    dkim_selector: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="DKIM selector key",
    )
    dkim_domain: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="DKIM signing domain (d=)",
    )
    dmarc_verdict: Mapped[AuthResultStatus | None] = mapped_column(
        Enum(AuthResultStatus, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        nullable=True,
        index=True,
        comment="DMARC alignment outcome",
    )
    dmarc_policy: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        comment="DMARC policy (none, quarantine, reject)",
    )
    return_path: Mapped[str | None] = mapped_column(
        String(998),
        nullable=True,
        comment="Return-Path envelope sender",
    )
    x_mailer: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="X-Mailer / User-Agent client",
    )
    x_originating_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        comment="Originating sending server IP",
    )
    authentication_results_raw: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Authentication-Results header text",
    )
    routing_hops: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="Extracted Received hops chronological sequence",
    )
    raw_headers: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        comment="Complete dictionary of all parsed RFC headers",
    )

    # Relationship
    email: Mapped[Email] = relationship(
        "Email",
        back_populates="header",
    )


class EmailURL(BaseModel):
    """Extracted URL and associated threat telemetry."""

    __tablename__ = "email_urls"

    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Parent email reference",
    )
    raw_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="URL extracted directly from email body/headers",
    )
    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Extracted hostname/domain",
    )
    expanded_url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Destination URL after resolving HTTP redirects",
    )
    is_shortened: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="True if link points to URL shortener service",
    )
    reputation: Mapped[ReputationVerdict] = mapped_column(
        Enum(ReputationVerdict, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=ReputationVerdict.UNKNOWN,
        nullable=False,
        index=True,
        comment="Aggregated URL reputation verdict",
    )
    homoglyph_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Similarity score against monitored brand domains (0.0 - 1.0)",
    )
    homoglyph_target: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Impersonated legitimate brand domain name",
    )
    virustotal_positives: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Positive security vendor detections count",
    )
    virustotal_total: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Total security vendors queried",
    )
    checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of reputation query",
    )

    # Relationship
    email: Mapped[Email] = relationship(
        "Email",
        back_populates="urls",
    )

    __table_args__ = (
        Index("ix_email_urls_domain_reputation", "domain", "reputation"),
        Index("ix_email_urls_email_reputation", "email_id", "reputation"),
    )


class Attachment(BaseModel):
    """Email file attachment record and security scan results."""

    __tablename__ = "attachments"

    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Parent email reference",
    )
    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Original attachment filename",
    )
    extension: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True,
        comment="Normalized file extension e.g. 'pdf', 'exe'",
    )
    mime_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Detected MIME type based on magic bytes",
    )
    file_size_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Size of attachment in bytes",
    )
    md5_hash: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        comment="MD5 checksum hex digest",
    )
    sha256_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="SHA-256 checksum hex digest",
    )
    reputation: Mapped[ReputationVerdict] = mapped_column(
        Enum(ReputationVerdict, native_enum=False, values_callable=lambda x: [e.value for e in x]),
        default=ReputationVerdict.UNKNOWN,
        nullable=False,
        index=True,
        comment="Reputation assessment of attachment",
    )
    virustotal_positives: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Positive vendor detections count",
    )
    virustotal_total: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Total vendor engines queried",
    )
    is_executable: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="Whether attachment contains executable code or script",
    )
    has_macros: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="Whether document attachment contains embedded VBA macros",
    )
    storage_path: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Quarantine / object storage URI",
    )

    # Relationship
    email: Mapped[Email] = relationship(
        "Email",
        back_populates="attachments",
    )

    __table_args__ = (
        Index("ix_attachments_sha256_reputation", "sha256_hash", "reputation"),
        Index("ix_attachments_email_reputation", "email_id", "reputation"),
        Index("ix_attachments_mime_reputation", "mime_type", "reputation"),
    )
