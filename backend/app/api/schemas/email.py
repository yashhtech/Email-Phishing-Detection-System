"""Pydantic schemas for Email intake and analysis endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator


class StructuredEmailSubmitRequest(BaseModel):
    """Payload for submitting an email using structured form fields."""

    from_address: EmailStr = Field(description="Sender email address")
    to_addresses: list[EmailStr] = Field(
        min_length=1, description="List of primary recipient email addresses"
    )
    cc_addresses: list[EmailStr] = Field(
        default=[], description="List of CC recipient email addresses"
    )
    reply_to: EmailStr | None = Field(default=None, description="Optional Reply-To email address")
    subject: str = Field(min_length=1, max_length=1000, description="Email subject line")
    body_plain: str | None = Field(
        default=None, max_length=500_000, description="Plain text body content (max 500 KB)"
    )
    body_html: str | None = Field(
        default=None, max_length=1_000_000, description="HTML body content (max 1 MB)"
    )
    raw_headers: str | None = Field(
        default=None, max_length=100_000, description="Optional raw email headers"
    )

    @field_validator("from_address", mode="before")
    @classmethod
    def normalise_from(cls, v: str) -> str:
        return v.lower().strip()


class RawEmailSubmitRequest(BaseModel):
    """Payload for submitting a complete raw RFC 822 / MIME email."""

    raw_content: str = Field(
        min_length=5, max_length=5_000_000, description="Complete raw email text (.eml source)"
    )


class ExtractedURLResponse(BaseModel):
    """Extracted URL with domain, IP check, and defanged representation."""

    url: str
    domain: str
    scheme: str
    path: str
    is_ip_address: bool
    defanged_url: str
    reputation: str
    is_suspicious_tld: bool


class ExtractedAttachmentResponse(BaseModel):
    """Attachment metadata with cryptographic hash and safety classification."""

    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_executable: bool
    is_archive: bool


class ExtractedHeadersResponse(BaseModel):
    """Parsed email authentication and routing headers."""

    message_id: str
    from_raw: str
    to_raw: list[str]
    cc_raw: list[str]
    reply_to: str | None
    subject: str | None
    date: datetime
    spf_status: str
    spf_details: str | None
    dkim_status: str
    dkim_details: str | None
    dmarc_status: str
    dmarc_details: str | None
    hop_count: int
    raw_headers: dict[str, str]


class EmailAnalysisSubmitResponse(BaseModel):
    """Full analysis intake response containing preliminary forensic signals."""

    email_id: str
    analysis_id: str
    status: str
    verdict: str
    severity: str | None = None
    risk_score: float | None = None
    message_id: str
    from_address: str
    from_domain: str
    to_addresses: list[str]
    cc_addresses: list[str]
    reply_to: str | None
    subject: str | None
    received_at: datetime
    body_preview: str | None
    body_plain: str | None
    body_html: str | None
    headers: ExtractedHeadersResponse
    urls: list[ExtractedURLResponse]
    attachments: list[ExtractedAttachmentResponse]
    initial_risk_score: float
    initial_risk_level: str
    threat_signals: list[str]
    explanation: str | None = None
    findings: list[str] = Field(default_factory=list)
    security_checks: dict[str, Any] = Field(default_factory=dict)
    threat_categories: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    completed_at: datetime | None = None
