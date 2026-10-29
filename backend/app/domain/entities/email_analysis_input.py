"""Canonical structured input model for downstream email threat detection engines.

All downstream engines (ML classifier, Groq LLM, Threat Intel, Heuristic rules,
and Forensic reporting) consume this canonical entity.

Design principles:
1. Strict separation of original evidence (unmodified raw bytes/text) and normalized data.
2. Sanitized HTML safe for UI rendering without script execution.
3. Safe attachment metadata extracted without file execution.
4. Structural anomaly telemetry flagging malformed RFC 5322 MIME structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class RawEvidence:
    """Immutable snapshot of raw unnormalized evidence."""

    raw_content: str | bytes
    raw_header_pairs: tuple[tuple[str, str], ...]
    raw_from: str
    raw_to: tuple[str, ...]
    raw_cc: tuple[str, ...]
    raw_bcc: tuple[str, ...]
    raw_reply_to: str | None
    raw_return_path: str | None
    raw_subject: str | None
    raw_date: str | None
    raw_body_plain: str | None
    raw_body_html: str | None


@dataclass(frozen=True)
class NormalizedSender:
    """Normalized sender identity with spoofing heuristics."""

    address: str
    display_name: str
    domain: str
    local_part: str
    is_spoofed_display_name: bool = False
    spoofed_target: str | None = None


@dataclass(frozen=True)
class NormalizedRecipient:
    """Normalized recipient identity."""

    address: str
    display_name: str
    domain: str
    recipient_type: str  # 'to', 'cc', 'bcc'


@dataclass(frozen=True)
class NormalizedHeaders:
    """Cleaned and categorized header metadata."""

    message_id: str
    date: datetime
    all_headers: dict[str, list[str]]
    received_hops: tuple[dict[str, Any], ...]
    spf_header: str | None = None
    dkim_header: str | None = None
    dmarc_header: str | None = None
    arc_headers: tuple[str, ...] = ()
    x_originating_ip: str | None = None
    x_mailer: str | None = None


@dataclass(frozen=True)
class NormalizedContent:
    """Content representation with both raw original and sanitized versions."""

    normalized_plain: str
    raw_html: str | None
    sanitized_html: str | None  # Safe for UI rendering (scripts & event handlers stripped)
    clean_text_for_ai: str  # Token-efficient representation for ML and Groq LLM
    character_count: int
    has_html: bool
    has_plain: bool


@dataclass(frozen=True)
class ExtractedURLItem:
    """Extracted URL with canonicalization and safe defanged form."""

    raw_url: str
    canonical_url: str
    defanged_url: str
    domain: str
    scheme: str
    path: str
    is_ip_address: bool
    is_shortener: bool
    is_suspicious_tld: bool
    source_location: str  # 'body_plain', 'body_html_href', 'body_html_text', 'header'


@dataclass(frozen=True)
class ExtractedAttachmentMetadata:
    """Safe attachment telemetry extracted without executing files."""

    filename: str
    safe_filename: str
    extension: str
    declared_mime_type: str
    detected_mime_type: str
    size_bytes: int
    md5_hash: str
    sha256_hash: str
    is_executable: bool
    is_archive: bool
    has_double_extension: bool
    has_macro_extension: bool
    entropy_score: float | None = None


@dataclass(frozen=True)
class StructuralAnomaly:
    """Detected malformation or evasion indicator in the email structure."""

    anomaly_type: str
    description: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'


@dataclass(frozen=True)
class StructuralIntegrity:
    """Integrity report for RFC MIME structure and parser anomalies."""

    is_malformed: bool
    anomalies: tuple[StructuralAnomaly, ...]
    flags: tuple[str, ...]


@dataclass(frozen=True)
class EmailAnalysisInput:
    """Primary canonical model passed into all downstream detection engines."""

    analysis_input_id: str
    raw_evidence: RawEvidence
    sender: NormalizedSender
    recipients: tuple[NormalizedRecipient, ...]
    reply_to: str | None
    return_path: str | None
    subject: str
    normalized_subject: str
    headers: NormalizedHeaders
    content: NormalizedContent
    urls: tuple[ExtractedURLItem, ...]
    domains: tuple[str, ...]
    attachments: tuple[ExtractedAttachmentMetadata, ...]
    integrity: StructuralIntegrity
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
