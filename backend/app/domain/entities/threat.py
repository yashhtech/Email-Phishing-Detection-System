"""Threat indicator domain entities."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    """Type of Indicator of Compromise."""

    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    EMAIL_ADDRESS = "email_address"


class ThreatCategory(StrEnum):
    """Threat classification category."""

    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    CREDENTIAL_THEFT = "credential_theft"
    BRAND_IMPERSONATION = "brand_impersonation"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    RANSOMWARE = "ransomware"
    SOCIAL_ENGINEERING = "social_engineering"
    UNKNOWN = "unknown"


class ThreatIndicator(BaseModel):
    """A single Indicator of Compromise (IOC) extracted from email analysis."""

    model_config = {"frozen": True}

    id: str = Field(description="ULID primary key")
    type: IOCType
    value: str = Field(max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
    categories: list[ThreatCategory] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = Field(default=1, ge=1)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    analyst_annotation: str | None = Field(default=None)
    is_false_positive: bool = Field(default=False)
    tags: list[str] = Field(default_factory=list)
