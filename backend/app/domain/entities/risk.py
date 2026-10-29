"""Risk scoring domain entities."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.domain.entities.analysis import RiskLevel


class RiskFactor(BaseModel):
    """Individual factor contributing to the composite risk score."""

    model_config = {"frozen": True}

    factor: str = Field(description="Factor identifier, e.g. 'spf_fail'")
    weight: float = Field(ge=0.0, le=1.0, description="Weight in composite score")
    score: float = Field(ge=0.0, le=100.0, description="Raw sub-score 0-100")
    description: str = Field(description="Human-readable explanation")


class RiskScore(BaseModel):
    """Composite risk score computed by the RiskEngine.

    This is the authoritative risk representation for an email.
    Only RiskEngine may create instances of this class.
    """

    model_config = {"frozen": True}

    score: int = Field(ge=0, le=100, description="Composite score 0-100")
    level: RiskLevel
    factors: list[RiskFactor] = Field(default_factory=list)
