"""Risk scoring models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(StrEnum):
    """Risk classification bands."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskScore(BaseModel):
    """Final risk score and classification."""

    model_config = ConfigDict(validate_assignment=True)

    score: int = Field(ge=0, le=100)
    level: RiskLevel

    @classmethod
    def from_score(cls, score: int) -> RiskScore:
        if score <= 33:
            level = RiskLevel.LOW
        elif score <= 66:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.HIGH
        return cls(score=score, level=level)
