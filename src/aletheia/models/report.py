"""Report models for CLI and output formatters."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from .email import AttachmentMetadata, EmailMetadata
from .findings import Finding
from .risk import RiskScore


class AnalysisReport(BaseModel):
    """Aggregated report for one analyzed email."""

    model_config = ConfigDict(validate_assignment=True)

    executive_summary: str = Field(min_length=1)
    risk_score: RiskScore
    findings: list[Finding] = Field(default_factory=list)
    headers: dict[str, str | list[str]] = Field(default_factory=dict)
    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentMetadata] = Field(default_factory=list)
    metadata: EmailMetadata
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
