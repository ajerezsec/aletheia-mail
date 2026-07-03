"""Unit tests for domain models."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from aletheia.models import (
    AnalysisReport,
    AttachmentMetadata,
    EmailMetadata,
    Finding,
    FindingSeverity,
    RiskLevel,
    RiskScore,
)


def test_email_metadata_accepts_valid_addresses() -> None:
    model = EmailMetadata(
        subject="Invoice",
        from_address="sender@example.com",
        to=["ops@example.com"],
        cc=["audit@example.org"],
        reply_to="reply@example.com",
    )
    assert model.from_address == "sender@example.com"
    assert model.to == ["ops@example.com"]


def test_email_metadata_rejects_invalid_sender() -> None:
    with pytest.raises(ValidationError):
        EmailMetadata(from_address="not-an-email")


def test_attachment_metadata_normalizes_and_validates() -> None:
    attachment = AttachmentMetadata(
        name="payload.EXE",
        extension=".EXE",
        mime_type="application/octet-stream",
        size_bytes=2048,
        sha256="a" * 64,
    )
    assert attachment.extension == "exe"
    assert attachment.sha256 == "a" * 64


def test_finding_requires_non_empty_fields() -> None:
    with pytest.raises(ValidationError):
        Finding(
            title="",
            severity=FindingSeverity.HIGH,
            explanation="bad",
            evidence="x",
            recommendation="y",
        )


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [(0, RiskLevel.LOW), (33, RiskLevel.LOW), (34, RiskLevel.MEDIUM), (70, RiskLevel.HIGH)],
)
def test_risk_score_classification(score: int, expected_level: RiskLevel) -> None:
    risk = RiskScore.from_score(score)
    assert risk.level == expected_level


def test_analysis_report_aggregates_required_sections() -> None:
    metadata = EmailMetadata(from_address="sender@example.com")
    finding = Finding(
        title="Reply-To domain differs",
        severity=FindingSeverity.HIGH,
        explanation="Reply-To domain does not match From domain.",
        evidence="From: microsoft.com; Reply-To: secure-login.ru",
        recommendation="Verify sender legitimacy before interacting.",
    )
    risk = RiskScore(score=88, level=RiskLevel.HIGH)

    report = AnalysisReport(
        executive_summary="High-risk email with sender mismatch indicators.",
        risk_score=risk,
        findings=[finding],
        headers={"From": "sender@example.com", "Received": ["hop1", "hop2"]},
        urls=["https://example.com"],
        metadata=metadata,
    )

    assert report.risk_score.score == 88
    assert len(report.findings) == 1
    assert isinstance(report.generated_at, datetime)
