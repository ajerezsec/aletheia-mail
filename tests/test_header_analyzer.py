"""Unit tests for milestone 4 header analyzer."""

from __future__ import annotations

from pathlib import Path

from aletheia.analyzers import HeaderAnalyzer
from aletheia.models import EmailMetadata, FindingSeverity
from aletheia.parsers import EMLParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_header_analyzer_pass_case_has_no_findings() -> None:
    parser = EMLParser()
    analyzer = HeaderAnalyzer()

    metadata = parser.parse(FIXTURES_DIR / "sample_basic.eml")
    analysis = analyzer.analyze(metadata)

    assert analysis.spf_result == "pass"
    assert analysis.dkim_result == "pass"
    assert analysis.dmarc_result == "pass"
    assert analysis.received_hops == 1
    assert analysis.findings == []


def test_header_analyzer_detects_auth_and_domain_mismatches() -> None:
    parser = EMLParser()
    analyzer = HeaderAnalyzer()

    metadata = parser.parse(FIXTURES_DIR / "sample_header_suspicious.eml")
    analysis = analyzer.analyze(metadata)

    titles = {finding.title for finding in analysis.findings}
    assert "SPF check not passed" in titles
    assert "DKIM check not passed" in titles
    assert "DMARC check not passed" in titles
    assert "Reply-To domain differs from From domain" in titles
    assert "Return-Path domain differs from From domain" in titles

    high_findings = [
        finding
        for finding in analysis.findings
        if finding.severity == FindingSeverity.HIGH
    ]
    assert len(high_findings) >= 2


def test_header_analyzer_flags_missing_auth_and_received_chain() -> None:
    analyzer = HeaderAnalyzer()
    metadata = EmailMetadata(
        from_address="sender@example.com",
        to=["target@example.com"],
        authentication_results=None,
        received_headers=[],
    )

    analysis = analyzer.analyze(metadata)
    titles = {finding.title for finding in analysis.findings}

    assert "Authentication-Results header missing" in titles
    assert "SPF result missing" in titles
    assert "DKIM result missing" in titles
    assert "DMARC result missing" in titles
    assert "Received chain missing" in titles
