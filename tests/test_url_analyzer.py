"""Unit tests for the URL analyzer."""

from __future__ import annotations

from pathlib import Path

from aletheia.analyzers import URLAnalyzer
from aletheia.models import EmailMetadata, FindingSeverity
from aletheia.parsers import EMLParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_url_analyzer_returns_no_findings_for_benign_fixture() -> None:
    parser = EMLParser()
    analyzer = URLAnalyzer()

    metadata = parser.parse(FIXTURES_DIR / "sample_basic.eml")
    analysis = analyzer.analyze(metadata)

    assert analysis.total_urls == 2
    assert analysis.unique_domains == ["portal.example.com", "secure.example.org"]
    assert analysis.findings == []


def test_url_analyzer_detects_suspicious_patterns() -> None:
    parser = EMLParser()
    analyzer = URLAnalyzer()

    metadata = parser.parse(FIXTURES_DIR / "sample_url_suspicious.eml")
    analysis = analyzer.analyze(metadata)

    titles = {finding.title for finding in analysis.findings}
    assert "Shortened URL detected" in titles
    assert "URL uses IP address instead of domain" in titles
    assert "Punycode domain detected" in titles
    assert "URL uses non-standard port" in titles
    assert "Potential lookalike URL pattern detected" in titles

    high_findings = [
        finding for finding in analysis.findings if finding.severity == FindingSeverity.HIGH
    ]
    assert high_findings


def test_url_analyzer_handles_messages_without_urls() -> None:
    analyzer = URLAnalyzer()
    analysis = analyzer.analyze(metadata=EmailMetadata(from_address="sender@example.com"))

    assert analysis.total_urls == 0
    assert analysis.findings == []
    assert analysis.summary == "No URLs were extracted from the message body."
