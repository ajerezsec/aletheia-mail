"""Unit tests for milestone 3 EML parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from aletheia.parsers import EMLParser, ParseError

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_eml_parser_extracts_expected_metadata() -> None:
    parser = EMLParser()

    metadata = parser.parse(FIXTURES_DIR / "sample_basic.eml")

    assert metadata.subject == "Invoice review required"
    assert metadata.from_address == "security@example.com"
    assert metadata.to == ["analyst@example.com"]
    assert metadata.cc == ["soc@example.com"]
    assert metadata.reply_to == "noreply@example.com"
    assert metadata.return_path == "bounce@example.com"
    assert metadata.authentication_results is not None
    assert metadata.message_id == "<sample-1@example.com>"
    assert metadata.date_header == "Thu, 02 Jul 2026 10:00:00 +0000"
    assert len(metadata.received_headers) == 1
    assert metadata.text_body is not None
    assert metadata.html_body is not None


def test_eml_parser_extracts_urls_and_attachments() -> None:
    parser = EMLParser()

    metadata = parser.parse(FIXTURES_DIR / "sample_basic.eml")

    assert metadata.urls == [
        "https://portal.example.com/review?id=42",
        "https://secure.example.org/login",
    ]
    assert len(metadata.attachments) == 1

    attachment = metadata.attachments[0]
    assert attachment.name == "invoice.txt"
    assert attachment.extension == "txt"
    assert attachment.mime_type == "text/plain"
    assert attachment.size_bytes > 0
    assert len(attachment.sha256) == 64


def test_eml_parser_raises_on_missing_from_header() -> None:
    parser = EMLParser()

    with pytest.raises(ParseError, match="Missing required From header"):
        parser.parse(FIXTURES_DIR / "sample_missing_from.eml")


def test_eml_parser_raises_for_nonexistent_file() -> None:
    parser = EMLParser()

    with pytest.raises(ParseError, match="File not found"):
        parser.parse(FIXTURES_DIR / "does-not-exist.eml")
