"""CLI smoke tests for The Aletheia Project."""

from pathlib import Path

from typer.testing import CliRunner

from aletheia.cli import app

runner = CliRunner()


def test_cli_help_shows_project_name() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Aletheia" in result.stdout


def test_analyze_command_accepts_existing_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.eml"
    sample.write_text("Subject: test\n\nHello", encoding="utf-8")

    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0
    assert "Scaffold ready" in result.stdout
