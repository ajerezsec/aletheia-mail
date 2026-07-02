"""Command-line interface for The Aletheia Project."""

from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(
    help="The Aletheia Project: uncover hidden technical truth in suspicious emails."
)
console = Console()
EmlPathArgument = typer.Argument(..., exists=True, readable=True, help="Path to .eml file.")


@app.callback()
def main() -> None:
    """Aletheia CLI entrypoint."""


@app.command("analyze")
def analyze(
    eml_path: Path = EmlPathArgument,
) -> None:
    """Analyze a .eml file (analysis engine will be added in next iteration)."""

    console.print(f"[bold]Input:[/bold] {eml_path}")
    console.print("[yellow]Scaffold ready:[/yellow] analyzer engine is not implemented yet.")


if __name__ == "__main__":
    app()
