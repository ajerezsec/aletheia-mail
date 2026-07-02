# Development

## Setup

```bash
python -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev]
```

## Common Commands

```bash
python -m ruff check .
python -m ruff format .
python -m pytest
aletheia --help
```

## Development Principles

- Keep each iteration small and functional.
- Add tests with every behavior change.
- Prefer explicit interfaces and typed models.
- Avoid large classes and long methods.
