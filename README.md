# The Aletheia Project

The Aletheia Project is an open source cybersecurity initiative focused on email threat analysis.

In Greek philosophy, **Aletheia** means *unconcealed truth*. This project applies that idea to suspicious emails: reveal hidden technical signals, explain risk clearly, and produce actionable reports.

## Objectives

- Build clean, modular, and scalable Python architecture.
- Keep engineering quality high from day one (tests, linting, docs).
- Deliver clear risk findings for analysts and defenders.
- Grow incrementally as a real long-term open source project.

## Planned Features (MVP)

- Parse `.eml` files and extract core metadata.
- Analyze headers (SPF, DKIM, DMARC, Received chain anomalies).
- Analyze URLs (domain, root domain, punycode, IP usage, shorteners, suspicious patterns).
- Analyze attachments (name, extension, MIME, size, SHA256, dangerous extensions).
- Generate findings with severity, evidence, and recommendation.
- Compute a 0-100 risk score with Low/Medium/High classification.
- Export reports in Rich terminal view, JSON, and Markdown.

## Installation

Prerequisites:

- Python 3.11+

```bash
python -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev]
```

## Usage

Current CLI baseline:

```bash
aletheia --help
aletheia analyze suspicious.eml
```

MVP targets:

```bash
aletheia analyze suspicious.eml
aletheia analyze suspicious.eml --json
aletheia analyze suspicious.eml --markdown report.md
```

## Screenshots

Placeholders until Rich reporting is implemented:

- `docs/assets/terminal-report-placeholder.png`
- `docs/assets/json-output-placeholder.png`
- `docs/assets/markdown-report-placeholder.png`

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## Contributing

Contributions are welcome.

1. Open an issue describing the problem or proposal.
2. Discuss approach before large changes.
3. Submit small, focused pull requests with tests.

## License

MIT. See [LICENSE](LICENSE).
