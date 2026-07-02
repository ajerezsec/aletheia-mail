# Architecture Overview

The project follows a modular architecture that isolates concerns and enables long-term growth:

1. Parsing layer: reads `.eml` and creates structured email data.
2. Analyzer layer: independent analyzers for headers, URLs, attachments, and metadata.
3. Findings + scoring layer: converts signals to findings and computes risk.
4. Reporting layer: renders Rich, JSON, and Markdown outputs.
5. CLI layer: orchestrates use cases and output options.

This repository starts with a professional foundation (tooling + packaging + tests), then adds one capability per iteration.
