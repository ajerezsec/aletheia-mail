"""Parser interface contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from aletheia.models import EmailMetadata


class BaseParser(ABC):
    """Base interface for all file parsers."""

    @abstractmethod
    def parse(self, file_path: Path) -> EmailMetadata:
        """Parse a file path into normalized email metadata."""
