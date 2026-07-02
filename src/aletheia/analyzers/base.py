"""Base analyzer interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aletheia.models import EmailMetadata


class BaseAnalyzer(ABC):
    """Contract for all analyzer components."""

    @abstractmethod
    def analyze(self, metadata: EmailMetadata) -> object:
        """Analyze parsed metadata and return a typed analysis result."""
