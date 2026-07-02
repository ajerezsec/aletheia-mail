"""Domain data models for The Aletheia Project."""

from .email import AttachmentMetadata, EmailMetadata
from .findings import Finding, FindingSeverity
from .report import AnalysisReport
from .risk import RiskLevel, RiskScore

__all__ = [
    "AnalysisReport",
    "AttachmentMetadata",
    "EmailMetadata",
    "Finding",
    "FindingSeverity",
    "RiskLevel",
    "RiskScore",
]
