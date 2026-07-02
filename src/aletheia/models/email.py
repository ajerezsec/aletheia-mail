"""Email-related domain models."""

from __future__ import annotations

from email.utils import parseaddr

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_email(value: str) -> str:
    """Validate an email address using stdlib parsing and simple shape checks."""
    normalized = value.strip()
    _, parsed = parseaddr(normalized)
    if "@" not in parsed:
        raise ValueError("must be a valid email address")

    local_part, domain = parsed.rsplit("@", maxsplit=1)
    if not local_part or not domain or "." not in domain:
        raise ValueError("must be a valid email address")
    return parsed


class AttachmentMetadata(BaseModel):
    """Attachment information extracted from an email."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1)
    extension: str = Field(min_length=1, description="File extension without dot.")
    mime_type: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)

    @field_validator("extension")
    @classmethod
    def normalize_extension(cls, value: str) -> str:
        return value.lower().lstrip(".")

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        normalized = value.lower()
        allowed = set("0123456789abcdef")
        if len(normalized) != 64 or any(char not in allowed for char in normalized):
            raise ValueError("must be a valid SHA256 hexadecimal digest")
        return normalized


class EmailMetadata(BaseModel):
    """Core parsed email metadata used by analyzers and reporting."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True)

    subject: str = Field(default="", description="Subject header value.")
    from_address: str = Field(min_length=3)
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    reply_to: str | None = None
    return_path: str | None = None
    authentication_results: str | None = None
    message_id: str | None = None
    date_header: str | None = None
    received_headers: list[str] = Field(default_factory=list)
    text_body: str | None = None
    html_body: str | None = None
    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentMetadata] = Field(default_factory=list)

    @field_validator("from_address", "reply_to", "return_path")
    @classmethod
    def validate_optional_email_fields(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _validate_email(value)

    @field_validator("to", "cc")
    @classmethod
    def validate_email_list(cls, value: list[str]) -> list[str]:
        return [_validate_email(item) for item in value]
