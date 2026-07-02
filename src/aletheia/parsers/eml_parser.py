"""EML parser implementation for milestone 3."""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from aletheia.models import AttachmentMetadata, EmailMetadata

from .base import BaseParser
from .exceptions import ParseError

URL_REGEX = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)


class EMLParser(BaseParser):
    """Parse RFC822 EML files into normalized `EmailMetadata` models."""

    def parse(self, file_path: Path) -> EmailMetadata:
        """Parse a .eml file and extract metadata, bodies, URLs, and attachments."""
        if not file_path.exists() or not file_path.is_file():
            raise ParseError(f"File not found: {file_path}")

        try:
            with file_path.open("rb") as handle:
                message = BytesParser(policy=policy.default).parse(handle)
        except OSError as exc:
            raise ParseError(f"Unable to read file: {file_path}") from exc
        except Exception as exc:
            raise ParseError(f"Unable to parse EML message: {file_path}") from exc

        from_address = parseaddr(message.get("From", ""))[1]
        if not from_address:
            raise ParseError("Missing required From header")

        to_addresses = [
            address for _, address in getaddresses(message.get_all("To", [])) if address
        ]
        cc_addresses = [
            address for _, address in getaddresses(message.get_all("Cc", [])) if address
        ]

        text_body_parts: list[str] = []
        html_body_parts: list[str] = []
        attachments: list[AttachmentMetadata] = []

        if message.is_multipart():
            for part in message.walk():
                if part.is_multipart():
                    continue

                disposition = (part.get_content_disposition() or "").lower()
                if disposition == "attachment" or part.get_filename():
                    attachments.append(_extract_attachment(part))
                    continue

                content_type = part.get_content_type().lower()
                decoded = _decode_part(part)
                if content_type == "text/plain":
                    text_body_parts.append(decoded)
                elif content_type == "text/html":
                    html_body_parts.append(decoded)
        else:
            content_type = message.get_content_type().lower()
            decoded = _decode_part(message)
            if content_type == "text/html":
                html_body_parts.append(decoded)
            else:
                text_body_parts.append(decoded)

        text_body = "\n".join(filter(None, text_body_parts)) or None
        html_body = "\n".join(filter(None, html_body_parts)) or None
        urls = _extract_urls(text_body, html_body)

        return EmailMetadata(
            subject=message.get("Subject", "") or "",
            from_address=from_address,
            to=to_addresses,
            cc=cc_addresses,
            reply_to=parseaddr(message.get("Reply-To", ""))[1] or None,
            return_path=parseaddr(message.get("Return-Path", ""))[1] or None,
            authentication_results=message.get("Authentication-Results"),
            message_id=message.get("Message-ID"),
            date_header=message.get("Date"),
            received_headers=message.get_all("Received", []),
            text_body=text_body,
            html_body=html_body,
            urls=urls,
            attachments=attachments,
        )


def _decode_part(part: object) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        fallback = part.get_payload() or ""
        return str(fallback)

    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extract_attachment(part: object) -> AttachmentMetadata:
    payload = part.get_payload(decode=True) or b""
    name = part.get_filename() or "unnamed.bin"
    extension = Path(name).suffix.lstrip(".") or "bin"
    mime_type = part.get_content_type()
    sha256 = hashlib.sha256(payload).hexdigest()

    return AttachmentMetadata(
        name=name,
        extension=extension,
        mime_type=mime_type,
        size_bytes=len(payload),
        sha256=sha256,
    )


def _extract_urls(text_body: str | None, html_body: str | None) -> list[str]:
    candidates: list[str] = []
    if text_body:
        candidates.extend(URL_REGEX.findall(text_body))
    if html_body:
        candidates.extend(URL_REGEX.findall(html_body))

    # Preserve order while removing duplicates.
    unique_urls = list(dict.fromkeys(candidates))
    return unique_urls
