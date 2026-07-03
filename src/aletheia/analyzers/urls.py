"""URL analyzer for suspicious link patterns."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from aletheia.models import EmailMetadata, Finding, FindingSeverity

from .base import BaseAnalyzer

SHORTENER_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "is.gd",
    "ow.ly",
}
DEFAULT_PORTS = {"http": 80, "https": 443}


class URLAnalysis(BaseModel):
    """Structured result for URL-focused checks."""

    model_config = ConfigDict(validate_assignment=True)

    total_urls: int = Field(ge=0)
    unique_domains: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: str = Field(min_length=1)


class URLAnalyzer(BaseAnalyzer):
    """Analyze extracted URLs and flag common phishing indicators."""

    def analyze(self, metadata: EmailMetadata) -> URLAnalysis:
        findings: list[Finding] = []
        unique_domains: list[str] = []

        for url in metadata.urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if host and host not in unique_domains:
                unique_domains.append(host)

            findings.extend(_findings_for_url(url, parsed))

        summary = _build_summary(metadata.urls, unique_domains, findings)
        return URLAnalysis(
            total_urls=len(metadata.urls),
            unique_domains=unique_domains,
            findings=findings,
            summary=summary,
        )


def _findings_for_url(url: str, parsed: object) -> list[Finding]:
    host = (parsed.hostname or "").lower()
    findings: list[Finding] = []

    if not host:
        return findings

    if _is_ip_host(host):
        findings.append(
            _finding(
                title="URL uses IP address instead of domain",
                severity=FindingSeverity.HIGH,
                explanation="URLs that use raw IP addresses often bypass normal trust cues.",
                evidence=url,
                recommendation=(
                    "Avoid opening the link until the destination is independently "
                    "verified."
                ),
            )
        )

    if host in SHORTENER_DOMAINS:
        findings.append(
            _finding(
                title="Shortened URL detected",
                severity=FindingSeverity.MEDIUM,
                explanation=(
                    "URL shortening obscures the real destination and is common "
                    "in phishing lures."
                ),
                evidence=url,
                recommendation=(
                    "Expand the link safely before interacting with the "
                    "destination."
                ),
            )
        )

    if parsed.port and parsed.port != DEFAULT_PORTS.get(parsed.scheme):
        findings.append(
            _finding(
                title="URL uses non-standard port",
                severity=FindingSeverity.MEDIUM,
                explanation=(
                    "Unexpected ports can indicate evasive infrastructure or "
                    "non-standard services."
                ),
                evidence=url,
                recommendation=(
                    "Validate that the service and port are expected before "
                    "opening the link."
                ),
            )
        )

    if "xn--" in host:
        findings.append(
            _finding(
                title="Punycode domain detected",
                severity=FindingSeverity.MEDIUM,
                explanation=(
                    "Punycode can legitimately encode IDNs, but it is also used "
                    "in lookalike domains."
                ),
                evidence=url,
                recommendation=(
                    "Inspect the domain carefully for spoofing before trusting "
                    "the destination."
                ),
            )
        )

    if _looks_deceptive(host):
        findings.append(
            _finding(
                title="Potential lookalike URL pattern detected",
                severity=FindingSeverity.MEDIUM,
                explanation=(
                    "The domain shape resembles a common impersonation pattern "
                    "used in phishing links."
                ),
                evidence=url,
                recommendation="Verify the root domain and brand ownership before clicking.",
            )
        )

    return findings


def _is_ip_host(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def _looks_deceptive(host: str) -> bool:
    if host.count(".") >= 3:
        return True

    labels = host.split(".")
    if len(labels) < 2:
        return False

    second_level = labels[-2]
    suspicious_tokens = ("login", "secure", "verify", "update")
    return any(token in second_level for token in suspicious_tokens)


def _finding(
    *,
    title: str,
    severity: FindingSeverity,
    explanation: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        explanation=explanation,
        evidence=evidence,
        recommendation=recommendation,
    )


def _build_summary(urls: list[str], unique_domains: list[str], findings: list[Finding]) -> str:
    if not urls:
        return "No URLs were extracted from the message body."

    if not findings:
        return (
            f"URL analysis reviewed {len(urls)} URL(s) across {len(unique_domains)} domain(s) "
            "without detecting common phishing indicators."
        )

    high_count = sum(1 for finding in findings if finding.severity == FindingSeverity.HIGH)
    medium_count = sum(1 for finding in findings if finding.severity == FindingSeverity.MEDIUM)
    return (
        f"URL analysis reviewed {len(urls)} URL(s) across {len(unique_domains)} domain(s) and "
        f"detected {len(findings)} issue(s): {high_count} high and {medium_count} medium severity."
    )
