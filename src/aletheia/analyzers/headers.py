"""Header analyzer for SPF, DKIM, DMARC and sender consistency checks."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from aletheia.models import EmailMetadata, Finding, FindingSeverity

from .base import BaseAnalyzer

AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=([a-z_]+)", re.IGNORECASE)


class HeaderAnalysis(BaseModel):
    """Structured result for header-focused checks."""

    model_config = ConfigDict(validate_assignment=True)

    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None
    received_hops: int = Field(ge=0)
    findings: list[Finding] = Field(default_factory=list)
    summary: str = Field(min_length=1)


class HeaderAnalyzer(BaseAnalyzer):
    """Analyze email headers and produce findings with recommendations."""

    def analyze(self, metadata: EmailMetadata) -> HeaderAnalysis:
        auth = _parse_authentication_results(metadata.authentication_results)
        findings: list[Finding] = []

        spf_result = auth.get("spf")
        dkim_result = auth.get("dkim")
        dmarc_result = auth.get("dmarc")

        if metadata.authentication_results is None:
            findings.append(
                _finding(
                    title="Authentication-Results header missing",
                    severity=FindingSeverity.MEDIUM,
                    explanation="The message does not include Authentication-Results evidence.",
                    evidence="Authentication-Results: <missing>",
                    recommendation=(
                        "Treat sender authentication with caution and corroborate "
                        "with other signals."
                    ),
                )
            )

        findings.extend(_auth_findings("SPF", spf_result, high_on_fail=False))
        findings.extend(_auth_findings("DKIM", dkim_result, high_on_fail=False))
        findings.extend(_auth_findings("DMARC", dmarc_result, high_on_fail=True))

        from_domain = _extract_domain(metadata.from_address)
        reply_domain = _extract_domain(metadata.reply_to)
        return_path_domain = _extract_domain(metadata.return_path)

        if reply_domain and from_domain != reply_domain:
            findings.append(
                _finding(
                    title="Reply-To domain differs from From domain",
                    severity=FindingSeverity.HIGH,
                    explanation=(
                        "A mismatch between visible sender and reply destination "
                        "can indicate spoofing."
                    ),
                    evidence=f"From: {from_domain}; Reply-To: {reply_domain}",
                    recommendation="Verify sender legitimacy before replying or opening links.",
                )
            )

        if return_path_domain and from_domain != return_path_domain:
            findings.append(
                _finding(
                    title="Return-Path domain differs from From domain",
                    severity=FindingSeverity.MEDIUM,
                    explanation=(
                        "Different envelope sender domains can be legitimate but "
                        "are often abused in phishing."
                    ),
                    evidence=f"From: {from_domain}; Return-Path: {return_path_domain}",
                    recommendation=(
                        "Correlate sender domains with expected infrastructure "
                        "before trusting."
                    ),
                )
            )

        if not metadata.received_headers:
            findings.append(
                _finding(
                    title="Received chain missing",
                    severity=FindingSeverity.MEDIUM,
                    explanation="No Received headers were found, limiting transport traceability.",
                    evidence="Received: <none>",
                    recommendation=(
                        "Treat provenance as uncertain and prioritize additional "
                        "verification."
                    ),
                )
            )

        summary = _build_summary(
            findings,
            len(metadata.received_headers),
            spf_result,
            dkim_result,
            dmarc_result,
        )
        return HeaderAnalysis(
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            received_hops=len(metadata.received_headers),
            findings=findings,
            summary=summary,
        )


def _parse_authentication_results(header_value: str | None) -> dict[str, str]:
    if not header_value:
        return {}

    parsed: dict[str, str] = {}
    for protocol, result in AUTH_PATTERN.findall(header_value):
        parsed[protocol.lower()] = result.lower()
    return parsed


def _auth_findings(protocol: str, result: str | None, *, high_on_fail: bool) -> list[Finding]:
    if result is None:
        return [
            _finding(
                title=f"{protocol} result missing",
                severity=FindingSeverity.MEDIUM,
                explanation=(
                    f"{protocol} outcome could not be determined from "
                    "Authentication-Results."
                ),
                evidence=f"{protocol}=<missing>",
                recommendation=(
                    "Treat this message with caution until sender identity is "
                    "corroborated."
                ),
            )
        ]

    if result == "pass":
        return []

    severity = (
        FindingSeverity.HIGH
        if high_on_fail and result in {"fail", "softfail"}
        else FindingSeverity.MEDIUM
    )
    return [
        _finding(
            title=f"{protocol} check not passed",
            severity=severity,
            explanation=f"{protocol} did not pass, reducing confidence in sender authenticity.",
            evidence=f"{protocol}={result}",
            recommendation=(
                "Validate sender identity through an independent channel before "
                "interacting."
            ),
        )
    ]


def _extract_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", maxsplit=1)[1].lower()


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


def _build_summary(
    findings: list[Finding],
    received_hops: int,
    spf_result: str | None,
    dkim_result: str | None,
    dmarc_result: str | None,
) -> str:
    if not findings:
        return (
            "Header checks show no immediate inconsistencies. "
            f"SPF={spf_result or 'n/a'}, DKIM={dkim_result or 'n/a'}, "
            f"DMARC={dmarc_result or 'n/a'}, "
            f"Received hops={received_hops}."
        )

    high_count = sum(1 for finding in findings if finding.severity == FindingSeverity.HIGH)
    medium_count = sum(1 for finding in findings if finding.severity == FindingSeverity.MEDIUM)
    return (
        f"Header analysis detected {len(findings)} issue(s): "
        f"{high_count} high and {medium_count} medium severity. "
        f"Received hops={received_hops}."
    )
