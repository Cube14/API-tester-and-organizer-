
import json
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


class JSONReporter:
    """Generate structured and sanitized JSON reports for API Sentinel."""

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sanitize_endpoint(endpoint):
        """Redact query parameter values while preserving parameter names."""
        if not endpoint or not isinstance(endpoint, str):
            return endpoint

        try:
            parsed = urlsplit(endpoint)

            if not parsed.query:
                return endpoint

            redacted_query = urlencode([
                (key, "[REDACTED]")
                for key, _ in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                )
            ])

            return urlunsplit((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                redacted_query,
                parsed.fragment,
            ))

        except (TypeError, ValueError):
            return "[ENDPOINT REDACTED]"

    @staticmethod
    def _sanitize_evidence(evidence):
        """Export only approved evidence metadata."""
        if not isinstance(evidence, dict):
            return {}

        allowed_fields = {
            "http_status",
            "baseline_http_status",
            "owner_field_found",
            "ownership_mismatch",
            "ownership_baseline_verified",
            "owner_field",
            "response_type",
            "content_type",
        }

        return {
            key: value
            for key, value in evidence.items()
            if key in allowed_fields
        }

    @staticmethod
    def _build_summary(findings, tests_performed):
        """Calculate accurate finding counts from result statuses."""
        statuses = [
            finding.get("status")
            for finding in findings
        ]

        confirmed = statuses.count("confirmed_bola")
        potential = statuses.count("potential_bola")
        inconclusive = statuses.count("inconclusive")
        not_confirmed = statuses.count("not_confirmed")

        return {
            "tests_performed": tests_performed,
            "results_recorded": len(findings),
            "confirmed_bola_findings": confirmed,
            "potential_bola_findings": potential,
            "inconclusive_tests": inconclusive,
            "not_confirmed_tests": not_confirmed,
            "total_bola_findings": confirmed + potential,
            "confirmed_vulnerabilities": confirmed,
        }

    def generate_report(self, findings, tests_performed):
        """Generate and save a sanitized JSON scan report."""

        timestamp = datetime.now(timezone.utc)
        findings = findings or []

        safe_findings = []

        for finding in findings:
            evidence = finding.get("evidence", {})

            status = finding.get("status")
            confirmed = status == "confirmed_bola"

            safe_findings.append({
                "status": status,
                "severity": finding.get("severity"),
                "finding_type": "BOLA" if confirmed else None,
                "vulnerable": confirmed,
                "endpoint": self._sanitize_endpoint(
                    finding.get("endpoint")
                ),
                "method": finding.get("method"),
                "authenticated_account": finding.get(
                    "authenticated_account"
                ),
                "object_id": finding.get("object_id"),
                "status_code": finding.get("status_code"),
                "ownership_mismatch": (
                    evidence.get("ownership_mismatch", False)
                    if isinstance(evidence, dict)
                    else False
                ),
                "ownership_baseline_verified": (
                    evidence.get(
                        "ownership_baseline_verified", False
                    )
                    if isinstance(evidence, dict)
                    else False
                ),
                "reason": finding.get("reason"),
                "evidence": self._sanitize_evidence(evidence),
                "recommendation": finding.get("recommendation"),
                "explanation": finding.get("explanation"),
            })

        report = {
            "tool": "API Sentinel",
            "version": "1.0",
            "report_type": "BOLA Security Scan",
            "scan_timestamp": timestamp.isoformat(),
            "summary": self._build_summary(
                safe_findings,
                tests_performed,
            ),
            "findings": safe_findings,
        }

        filename = (
            "api_sentinel_"
            + timestamp.strftime("%Y%m%d_%H%M%S_%f")
            + ".json"
        )

        report_path = self.output_dir / filename

        with report_path.open("w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False,
                default=str,
            )

        return report_path
