
import json
from pathlib import Path
from datetime import datetime, timezone


class JSONReporter:
    """Generates JSON reports from API Sentinel findings."""

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    
    def generate_report(self, findings, tests_performed):
        """Save sanitized scan findings as a JSON report."""

        timestamp = datetime.now(timezone.utc)

        safe_findings = []

        for finding in findings:
            safe_findings.append({
                "status": finding.get("status"),
                "severity": finding.get("severity"),
                "endpoint": finding.get("endpoint"),
                "method": finding.get("method"),
                "authenticated_account": finding.get(
                    "authenticated_account"
                ),
                "object_id": finding.get("object_id"),
                "status_code": finding.get("status_code"),
                "ownership_mismatch": finding.get("vulnerable"),
                "reason": finding.get("reason")
            })

        report = {
            "tool": "API Sentinel",
            "scan_timestamp": timestamp.isoformat(),
            "summary": {
                "tests_performed": tests_performed,
                "findings_count": len(safe_findings),
                "potential_bola_findings": sum(
                    1 for finding in safe_findings
                    if finding.get("status") == "potential_bola"
                )
            },
            "findings": safe_findings
        }

        filename = (
            "api_sentinel_"
            + timestamp.strftime("%Y%m%d_%H%M%S")
            + ".json"
        )

        report_path = self.output_dir / filename

        with report_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        return report_path
