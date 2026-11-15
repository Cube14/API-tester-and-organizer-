
from src.reporter.json_reporter import JSONReporter

sample_findings = [
    {
        "status": "potential_bola",
        "severity": "High",
        "endpoint": "/workshop/api/mechanic/mechanic_report",
        "method": "GET",
        "authenticated_account": "account_a",
        "object_id": 7,
        "status_code": 200,
        "expected_owner": "account_a",
        "actual_owner": "account_b",
        "reason": "Object belongs to a different account."
    }
]

reporter = JSONReporter()

report_path = reporter.generate_report(
    findings=sample_findings,
    tests_performed=2
)

print("Report generated successfully!")
print("Location:", report_path)
