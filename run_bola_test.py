
import os
from dotenv import load_dotenv

from src.auth.auth_manager import AuthManager
from src.engine.bola_detector import BOLADetector
from src.reporter.json_reporter import JSONReporter

load_dotenv()

base_url = os.getenv("CRAPI_BASE_URL")

accounts = {
    "account_a": {
        "token": os.getenv("CRAPI_ACCOUNT_A_TOKEN"),
        "email": os.getenv("CRAPI_ACCOUNT_A_EMAIL"),
        "target_report": 7
    },
    "account_b": {
        "token": os.getenv("CRAPI_ACCOUNT_B_TOKEN"),
        "email": os.getenv("CRAPI_ACCOUNT_B_EMAIL"),
        "target_report": 6
    }
}

auth_manager = AuthManager(timeout=10)

try:
    # Register both accounts.
    for account_name, details in accounts.items():
        auth_manager.register_account(
            account_name,
            details["token"]
        )

    detector = BOLADetector(auth_manager)

    def run_test(requester, target_report):
        """Test whether an account can access another account's report."""

        expected_owner = accounts[requester]["email"]

        target_url = (
            f"{base_url}/workshop/api/mechanic/"
            f"mechanic_report?report_id={target_report}"
        )

        return detector.test_cross_account_access(
            attacker_account=requester,
            target_url=target_url,
            expected_owner=expected_owner,
            owner_path="vehicle.owner.email",
            object_id=target_report
        )

    # Test 1: Account A requests Account B's report.
    result_a = run_test("account_a", 7)

    # Test 2: Account B requests Account A's report.
    result_b = run_test("account_b", 6)

    # Display results without exposing personal information.
    for account_name, result in [
        ("Account A -> Report 7", result_a),
        ("Account B -> Report 6", result_b)
    ]:
        print(f"\nTest: {account_name}")
        print("HTTP Status:", result.get("status_code"))
        print("Result:", result.get("status"))
        print("Vulnerable:", result.get("vulnerable"))
        print("Reason:", result.get("reason"))

    print("\n========== SCAN SUMMARY ==========")
    print("Tests performed: 2")
    print("Potential BOLA findings:", len(detector.results))
    print("==================================")
    
finally:
    auth_manager.close()
# Generate a JSON security report.
reporter = JSONReporter()

report_path = reporter.generate_report(
    findings=detector.results,
    tests_performed=2
)

print("\n========== REPORT ==========")
print("Report saved:", report_path)
print("============================")