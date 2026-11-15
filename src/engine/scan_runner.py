
import os
from dotenv import load_dotenv

from src.auth.auth_manager import AuthManager
from src.engine.bola_detector import BOLADetector
from src.reporter.json_reporter import JSONReporter


def run_crapi_scan():
    """Run bidirectional BOLA tests against the local crAPI lab."""

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

    if not base_url:
        raise ValueError("CRAPI_BASE_URL is missing.")

    for name, details in accounts.items():
        if not details["token"] or not details["email"]:
            raise ValueError(f"Missing credentials for {name}.")

    auth_manager = AuthManager(timeout=10)

    try:
        for account_name, details in accounts.items():
            auth_manager.register_account(
                account_name,
                details["token"]
            )

        detector = BOLADetector(auth_manager)

        for requester, details in accounts.items():
            target_report = details["target_report"]

            target_url = (
                f"{base_url}/workshop/api/mechanic/"
                f"mechanic_report?report_id={target_report}"
            )

            result = detector.test_cross_account_access(
                attacker_account=requester,
                target_url=target_url,
                expected_owner=details["email"],
                owner_path="vehicle.owner.email",
                object_id=target_report
            )

            print(f"\nTest: {requester} -> Report {target_report}")
            print("HTTP Status:", result.get("status_code"))
            print("Result:", result.get("status"))
            print("Vulnerable:", result.get("vulnerable"))
            print("Reason:", result.get("reason"))

        reporter = JSONReporter()

        report_path = reporter.generate_report(
            findings=detector.results,
            tests_performed=len(accounts)
        )

        print("\n========== SCAN SUMMARY ==========")
        print("Tests performed:", len(accounts))
        print("Potential BOLA findings:", len(detector.results))
        print("Report saved:", report_path)
        print("==================================")

    finally:
        auth_manager.close()
