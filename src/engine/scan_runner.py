
import os
from dotenv import load_dotenv

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.auth.auth_manager import AuthManager
from src.engine.bola_detector import BOLADetector
from src.reporter.json_reporter import JSONReporter


console = Console()


def run_crapi_scan():
    """
    Run bidirectional, baseline-verified BOLA tests
    against the authorized local crAPI lab.
    """

    load_dotenv()

    base_url = os.getenv("CRAPI_BASE_URL")

    accounts = {
        "account_a": {
            "token": os.getenv("CRAPI_ACCOUNT_A_TOKEN"),
            "email": os.getenv("CRAPI_ACCOUNT_A_EMAIL")
        },
        "account_b": {
            "token": os.getenv("CRAPI_ACCOUNT_B_TOKEN"),
            "email": os.getenv("CRAPI_ACCOUNT_B_EMAIL")
        }
    }

    # Each target report is known to belong to the opposite account.
    test_cases = [
        {
            "attacker": "account_a",
            "owner": "account_b",
            "report_id": 7
        },
        {
            "attacker": "account_b",
            "owner": "account_a",
            "report_id": 6
        }
    ]

    if not base_url:
        raise ValueError("CRAPI_BASE_URL is missing from .env.")

    base_url = base_url.rstrip("/")

    for account_name, details in accounts.items():
        if not details["token"]:
            raise ValueError(
                f"Authentication token is missing for {account_name}."
            )

        if not details["email"]:
            raise ValueError(
                f"Account identity is missing for {account_name}."
            )

    auth_manager = AuthManager(timeout=10)

    scan_results = []
    tests_performed = 0

    try:
        # Register both authorized test accounts.
        for account_name, details in accounts.items():
            auth_manager.register_account(
                account_name,
                details["token"]
            )

        detector = BOLADetector(auth_manager)

        console.print(
            Panel(
                "[bold]Authorized local crAPI security assessment[/bold]\n\n"
                "Each test first verifies that the legitimate owner "
                "can retrieve the target report. A different account "
                "is then tested against the same report.\n\n"
                "[dim]Only the configured local lab is targeted.[/dim]",
                title="[bold red]API SENTINEL — BOLA SCAN[/bold red]",
                border_style="red"
            )
        )

        for test_case in test_cases:

            attacker = test_case["attacker"]
            owner = test_case["owner"]
            report_id = test_case["report_id"]

            target_url = (
                f"{base_url}/workshop/api/mechanic/"
                f"mechanic_report?report_id={report_id}"
            )

            console.print(
                f"\n[bold cyan]Testing Report {report_id}[/bold cyan]"
            )

            console.print(
                f"[dim]Legitimate owner: {owner}[/dim]"
            )

            console.print(
                f"[dim]Cross-account requester: {attacker}[/dim]"
            )

            result = detector.test_cross_account_access(
                attacker_account=attacker,
                target_url=target_url,
                expected_owner=accounts[attacker]["email"],
                owner_path="vehicle.owner.email",
                object_id=report_id,
                owner_account=owner,
                baseline_owner=accounts[owner]["email"]
            )

            tests_performed += 1
            scan_results.append(result)

            status = result.get("status", "unknown")
            http_status = result.get("status_code")

            if status == "confirmed_bola":
                status_style = "bold red"
            elif status == "potential_bola":
                status_style = "bold yellow"
            elif status == "inconclusive":
                status_style = "bold magenta"
            else:
                status_style = "green"

            console.print(
                f"Result: [{status_style}]{status}[/{status_style}]"
            )

            console.print(
                f"HTTP status: {http_status if http_status is not None else 'Unavailable'}"
            )

            console.print(
                "Baseline verified: "
                + (
                    "[green]Yes[/green]"
                    if result.get("evidence", {}).get(
                        "ownership_baseline_verified"
                    )
                    else "[yellow]No[/yellow]"
                )
            )

            console.print(
                f"Explanation: {result.get('explanation', result.get('reason', 'No explanation available.'))}"
            )

        # Build a clear scan summary.
        confirmed_count = sum(
            1 for result in scan_results
            if result.get("status") == "confirmed_bola"
        )

        potential_count = sum(
            1 for result in scan_results
            if result.get("status") == "potential_bola"
        )

        inconclusive_count = sum(
            1 for result in scan_results
            if result.get("status") == "inconclusive"
        )

        not_confirmed_count = sum(
            1 for result in scan_results
            if result.get("status") == "not_confirmed"
        )

        summary = Table(
            title="SCAN SUMMARY",
            box=box.ROUNDED,
            border_style="red",
            expand=True
        )

        summary.add_column("Metric", style="white")
        summary.add_column("Result", justify="right")

        summary.add_row("Test cases executed", str(tests_performed))
        summary.add_row(
            "Confirmed BOLA findings",
            f"[bold red]{confirmed_count}[/bold red]"
        )
        summary.add_row(
            "Potential BOLA findings",
            f"[bold yellow]{potential_count}[/bold yellow]"
        )
        summary.add_row(
            "Inconclusive tests",
            f"[magenta]{inconclusive_count}[/magenta]"
        )
        summary.add_row(
            "Not confirmed",
            f"[green]{not_confirmed_count}[/green]"
        )

        console.print()
        console.print(summary)

        # Generate the JSON report.
        reporter = JSONReporter()

        report_path = reporter.generate_report(
            findings=detector.results,
            tests_performed=tests_performed
        )

        console.print(
            Panel(
                f"[bold green]JSON report generated successfully[/bold green]\n\n"
                f"[white]{report_path}[/white]",
                title="REPORT",
                border_style="green"
            )
        )

        console.print(
            "\n[dim]Note: A potential finding is not a confirmed "
            "vulnerability. Confirmation requires a successful "
            "legitimate-owner baseline and matching ownership "
            "evidence from the cross-account request.[/dim]"
        )

    finally:
        auth_manager.close()
