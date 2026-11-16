
import json
import threading
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from src.browser.browser_manager import BrowserManager
from src.browser.network_capture import NetworkCapture, sanitize_url
from src.browser.page_discovery import PageDiscovery


console = Console()

BACKGROUND_CLASSIFICATIONS = {
    "analytics",
    "security_infrastructure",
    "telemetry",
    "media_delivery",
}


def classify_inventory(records):
    """Separate functional API endpoints from background traffic."""

    functional = []
    background = []

    for record in records:
        classification = record.get("classification", "other")

        if classification in BACKGROUND_CLASSIFICATIONS:
            background.append(record)
        else:
            functional.append(record)

    return functional, background


def get_origin(record):
    """Read the canonical origin field with compatibility fallback."""

    return record.get(
        "origin_category",
        record.get("origin", "unclassified")
    )


def count_classifications(records):
    counts = Counter(
        record.get("classification", "other")
        for record in records
    )

    return dict(sorted(counts.items()))


def count_status_codes(records):
    counts = Counter()

    for record in records:
        statuses = record.get("status_codes", [])

        for status in statuses:
            counts[str(status)] += 1

        if not statuses and record.get("status") is not None:
            counts[str(record["status"])] += 1

    return dict(sorted(counts.items()))


def count_failed_requests(records):
    return sum(
        record.get("failed_count", 0)
        for record in records
    )


def collect_identifier_findings(records):
    """Create endpoint-level findings for discovered path identifiers."""

    findings = []

    for record in records:
        identifiers = record.get("path_identifiers", [])

        for identifier in identifiers:
            findings.append({
                "method": record.get("method"),
                "domain": record.get("domain"),
                "origin": get_origin(record),
                "endpoint_template": record.get("endpoint_template"),
                "identifier_value": identifier.get("value"),
                "identifier_type": identifier.get("type"),
                "identifier_position": identifier.get("position"),
                "status": record.get("status"),
                "classification": record.get("classification"),
                "security_observation": (
                    "Direct object reference detected; "
                    "authorization requires verification."
                ),
                "potential_bola_candidate": True,
                "vulnerability_confirmed": False
            })

    return findings


def display_inventory(title, records, border_style):
    if not records:
        console.print(
            f"\n[yellow]No {title.lower()} discovered.[/yellow]"
        )
        return

    table = Table(
        title=title,
        border_style=border_style,
        expand=True
    )

    table.add_column("Method", width=8)
    table.add_column("Endpoint")
    table.add_column("Category", width=22)
    table.add_column("Origin", width=14)
    table.add_column("Status", width=10)

    for endpoint in records[:20]:
        table.add_row(
            endpoint.get("method", "—"),
            endpoint.get("endpoint_template", "—"),
            endpoint.get("classification", "other"),
            get_origin(endpoint),
            str(endpoint.get("status") or "—")
        )

    console.print(table)

    if len(records) > 20:
        console.print(
            f"[dim]Showing 20 of {len(records)}. "
            "All records are included in the JSON report.[/dim]"
        )


def display_identifier_findings(findings):
    if not findings:
        console.print(
            "\n[green]No dynamic path identifiers detected.[/green]"
        )
        return

    table = Table(
        title="OBJECT IDENTIFIER INTELLIGENCE",
        border_style="yellow",
        expand=True
    )

    table.add_column("Method", width=8)
    table.add_column("Endpoint template")
    table.add_column("Actual identifier")
    table.add_column("Type", width=22)
    table.add_column("Origin", width=13)

    for finding in findings[:30]:
        table.add_row(
            finding["method"] or "—",
            finding["endpoint_template"] or "—",
            finding["identifier_value"] or "—",
            finding["identifier_type"] or "unknown",
            finding["origin"]
        )

    console.print(table)

    console.print(
        Panel(
            "[bold yellow]Direct object references detected.[/bold yellow]\n\n"
            "These identifiers may be used to access individual objects. "
            "Their presence alone does not establish a vulnerability.\n\n"
            "Authorization must be verified using legitimate test accounts "
            "before reporting BOLA.",
            title="SECURITY OBSERVATION",
            border_style="yellow"
        )
    )

    if len(findings) > 30:
        console.print(
            f"[dim]Showing 30 of {len(findings)} identifier findings. "
            "All findings are included in the JSON report.[/dim]"
        )


def run_website_research():
    """Run passive authenticated website and API research."""

    console.print(
        Panel(
            "[bold]Authenticated website research[/bold]\n\n"
            "First-party APIs receive priority. External APIs are "
            "retained separately.\n"
            "Object identifiers are inspected for security relevance.\n\n"
            "[yellow]No active security tests will be performed.[/yellow]",
            title="[bold red]API SENTINEL — RESEARCH MODE[/bold red]",
            border_style="red"
        )
    )

    mode = Prompt.ask(
        "Browser connection",
        choices=["dedicated", "existing"],
        default="dedicated"
    )

    initial_url = Prompt.ask(
        "Initial website URL (blank uses current tab)",
        default=""
    ).strip()

    if initial_url and not initial_url.startswith(
        ("http://", "https://")
    ):
        console.print(
            "[red]Enter a complete HTTP or HTTPS URL.[/red]"
        )
        return

    manager = BrowserManager(mode=mode)
    page_discovery = PageDiscovery()

    try:
        console.print("\n[cyan]Connecting to browser...[/cyan]")

        context = manager.start()
        page = manager.get_active_page()

        if initial_url:
            console.print(
                "[cyan]Opening the requested website...[/cyan]"
            )

            page.goto(
                initial_url,
                wait_until="domcontentloaded",
                timeout=60000
            )

        elif mode == "dedicated":
            console.print(
                "[yellow]Navigate to your target website "
                "in the opened browser.[/yellow]"
            )

        target_url = initial_url or page.url

        if not target_url.startswith(("http://", "https://")):
            target_url = None

        network_capture = NetworkCapture(
            target_url=target_url
        )

        network_capture.attach_context(context)
        page_discovery.attach_context(context)
        page_discovery.capture_all(context)

        console.print(
            Panel(
                "[bold green]Browser connected successfully.[/bold green]\n\n"
                "Log in manually if required. Browse the target website "
                "and use its normal functionality.\n\n"
                "API endpoints, object identifiers and external traffic "
                "will be inventoried separately.\n\n"
                "[bold]Press Enter in this terminal when finished.[/bold]",
                title="BROWSER RESEARCH ACTIVE",
                border_style="green"
            )
        )

        finished = threading.Event()

        def wait_for_user():
            try:
                input()
            finally:
                finished.set()

        input_thread = threading.Thread(
            target=wait_for_user,
            daemon=True
        )
        input_thread.start()

        while not finished.is_set():
            page.wait_for_timeout(500)

            if network_capture.target_host is None:
                for current_page in context.pages:
                    if current_page.is_closed():
                        continue

                    current_url = current_page.url

                    if current_url.startswith(("http://", "https://")):
                        target_url = current_url
                        network_capture.set_target_url(current_url)
                        break

        page_discovery.capture_all(context)

        pages = page_discovery.get_results()
        inventory = network_capture.get_inventory()

        primary_all = inventory.get("primary", [])
        external_all = inventory.get("external", [])

        primary_functional, primary_background = classify_inventory(
            primary_all
        )

        external_functional, external_background = classify_inventory(
            external_all
        )

        first_party = [
            record for record in primary_functional
            if get_origin(record) == "first_party"
        ]

        same_site = [
            record for record in primary_functional
            if get_origin(record) == "same_site"
        ]

        unclassified = [
            record for record in primary_functional
            if get_origin(record) not in {
                "first_party",
                "same_site"
            }
        ]

        third_party = external_functional

        background_traffic = (
            primary_background + external_background
        )

        all_functional = (
            first_party + same_site + unclassified + third_party
        )

        identifier_findings = collect_identifier_findings(
            all_functional
        )

        unique_identifier_values = {
            finding["identifier_value"]
            for finding in identifier_findings
        }

        identifier_endpoints = {
            (
                finding["method"],
                finding["domain"],
                finding["endpoint_template"]
            )
            for finding in identifier_findings
        }

        timestamp = datetime.now(timezone.utc)

        target_hostname = (
            urlsplit(target_url).hostname
            if target_url else None
        )

        all_records = all_functional + background_traffic

        report = {
            "tool": "API Sentinel",
            "report_type": "passive_website_research",
            "report_version": "3.0",
            "scan_timestamp": timestamp.isoformat(),
            "browser_mode": mode,

            "target": {
                "url": sanitize_url(target_url)
                if target_url else None,
                "hostname": target_hostname
            },

            "summary": {
                "pages_discovered": len(pages),
                "total_functional_api_endpoints": len(all_functional),
                "first_party_api_endpoints": len(first_party),
                "same_site_api_endpoints": len(same_site),
                "unclassified_api_endpoints": len(unclassified),
                "third_party_api_endpoints": len(third_party),
                "background_traffic_endpoints": len(background_traffic),

                "endpoints_with_object_identifiers": len(
                    identifier_endpoints
                ),
                "unique_object_identifiers_observed": len(
                    unique_identifier_values
                ),
                "object_identifier_observations": len(
                    identifier_findings
                ),
                "potential_bola_candidates": len(
                    identifier_endpoints
                ),
                "confirmed_vulnerabilities": 0,

                "active_security_tests_performed": 0
            },

            "classification_summary": {
                "functional_apis": count_classifications(
                    all_functional
                ),
                "background_traffic": count_classifications(
                    background_traffic
                )
            },

            "response_status_summary": count_status_codes(
                all_records
            ),

            "failed_requests_observed": count_failed_requests(
                all_records
            ),

            "first_party_inventory": first_party,
            "same_site_inventory": same_site,
            "unclassified_inventory": unclassified,
            "third_party_inventory": third_party,
            "background_traffic": background_traffic,

            "object_identifier_findings": identifier_findings,

            # Backward-compatible fields.
            "primary_inventory": primary_functional,
            "external_inventory": external_functional,

            "pages": pages,
            "resource_types_observed": (
                network_capture.get_resource_summary()
            ),

            "privacy": {
                "cookies_saved": False,
                "authorization_headers_saved": False,
                "request_bodies_saved": False,
                "response_bodies_saved": False,
                "form_values_saved": False,
                "query_values_redacted": True,
                "path_identifiers_saved": True,
                "path_identifier_values_visible": True
            }
        }

        output_dir = Path("reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = (
            "api_sentinel_research_"
            + timestamp.strftime("%Y%m%d_%H%M%S")
            + ".json"
        )

        report_path = output_dir / filename

        report_path.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8"
        )

        summary_table = Table(
            title="RESEARCH SUMMARY",
            border_style="red",
            expand=True
        )

        summary_table.add_column("Metric")
        summary_table.add_column("Result", justify="right")

        summary_rows = [
            ("Pages discovered", len(pages)),
            ("First-party APIs", len(first_party)),
            ("Same-site APIs", len(same_site)),
            ("Unclassified APIs", len(unclassified)),
            ("Third-party APIs", len(third_party)),
            ("Background traffic", len(background_traffic)),
            ("Functional API endpoints", len(all_functional)),
            (
                "Endpoints with object identifiers",
                len(identifier_endpoints)
            ),
            (
                "Unique object identifiers",
                len(unique_identifier_values)
            ),
            (
                "Potential BOLA candidates",
                len(identifier_endpoints)
            ),
            ("Confirmed vulnerabilities", 0),
            ("Active security tests", 0)
        ]

        for label, value in summary_rows:
            summary_table.add_row(label, str(value))

        console.print()
        console.print(summary_table)

        classification_table = Table(
            title="TRAFFIC CLASSIFICATION",
            border_style="cyan",
            expand=True
        )

        classification_table.add_column("Classification")
        classification_table.add_column("Count", justify="right")

        for classification, count in count_classifications(
            all_records
        ).items():
            classification_table.add_row(
                classification,
                str(count)
            )

        console.print(classification_table)

        console.print(
            Panel(
                "[bold green]Research report generated[/bold green]\n\n"
                f"{report_path}",
                title="REPORT",
                border_style="green"
            )
        )

        display_inventory(
            "FIRST-PARTY API INVENTORY",
            first_party,
            "green"
        )

        display_inventory(
            "SAME-SITE API INVENTORY",
            same_site,
            "blue"
        )

        display_inventory(
            "UNCLASSIFIED API INVENTORY",
            unclassified,
            "yellow"
        )

        display_inventory(
            "THIRD-PARTY API INVENTORY",
            third_party,
            "cyan"
        )

        display_inventory(
            "BACKGROUND TRAFFIC INVENTORY",
            background_traffic,
            "yellow"
        )

        display_identifier_findings(identifier_findings)

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Research interrupted by user.[/yellow]"
        )

    except Exception as error:
        console.print(
            Panel(
                f"[bold red]Research failed[/bold red]\n\n{error}",
                border_style="red"
            )
        )

    finally:
        manager.stop()
