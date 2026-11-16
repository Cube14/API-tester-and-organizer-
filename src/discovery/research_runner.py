
import json
import threading
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


def run_website_research():
    """Run passive authenticated website and API research."""

    console.print(
        Panel(
            "[bold]Authenticated website research[/bold]\n\n"
            "First-party APIs receive priority. External APIs are "
            "retained separately.\n\n"
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

    network_capture = None
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

        # Derive the target origin from the initial/current page.
        target_url = (
            initial_url
            if initial_url
            else page.url
        )

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
                "First-party and external API traffic will be "
                "classified separately.\n\n"
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
                        network_capture.set_target_url(current_url)
                        break

        page_discovery.capture_all(context)

        pages = page_discovery.get_results()
        inventory = network_capture.get_inventory()

        primary = inventory["primary"]
        external = inventory["external"]

        timestamp = datetime.now(timezone.utc)

        report = {
            "tool": "API Sentinel",
            "report_type": "passive_website_research",
            "scan_timestamp": timestamp.isoformat(),
            "browser_mode": mode,
            "target": {
                "url": sanitize_url(target_url)
                if target_url else None,
                "hostname": (
                    urlsplit(target_url).hostname
                    if target_url else None
                )
            },
            "summary": {
                "pages_discovered": len(pages),
                "primary_api_endpoints": len(primary),
                "external_api_endpoints": len(external),
                "total_api_endpoints": len(primary) + len(external),
                "active_security_tests_performed": 0
            },
            "primary_inventory": primary,
            "external_inventory": external,
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
                "query_values_redacted": True
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

        table = Table(
            title="RESEARCH SUMMARY",
            border_style="red",
            expand=True
        )

        table.add_column("Metric")
        table.add_column("Result", justify="right")

        table.add_row("Pages discovered", str(len(pages)))
        table.add_row("First-party / same-site APIs", str(len(primary)))
        table.add_row("External APIs", str(len(external)))
        table.add_row("Total API endpoints", str(len(primary) + len(external)))
        table.add_row("Active security tests", "0")

        console.print()
        console.print(table)

        console.print(
            Panel(
                "[bold green]Research report generated[/bold green]\n\n"
                f"{report_path}",
                title="REPORT",
                border_style="green"
            )
        )

        def display_inventory(title, records, border_style):
            if not records:
                console.print(
                    f"\n[yellow]No {title.lower()} discovered.[/yellow]"
                )
                return

            endpoint_table = Table(
                title=title,
                border_style=border_style,
                expand=True
            )

            endpoint_table.add_column("Method", width=8)
            endpoint_table.add_column("Endpoint")
            endpoint_table.add_column("Category", width=16)
            endpoint_table.add_column("Status", width=8)

            for endpoint in records[:20]:
                endpoint_table.add_row(
                    endpoint["method"],
                    endpoint["endpoint_template"],
                    endpoint["classification"],
                    str(endpoint["status"] or "—")
                )

            console.print(endpoint_table)

            if len(records) > 20:
                console.print(
                    f"[dim]Showing 20 of {len(records)}. "
                    "All records are included in the JSON report.[/dim]"
                )

        display_inventory(
            "PRIMARY API INVENTORY",
            primary,
            "green"
        )

        display_inventory(
            "EXTERNAL API INVENTORY",
            external,
            "cyan"
        )

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
