
import argparse

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from src.engine.test_planner import TestPlanner
from src.parser.openapi_parser import OpenAPIParser
from src.engine.scan_runner import run_crapi_scan
from src.discovery.research_runner import run_website_research


console = Console()

SPECIFICATION_PATH = "config/sample_api.yaml"


def show_banner():
    """Display the API Sentinel application banner."""

    banner = Text()
    banner.append("API ", style="bold white")
    banner.append("SENTINEL", style="bold red")
    banner.append(
        "\nINTELLIGENT API SECURITY SCANNER",
        style="dim white"
    )

    console.print()
    console.print(
        Panel(
            Align.center(banner),
            border_style="red",
            box=box.DOUBLE,
            padding=(1, 4)
        )
    )

    console.print(
        Align.center(
            "[dim]Discover. Analyze. Test. Protect.[/dim]"
        )
    )
    console.print()


def show_menu():
    """Display the interactive application menu."""

    table = Table(
        title="MAIN MENU",
        box=box.ROUNDED,
        border_style="red",
        show_header=False,
        expand=True
    )

    table.add_column("Option", style="bold red", width=10)
    table.add_column("Action", style="bold white")
    table.add_column("Description", style="dim")

    table.add_row(
        "[1]",
        "Discover API",
        "Analyze OpenAPI endpoints and object identifiers"
    )

    table.add_row(
        "[2]",
        "Generate Test Plan",
        "Identify potential authorization risks"
    )

    table.add_row(
        "[3]",
        "Run Security Scan",
        "Execute authorized two-account BOLA tests"
    )

    table.add_row(
        "[4]",
        "Website Research",
        "Browse authenticated websites and discover APIs"
    )

    table.add_row(
        "[5]",
        "Exit",
        "Close API Sentinel"
    )

    console.print(table)
    console.print()


def show_endpoints():
    """Discover and display API endpoints."""

    console.print(
        Panel(
            "Analyzing the OpenAPI specification...",
            title="API DISCOVERY",
            border_style="cyan"
        )
    )

    parser = OpenAPIParser(SPECIFICATION_PATH)
    parser.display_endpoints()


def show_test_plan():
    """Generate and display the BOLA test plan."""

    parser = OpenAPIParser(SPECIFICATION_PATH)
    planner = TestPlanner(parser)

    test_plan = planner.generate_test_plan()

    console.print(
        Panel(
            "Reviewing endpoints and identifying authorization test cases.",
            title="SECURITY TEST PLANNER",
            border_style="cyan"
        )
    )

    if not test_plan:
        console.print(
            "[yellow]No suitable endpoints found.[/yellow]"
        )
        return

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        expand=True
    )

    table.add_column("Endpoint", style="white")
    table.add_column("Method", style="cyan", width=8)
    table.add_column("Identifier", style="yellow")
    table.add_column("Execution", style="magenta")
    table.add_column("Status", style="green")

    for test in test_plan:
        identifiers = ", ".join(
            f"{item['name']} ({item['location']})"
            for item in test["object_id_parameters"]
        )

        status = test["status"]

        status_style = (
            "yellow"
            if status != "planned"
            else "green"
        )

        table.add_row(
            test["endpoint"],
            test["method"],
            identifiers,
            test["execution_mode"],
            f"[{status_style}]{status}[/{status_style}]"
        )

    console.print(table)

    console.print(
        f"\n[bold]Total planned tests:[/bold] {len(test_plan)}"
    )

    console.print(
        "[dim]Planning only. No HTTP requests were executed.[/dim]"
    )


def run_security_scan():
    """Run the authorized local crAPI demonstration."""

    console.print(
        Panel(
            "[bold]Two-account authorization testing[/bold]\n\n"
            "This scan uses the configured local crAPI lab and "
            "the two authorized test accounts.",
            title="SECURITY SCAN",
            border_style="red"
        )
    )

    confirmation = Prompt.ask(
        "Start the authorized local scan?",
        choices=["y", "n"],
        default="n"
    )

    if confirmation != "y":
        console.print("[yellow]Scan cancelled.[/yellow]")
        return

    console.print()
    run_crapi_scan()


def run_research():
    """Start authenticated passive website research."""

    console.print(
        Panel(
            "[bold]Website and API research[/bold]\n\n"
            "API Sentinel will observe browser activity, "
            "discover pages and identify API endpoints.\n\n"
            "It will not run active security tests in this mode.",
            title="WEBSITE RESEARCH",
            border_style="cyan"
        )
    )

    confirmation = Prompt.ask(
        "Start browser research?",
        choices=["y", "n"],
        default="n"
    )

    if confirmation != "y":
        console.print("[yellow]Research cancelled.[/yellow]")
        return

    run_website_research()


def run_interactive():
    """Run the interactive API Sentinel application."""

    while True:
        console.clear()
        show_banner()
        show_menu()

        choice = Prompt.ask(
            "Select an option",
            choices=["1", "2", "3", "4", "5"]
        )

        console.print()

        try:
            if choice == "1":
                show_endpoints()

            elif choice == "2":
                show_test_plan()

            elif choice == "3":
                run_security_scan()

            elif choice == "4":
                run_research()

            elif choice == "5":
                console.print(
                    Panel(
                        "[bold green]Thank you for using API Sentinel.[/bold green]",
                        border_style="red"
                    )
                )
                break

        except KeyboardInterrupt:
            console.print(
                "\n[yellow]Operation interrupted.[/yellow]"
            )

        except Exception as error:
            console.print(
                Panel(
                    f"[bold red]Operation failed[/bold red]\n\n{error}",
                    title="ERROR",
                    border_style="red"
                )
            )

        if choice != "5":
            console.print()
            Prompt.ask(
                "Press Enter to return to the main menu",
                default=""
            )


def main():
    """Application entry point."""

    cli = argparse.ArgumentParser(
        prog="API Sentinel",
        description="Intelligent API Security Scanner"
    )

    cli.add_argument(
        "command",
        nargs="?",
        choices=["endpoints", "scan", "plan", "research"],
        help="Optional command to execute directly"
    )

    args = cli.parse_args()

    if args.command is None:
        run_interactive()

    elif args.command == "endpoints":
        show_endpoints()

    elif args.command == "scan":
        run_crapi_scan()

    elif args.command == "plan":
        show_test_plan()

    elif args.command == "research":
        run_research()


if __name__ == "__main__":
    main()
