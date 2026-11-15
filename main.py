
import argparse
from src.engine.test_planner import TestPlanner

from src.parser.openapi_parser import OpenAPIParser
from src.engine.scan_runner import run_crapi_scan


def show_endpoints():
    """Discover and display API endpoints."""

    parser = OpenAPIParser("config/sample_api.yaml")
    parser.display_endpoints()

def show_test_plan():
    """Generate and display the BOLA test plan."""

    import json

    parser = OpenAPIParser("config/sample_api.yaml")
    planner = TestPlanner(parser)

    test_plan = planner.generate_test_plan()

    print("\n========== API SENTINEL TEST PLAN ==========\n")

    if not test_plan:
        print("No suitable endpoints found for BOLA testing.")
        return

    for index, test in enumerate(test_plan, start=1):
        print(f"[{index}] {test['method']} {test['endpoint']}")
        print(f"    Operation: {test['operation_id']}")
        print(f"    Test Type: {test['test_type']}")
        print(f"    Execution Mode: {test['execution_mode']}")
        print(f"    Status: {test['status']}")

        print("    Test Steps:")

        for step_number, step in enumerate(test["steps"], start=1):
            print(f"        {step_number}. {step}")

        print()

    print("Total planned tests:", len(test_plan))
    print("\nNo HTTP requests were executed.")


def main():
    cli = argparse.ArgumentParser(
        prog="API Sentinel",
        description="API Security Testing and BOLA Detection Tool"
    )

    subcommands = cli.add_subparsers(
        dest="command",
        required=True
    )

    subcommands.add_parser(
        "endpoints",
        help="Discover and display API endpoints"
    )

    subcommands.add_parser(
        "scan",
        help="Run bidirectional BOLA tests against crAPI"
    )
    subcommands.add_parser(
    "plan",
    help="Generate a BOLA test plan from the OpenAPI specification"
    )
    args = cli.parse_args()

    if args.command == "endpoints":
        show_endpoints()

    elif args.command == "scan":
        run_crapi_scan()
    elif args.command == "plan":
     show_test_plan()

if __name__ == "__main__":
    main()
