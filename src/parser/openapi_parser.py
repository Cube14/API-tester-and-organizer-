
import json
from pathlib import Path

import yaml
from openapi_spec_validator import validate


HTTP_METHODS = {
    "get", "post", "put", "patch", "delete", "options", "head", "trace"
}


class OpenAPIParser:
    """Loads, validates and extracts operations from an OpenAPI document."""

    def __init__(self, specification_path):
        self.specification_path = Path(specification_path)
        self.specification = None

    def load_specification(self):
        if not self.specification_path.is_file():
            raise FileNotFoundError(
                f"Specification not found: {self.specification_path}"
            )

        content = self.specification_path.read_text(encoding="utf-8")

        if self.specification_path.suffix.lower() == ".json":
            self.specification = json.loads(content)
        else:
            self.specification = yaml.safe_load(content)

        if not isinstance(self.specification, dict):
            raise ValueError("Invalid OpenAPI document.")

        version = self.specification.get("openapi", "")

        if not version.startswith("3."):
            raise ValueError("This parser currently supports OpenAPI 3.x.")

        validate(self.specification)

        return self.specification

    def extract_endpoints(self):
        if self.specification is None:
            self.load_specification()

        endpoints = []

        global_security = self.specification.get("security", [])

        for path, path_item in self.specification.get("paths", {}).items():

            if not isinstance(path_item, dict):
                continue

            path_parameters = path_item.get("parameters", [])

            for method, operation in path_item.items():

                if method.lower() not in HTTP_METHODS:
                    continue

                if not isinstance(operation, dict):
                    continue

                operation_parameters = operation.get("parameters", [])

                # Operation-level parameters extend path-level parameters.
                parameters = path_parameters + operation_parameters

                # Operation security overrides global security.
                security = operation.get("security", global_security)

                endpoint = {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary", ""),
                    "parameters": parameters,
                    "request_body": operation.get("requestBody"),
                    "security": security,
                    "auth_required": bool(security),
                    "tags": operation.get("tags", [])
                }

                endpoints.append(endpoint)

        return endpoints

    def display_endpoints(self):
        endpoints = self.extract_endpoints()

        print("\n========== API ENDPOINT INVENTORY ==========\n")

        for index, endpoint in enumerate(endpoints, start=1):
            auth_status = (
                "AUTH REQUIRED"
                if endpoint["auth_required"]
                else "NO SECURITY DECLARED"
            )

            print(f"[{index}] {endpoint['method']} {endpoint['path']}")
            print(f"    Summary: {endpoint['summary']}")
            print(f"    Authentication: {auth_status}")
            print(f"    Parameters: {len(endpoint['parameters'])}")
            print()

        print(f"Total endpoints discovered: {len(endpoints)}")

        return endpoints
