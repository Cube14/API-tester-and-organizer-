
import json
import re
import copy
from pathlib import Path
from urllib.parse import unquote

import yaml
from openapi_spec_validator import validate


HTTP_METHODS = {
    "get", "post", "put", "patch",
    "delete", "options", "head", "trace"
}


class OpenAPIParser:
    """Loads, validates and extracts operations from an OpenAPI document."""

    def __init__(self, specification_path):
        self.specification_path = Path(specification_path)
        self.specification = None

    def load_specification(self):
        """Load and validate an OpenAPI 3.x specification."""

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
            raise ValueError(
                "This parser currently supports OpenAPI 3.x."
            )

        validate(self.specification)

        return self.specification

    def resolve_local_reference(self, reference, visited=None):
        """
        Resolve chained local JSON Pointer references.

        External references are not fetched.
        Circular references are detected and rejected.
        """

        if (
            not isinstance(reference, str)
            or not reference.startswith("#/")
        ):
            raise ValueError(
                f"Unsupported or invalid reference: {reference}"
            )

        if self.specification is None:
            self.load_specification()

        if visited is None:
            visited = set()

        if reference in visited:
            raise ValueError(
                f"Circular reference detected: {reference}"
            )

        visited = visited.copy()
        visited.add(reference)

        pointer = unquote(reference[2:])
        current = self.specification

        for token in pointer.split("/"):
            token = token.replace("~1", "/").replace("~0", "~")

            if isinstance(current, dict) and token in current:
                current = current[token]
            elif isinstance(current, list) and token.isdigit():
                index = int(token)

                if index >= len(current):
                    raise ValueError(
                        f"Reference could not be resolved: {reference}"
                    )

                current = current[index]
            else:
                raise ValueError(
                    f"Reference could not be resolved: {reference}"
                )

        if isinstance(current, dict) and "$ref" in current:
            return self.resolve_local_reference(
                current["$ref"],
                visited
            )

        return copy.deepcopy(current)

    def resolve_parameters(self, parameters):
        """Resolve local references in a list of OpenAPI parameters."""

        resolved_parameters = []

        for parameter in parameters:

            if not isinstance(parameter, dict):
                raise ValueError("Invalid parameter definition.")

            if "$ref" in parameter:
                resolved = self.resolve_local_reference(
                    parameter["$ref"]
                )

                resolved_parameters.append(resolved)

            else:
                resolved_parameters.append(
                    copy.deepcopy(parameter)
                )

        return resolved_parameters

    def extract_endpoints(self):
        """Extract API operations and their metadata."""

        if self.specification is None:
            self.load_specification()

        endpoints = []

        global_security = self.specification.get("security", [])

        for path, path_item in self.specification.get("paths", {}).items():

            if not isinstance(path_item, dict):
                continue

            path_parameters = self.resolve_parameters(
                path_item.get("parameters", [])
            )

            for method, operation in path_item.items():

                if method.lower() not in HTTP_METHODS:
                    continue

                if not isinstance(operation, dict):
                    continue

                operation_parameters = self.resolve_parameters(
                    operation.get("parameters", [])
                )

                # Operation-level parameters extend path-level parameters.
                parameters = self.merge_parameters(
                    path_parameters,
                    operation_parameters
                )

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

    @staticmethod
    def merge_parameters(path_parameters, operation_parameters):
        """
        Merge path-level and operation-level parameters.

        Operation-level parameters override path-level parameters
        with the same name and location.
        """

        merged = {}

        for parameter in path_parameters:
            key = (parameter.get("in"), parameter.get("name"))
            merged[key] = parameter

        for parameter in operation_parameters:
            key = (parameter.get("in"), parameter.get("name"))
            merged[key] = parameter

        return list(merged.values())

    @staticmethod
    def identify_object_parameters(endpoint):
        """
        Identify parameters that may represent object identifiers.

        Supports snake_case and camelCase naming conventions.
        This is heuristic discovery, not vulnerability detection.
        """

        candidates = []

        for parameter in endpoint.get("parameters", []):

            name = parameter.get("name", "")
            location = parameter.get("in")

            if location not in {"path", "query"}:
                continue

            if not isinstance(name, str) or not name:
                continue

            # Convert camelCase into snake_case.
            normalized_name = re.sub(
                r"([a-z0-9])([A-Z])",
                r"\1_\2",
                name
            ).lower()

            # Match "id" or names ending in "_id".
            if (
                normalized_name == "id"
                or normalized_name.endswith("_id")
            ):
                candidates.append({
                    "name": name,
                    "location": location,
                    "required": parameter.get("required", False),
                    "schema": parameter.get("schema", {})
                })

        return candidates

    @staticmethod
    def identify_endpoints_without_declared_security(endpoints):
        """
        Identify endpoints that accept object identifiers
        but have no declared authentication requirement.

        This is a security observation, not proof of a vulnerability.
        """

        findings = []

        for endpoint in endpoints:

            # Skip endpoints that declare authentication.
            if endpoint.get("auth_required", False):
                continue

            # Identify possible object ID parameters.
            object_ids = OpenAPIParser.identify_object_parameters(
                endpoint
            )

            # Only report endpoints with object ID candidates.
            if object_ids:
                findings.append({
                    "path": endpoint.get("path"),
                    "method": endpoint.get("method"),
                    "object_id_candidates": object_ids,
                    "status": "security_review_recommended",
                    "reason": (
                        "Endpoint accepts object identifiers but "
                        "has no authentication security declared "
                        "in the OpenAPI specification."
                    )
                })

        return findings

    def display_endpoints(self):
        """Display discovered endpoints and object identifier candidates."""

        endpoints = self.extract_endpoints()

        print("\n========== API ENDPOINT INVENTORY ==========\n")

        for index, endpoint in enumerate(endpoints, start=1):

            auth_status = (
                "AUTH REQUIRED"
                if endpoint["auth_required"]
                else "NO SECURITY DECLARED"
            )

            print(
                f"[{index}] {endpoint['method']} {endpoint['path']}"
            )
            print(f"    Summary: {endpoint['summary']}")
            print(f"    Authentication: {auth_status}")
            print(f"    Parameters: {len(endpoint['parameters'])}")

            object_ids = self.identify_object_parameters(endpoint)

            if object_ids:
                print("    Object ID Candidates:")

                for candidate in object_ids:
                    print(
                        f"        {candidate['name']} "
                        f"({candidate['location']})"
                    )
            else:
                print("    Object ID Candidates: None")

            print()

        print(f"Total endpoints discovered: {len(endpoints)}")

        security_findings = (
            self.identify_endpoints_without_declared_security(
                endpoints
            )
        )

        print("\n========== SECURITY OBSERVATIONS ==========\n")

        if security_findings:
            for finding in security_findings:
                print(
                    f"[REVIEW] {finding['method']} "
                    f"{finding['path']}"
                )
                print("    Status:", finding["status"])
                print("    Reason:", finding["reason"])
                print()
        else:
            print("No endpoints flagged for security review.\n")

        print(
            "Total security observations:",
            len(security_findings)
        )

        return endpoints
