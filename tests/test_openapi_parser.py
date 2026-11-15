
from pathlib import Path

from src.parser.openapi_parser import OpenAPIParser


def test_endpoint_discovery():
    spec_path = (
        Path(__file__).resolve().parents[1]
        / "config"
        / "sample_api.yaml"
    )

    parser = OpenAPIParser(spec_path)
    endpoints = parser.extract_endpoints()

    assert len(endpoints) == 6
    
    paths = [endpoint["path"] for endpoint in endpoints]

    assert "/api/users/{user_id}" in paths
    assert "/api/profile" in paths
    assert "/api/health" in paths


def test_security_requirements():
    spec_path = (
        Path(__file__).resolve().parents[1]
        / "config"
        / "sample_api.yaml"
    )

    parser = OpenAPIParser(spec_path)
    endpoints = parser.extract_endpoints()

    protected = [
        endpoint for endpoint in endpoints
        if endpoint["path"] == "/api/profile"
    ]

    public = [
        endpoint for endpoint in endpoints
        if endpoint["path"] == "/api/health"
    ]

    assert protected[0]["auth_required"] is True
    assert public[0]["auth_required"] is False


def test_path_parameter_extraction():
    spec_path = (
        Path(__file__).resolve().parents[1]
        / "config"
        / "sample_api.yaml"
    )

    parser = OpenAPIParser(spec_path)
    endpoints = parser.extract_endpoints()

    user_endpoint = next(
        endpoint for endpoint in endpoints
        if endpoint["path"] == "/api/users/{user_id}"
    )

    assert user_endpoint["parameters"][0]["name"] == "user_id"
    assert user_endpoint["parameters"][0]["in"] == "path"


def test_operation_parameter_overrides_path_parameter():
    path_parameters = [
        {
            "name": "user_id",
            "in": "path",
            "schema": {"type": "string"}
        }
    ]

    operation_parameters = [
        {
            "name": "user_id",
            "in": "path",
            "schema": {"type": "integer"}
        }
    ]

    result = OpenAPIParser.merge_parameters(
        path_parameters,
        operation_parameters
    )

    assert len(result) == 1
    assert result[0]["schema"]["type"] == "integer"


def test_identify_object_parameters():
    endpoint = {
        "parameters": [
            {
                "name": "user_id",
                "in": "path",
                "required": True,
                "schema": {"type": "integer"}
            },
            {
                "name": "page",
                "in": "query",
                "schema": {"type": "integer"}
            },
            {
                "name": "report_id",
                "in": "query",
                "schema": {"type": "integer"}
            }
        ]
    }

    result = OpenAPIParser.identify_object_parameters(endpoint)

    names = [item["name"] for item in result]

    assert names == ["user_id", "report_id"]


def test_ignore_non_object_parameters():
    endpoint = {
        "parameters": [
            {"name": "page", "in": "query"},
            {"name": "limit", "in": "query"},
            {"name": "Authorization", "in": "header"}
        ]
    }

    result = OpenAPIParser.identify_object_parameters(endpoint)

    assert result == []


def test_detect_camel_case_identifiers():
    endpoint = {
        "parameters": [
            {"name": "invoiceId", "in": "path"},
            {"name": "paymentId", "in": "query"},
            {"name": "bookingId", "in": "path"}
        ]
    }

    result = OpenAPIParser.identify_object_parameters(endpoint)

    names = [item["name"] for item in result]

    assert names == ["invoiceId", "paymentId", "bookingId"]


def test_detect_snake_case_identifiers():
    endpoint = {
        "parameters": [
            {"name": "transaction_id", "in": "path"},
            {"name": "subscription_id", "in": "query"},
            {"name": "resource_id", "in": "path"}
        ]
    }

    result = OpenAPIParser.identify_object_parameters(endpoint)

    names = [item["name"] for item in result]

    assert names == [
        "transaction_id",
        "subscription_id",
        "resource_id"
    ]


def test_ignore_pagination_and_filter_parameters():
    endpoint = {
        "parameters": [
            {"name": "page", "in": "query"},
            {"name": "limit", "in": "query"},
            {"name": "offset", "in": "query"},
            {"name": "sort", "in": "query"},
            {"name": "search", "in": "query"},
            {"name": "filter", "in": "query"}
        ]
    }

    result = OpenAPIParser.identify_object_parameters(endpoint)

    assert result == []


def test_ignore_identifier_names_in_headers():
    endpoint = {
        "parameters": [
            {"name": "user_id", "in": "header"},
            {"name": "account_id", "in": "cookie"}
        ]
    }

    result = OpenAPIParser.identify_object_parameters(endpoint)

    assert result == []

def test_resolve_referenced_parameter():
    spec_path = (
        Path(__file__).resolve().parents[1]
        / "config"
        / "sample_api.yaml"
    )

    parser = OpenAPIParser(spec_path)
    endpoints = parser.extract_endpoints()

    user_endpoint = next(
        endpoint for endpoint in endpoints
        if endpoint["path"] == "/api/users/{user_id}"
    )

    parameters = user_endpoint["parameters"]

    assert len(parameters) == 1
    assert parameters[0]["name"] == "user_id"
    assert parameters[0]["in"] == "path"
    assert parameters[0]["required"] is True
    assert parameters[0]["schema"]["type"] == "integer"

def test_resolve_nested_local_references():
    parser = OpenAPIParser("config/sample_api.yaml")
    parser.load_specification()

    parser.specification["components"]["parameters"]["UserId"] = {
        "$ref": "#/components/parameters/BaseUserId"
    }

    parser.specification["components"]["parameters"]["BaseUserId"] = {
        "name": "user_id",
        "in": "path",
        "required": True,
        "schema": {"type": "integer"}
    }

    result = parser.resolve_local_reference(
        "#/components/parameters/UserId"
    )

    assert result["name"] == "user_id"
    assert result["in"] == "path"
    assert result["schema"]["type"] == "integer"


def test_reject_circular_local_references():
    parser = OpenAPIParser("config/sample_api.yaml")
    parser.load_specification()

    parser.specification["components"]["parameters"]["UserId"] = {
        "$ref": "#/components/parameters/BaseUserId"
    }

    parser.specification["components"]["parameters"]["BaseUserId"] = {
        "$ref": "#/components/parameters/UserId"
    }

    import pytest

    with pytest.raises(ValueError, match="Circular reference"):
        parser.resolve_local_reference(
            "#/components/parameters/UserId"
        )

def test_reject_missing_local_reference():
    import pytest

    parser = OpenAPIParser("config/sample_api.yaml")
    parser.load_specification()

    with pytest.raises(ValueError, match="could not be resolved"):
        parser.resolve_local_reference(
            "#/components/parameters/UnknownParameter"
        )


def test_reject_external_reference():
    import pytest

    parser = OpenAPIParser("config/sample_api.yaml")
    parser.load_specification()

    with pytest.raises(ValueError, match="Unsupported or invalid"):
        parser.resolve_local_reference(
            "https://example.com/openapi.yaml#/parameters/UserId"
        )

def test_identify_object_endpoints_without_declared_security():
    endpoints = [
        {
            "path": "/api/orders/{order_id}",
            "method": "GET",
            "auth_required": False,
            "parameters": [
                {"name": "order_id", "in": "path"}
            ]
        },
        {
            "path": "/api/users/{user_id}",
            "method": "GET",
            "auth_required": True,
            "parameters": [
                {"name": "user_id", "in": "path"}
            ]
        }
    ]

    result = OpenAPIParser.identify_endpoints_without_declared_security(
        endpoints
    )

    assert len(result) == 1
    assert result[0]["path"] == "/api/orders/{order_id}"


def test_ignore_public_endpoints_without_object_identifiers():
    endpoints = [
        {
            "path": "/api/health",
            "method": "GET",
            "auth_required": False,
            "parameters": []
        }
    ]

    result = OpenAPIParser.identify_endpoints_without_declared_security(
        endpoints
    )

    assert result == []
