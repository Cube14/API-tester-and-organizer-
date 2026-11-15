
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

    assert len(endpoints) == 4

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
