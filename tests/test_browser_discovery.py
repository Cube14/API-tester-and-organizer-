
from urllib.parse import urlsplit

from src.browser.network_capture import (
    sanitize_url,
    normalize_path,
    NetworkCapture
)


def test_sanitize_url_redacts_query_values():
    result = sanitize_url(
        "https://example.com/api/orders?id=123&token=secret"
    )

    assert result == (
        "https://example.com/api/orders?"
        "id=[REDACTED]&token=[REDACTED]"
    )

    assert "123" not in result
    assert "secret" not in result


def test_sanitize_url_removes_fragment():
    result = sanitize_url(
        "https://example.com/dashboard#private-section"
    )

    assert result == "https://example.com/dashboard"


def test_sanitize_url_removes_url_credentials():
    result = sanitize_url(
        "https://user:password@example.com/api/users"
    )

    assert result == "https://example.com/api/users"

    parsed = urlsplit(result)

    assert parsed.username is None
    assert parsed.password is None
    assert "password" not in result


def test_api_candidate_detects_fetch():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/data",
        "fetch",
        "application/json"
    ) == "rest_api"


def test_api_candidate_detects_xhr():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/data",
        "xhr",
        "application/json"
    ) == "rest_api"


def test_api_candidate_detects_api_path():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/api/users",
        "document"
    ) == "rest_api"


def test_api_candidate_detects_graphql():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/graphql",
        "fetch"
    ) == "graphql"


def test_api_candidate_detects_authentication():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/oauth/token",
        "fetch"
    ) == "authentication"


def test_static_resources_are_excluded():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/assets/logo.svg",
        "fetch",
        "image/svg+xml"
    ) == "static_resource"


def test_analytics_are_classified_separately():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://www.google-analytics.com/g/collect",
        "fetch",
        "application/json"
    ) == "analytics"


def test_security_infrastructure_is_classified():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://challenges.cloudflare.com/cdn-cgi/test",
        "fetch"
    ) == "security_infrastructure"


def test_first_party_origin():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_origin(
        "example.com"
    ) == "first_party"


def test_same_site_subdomain():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_origin(
        "api.example.com"
    ) == "same_site"


def test_third_party_origin():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_origin(
        "api.external.com"
    ) == "third_party"


def test_numeric_identifier_normalization():
    assert normalize_path(
        "/api/users/123"
    ) == "/api/users/{id}"


def test_uuid_normalization():
    assert normalize_path(
        "/api/orders/550e8400-e29b-41d4-a716-446655440000"
    ) == "/api/orders/{uuid}"


def test_static_image_is_not_an_api():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/image.png",
        "image",
        "image/png"
    ) == "static_resource"


def test_resource_summary_starts_empty():
    capture = NetworkCapture()

    assert capture.get_results() == []
    assert capture.get_inventory() == {
        "primary": [],
        "external": []
    }
    assert capture.get_resource_summary() == {}


def test_target_can_be_set_after_manual_navigation():
    capture = NetworkCapture()

    capture.set_target_url("https://example.com/dashboard")

    assert capture.classify_origin(
        "example.com"
    ) == "first_party"
