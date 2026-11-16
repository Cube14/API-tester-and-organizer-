
from urllib.parse import urlsplit

from src.browser.network_capture import (
    sanitize_url,
    normalize_path,
    NetworkCapture
)


class FakeRequest:
    def __init__(self, url, method="GET", resource_type="fetch"):
        self.url = url
        self.method = method
        self.resource_type = resource_type


class FakeResponse:
    def __init__(self, request, status=200, headers=None):
        self.request = request
        self.status = status
        self.headers = headers or {}


class FakePage:
    def __init__(self):
        self.handlers = {}

    def on(self, event, callback):
        self.handlers[event] = callback

    def emit(self, event, value):
        self.handlers[event](value)


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


def test_api_candidate_detects_youtubei_path():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/youtubei/v1/browse",
        "fetch"
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


def test_manifest_file_is_not_an_api():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/manifest.webmanifest",
        "manifest",
        "application/manifest+json"
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


def test_telemetry_is_classified_separately():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/api/stats/qoe",
        "fetch",
        "text/html"
    ) == "telemetry"


def test_tracking_endpoint_is_telemetry():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/ptracking",
        "fetch"
    ) == "telemetry"


def test_media_delivery_is_classified():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://example.com/videoplayback",
        "fetch",
        "video/mp4"
    ) == "media_delivery"


def test_googlevideo_host_is_media_delivery():
    capture = NetworkCapture("https://example.com")

    assert capture.classify_request(
        "https://rr1.googlevideo.com/videoplayback",
        "fetch"
    ) == "media_delivery"


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


def test_target_can_be_set_after_manual_navigation():
    capture = NetworkCapture()

    capture.set_target_url("https://example.com/dashboard")

    assert capture.classify_origin(
        "example.com"
    ) == "first_party"


def test_setting_target_reclassifies_existing_records():
    capture = NetworkCapture()

    capture.endpoints[("GET", "example.com", "/api/users")] = {
        "domain": "example.com",
        "origin_category": "unclassified"
    }

    capture.set_target_url("https://example.com")

    assert capture.endpoints[
        ("GET", "example.com", "/api/users")
    ]["origin_category"] == "first_party"


def test_resource_summary_starts_empty():
    capture = NetworkCapture()

    assert capture.get_results() == []
    assert capture.get_inventory() == {
        "primary": [],
        "external": []
    }
    assert capture.get_resource_summary() == {}


def test_query_parameter_names_are_extracted_without_values():
    capture = NetworkCapture("https://example.com")

    names = capture._query_parameter_names(
        "https://example.com/api/users?id=123&token=secret"
    )

    assert names == ["id", "token"]
    assert "123" not in str(names)
    assert "secret" not in str(names)


def test_duplicate_query_variants_are_aggregated():
    capture = NetworkCapture("https://example.com")
    page = FakePage()
    capture.attach_page(page)

    first = FakeRequest(
        "https://example.com/api/users?id=123",
        "GET"
    )

    second = FakeRequest(
        "https://example.com/api/users?token=secret",
        "GET"
    )

    page.emit("request", first)
    page.emit("response", FakeResponse(first, 200, {
        "content-type": "application/json"
    }))

    page.emit("request", second)
    page.emit("response", FakeResponse(second, 200, {
        "content-type": "application/json"
    }))

    results = capture.get_results()

    assert len(results) == 1

    record = results[0]

    assert record["endpoint_template"] == "/api/users"
    assert record["request_count"] == 2
    assert record["query_parameters"] == ["id", "token"]
    assert record["status"] == 200
    assert record["status_codes"] == [200]

    assert "123" not in str(record)
    assert "secret" not in str(record)


def test_different_methods_remain_separate_endpoints():
    capture = NetworkCapture("https://example.com")
    page = FakePage()
    capture.attach_page(page)

    get_request = FakeRequest(
        "https://example.com/api/users",
        "GET"
    )

    post_request = FakeRequest(
        "https://example.com/api/users",
        "POST"
    )

    page.emit("request", get_request)
    page.emit("request", post_request)

    assert len(capture.get_results()) == 2


def test_numeric_path_variants_are_aggregated():
    capture = NetworkCapture("https://example.com")
    page = FakePage()
    capture.attach_page(page)

    first = FakeRequest(
        "https://example.com/api/users/123",
        "GET"
    )

    second = FakeRequest(
        "https://example.com/api/users/456",
        "GET"
    )

    page.emit("request", first)
    page.emit("request", second)

    results = capture.get_results()

    assert len(results) == 1
    assert results[0]["endpoint_template"] == "/api/users/{id}"
    assert results[0]["request_count"] == 2


def test_response_statuses_are_aggregated():
    capture = NetworkCapture("https://example.com")
    page = FakePage()
    capture.attach_page(page)

    first = FakeRequest("https://example.com/api/users")
    second = FakeRequest("https://example.com/api/users")

    page.emit("request", first)
    page.emit("response", FakeResponse(first, 200, {
        "content-type": "application/json"
    }))

    page.emit("request", second)
    page.emit("response", FakeResponse(second, 304, {
        "content-type": "application/json"
    }))

    record = capture.get_results()[0]

    assert record["request_count"] == 2
    assert record["status_codes"] == [200, 304]


def test_failed_requests_are_counted():
    capture = NetworkCapture("https://example.com")
    page = FakePage()
    capture.attach_page(page)

    request = FakeRequest(
        "https://example.com/api/users"
    )

    page.emit("request", request)
    page.emit("requestfailed", request)

    record = capture.get_results()[0]

    assert record["failed"] is True
    assert record["failed_count"] == 1
    assert record["request_count"] == 1


def test_primary_and_external_inventories_are_separated():
    capture = NetworkCapture("https://example.com")
    page = FakePage()
    capture.attach_page(page)

    primary = FakeRequest(
        "https://example.com/api/users"
    )

    external = FakeRequest(
        "https://api.external.com/api/data"
    )

    page.emit("request", primary)
    page.emit("request", external)

    inventory = capture.get_inventory()

    assert len(inventory["primary"]) == 1
    assert len(inventory["external"]) == 1
