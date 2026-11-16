
from src.browser.network_capture import (
    NetworkCapture,
    extract_path_identifiers,
    identify_path_segment,
    normalize_path,
)


def test_detect_numeric_identifier():
    assert identify_path_segment("12345") == "numeric_id"


def test_detect_uuid_identifier():
    value = "550e8400-e29b-41d4-a716-446655440000"
    assert identify_path_segment(value) == "uuid"


def test_detect_mongodb_object_id():
    value = "65f1a2b3c4d5e6f789012345"
    assert identify_path_segment(value) == "mongodb_object_id"


def test_detect_opaque_alphanumeric_identifier():
    value = "M4625N1RAJR7191B0"
    assert identify_path_segment(value) == "opaque_alphanumeric"


def test_normalize_opaque_identifier():
    path = "/workshop/api/merchant/service_requests/M4625N1RAJR7191B0"

    assert normalize_path(path) == (
        "/workshop/api/merchant/service_requests/{object_id}"
    )


def test_extract_actual_identifier_value():
    path = "/workshop/api/merchant/service_requests/M4625N1RAJR7191B0"

    identifiers = extract_path_identifiers(path)

    assert len(identifiers) == 1
    assert identifiers[0]["value"] == "M4625N1RAJR7191B0"
    assert identifiers[0]["type"] == "opaque_alphanumeric"


def test_normalize_multiple_identifiers():
    path = "/users/123/orders/550e8400-e29b-41d4-a716-446655440000"

    assert normalize_path(path) == "/users/{id}/orders/{uuid}"


def test_normalize_mongodb_object_id():
    path = "/users/65f1a2b3c4d5e6f789012345"

    assert normalize_path(path) == "/users/{object_id}"


def test_regular_route_name_is_not_identifier():
    assert identify_path_segment("service_requests") is None


def test_origin_compatibility_fields():
    capture = NetworkCapture(
        target_url="http://localhost:8888"
    )

    capture.endpoints[("GET", "localhost", "/api/test")] = {
        "domain": "localhost",
        "origin_category": "unclassified",
        "origin": "unclassified",
    }

    capture.set_target_url("http://localhost:8888")

    record = capture.endpoints[("GET", "localhost", "/api/test")]

    assert record["origin_category"] == "first_party"
    assert record["origin"] == "first_party"


def test_subdomain_origin_classification():
    capture = NetworkCapture(
        target_url="https://example.com"
    )

    assert capture.classify_origin("api.example.com") == "same_site"


def test_external_origin_classification():
    capture = NetworkCapture(
        target_url="https://example.com"
    )

    assert capture.classify_origin("external.test") == "third_party"
