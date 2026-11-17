
from src.engine.discovery_planner import BrowserDiscoveryPlanner


def sample_records():
    return [
        {
            "method": "GET",
            "domain": "example.local",
            "origin_category": "first_party",
            "classification": "rest_api",
            "endpoint_template": "/api/users/{id}",
            "path_identifiers": [
                {
                    "value": "123",
                    "type": "numeric_id",
                    "position": 3,
                }
            ],
            "query_parameters": [],
            "status": 200,
            "request_count": 2,
        },
        {
            "method": "GET",
            "domain": "example.local",
            "origin_category": "first_party",
            "classification": "rest_api",
            "endpoint_template": "/api/reports",
            "path_identifiers": [],
            "query_parameters": ["report_id", "page"],
            "status": 200,
            "request_count": 1,
        },
        {
            "method": "POST",
            "domain": "example.local",
            "origin_category": "first_party",
            "classification": "rest_api",
            "endpoint_template": "/api/orders",
            "path_identifiers": [],
            "query_parameters": ["user_id"],
            "status": 201,
            "request_count": 1,
        },
        {
            "method": "GET",
            "domain": "analytics.example.com",
            "origin_category": "third_party",
            "classification": "rest_api",
            "endpoint_template": "/api/users/{id}",
            "path_identifiers": [
                {
                    "value": "456",
                    "type": "numeric_id",
                    "position": 3,
                }
            ],
            "query_parameters": [],
            "status": 200,
            "request_count": 1,
        },
        {
            "method": "GET",
            "domain": "example.local",
            "origin_category": "first_party",
            "classification": "analytics",
            "endpoint_template": "/api/track/{id}",
            "path_identifiers": [
                {
                    "value": "789",
                    "type": "numeric_id",
                    "position": 3,
                }
            ],
            "query_parameters": [],
            "status": 200,
            "request_count": 1,
        },
    ]


def test_discovers_first_party_path_identifier():
    planner = BrowserDiscoveryPlanner(sample_records())
    candidates = planner.identify_candidates()

    assert any(
        item["endpoint"] == "/api/users/{id}"
        for item in candidates
    )


def test_discovers_query_identifier_names():
    planner = BrowserDiscoveryPlanner(sample_records())
    candidates = planner.identify_candidates()

    report_candidate = next(
        item for item in candidates
        if item["endpoint"] == "/api/reports"
    )

    assert report_candidate["object_id_parameters"][0]["name"] == "report_id"


def test_excludes_third_party_endpoints():
    planner = BrowserDiscoveryPlanner(sample_records())
    candidates = planner.identify_candidates()

    assert all(
        item["domain"] != "analytics.example.com"
        for item in candidates
    )


def test_excludes_background_traffic():
    planner = BrowserDiscoveryPlanner(sample_records())
    candidates = planner.identify_candidates()

    assert all(
        item["endpoint"] != "/api/track/{id}"
        for item in candidates
    )


def test_mutating_methods_require_manual_review():
    planner = BrowserDiscoveryPlanner(sample_records())
    candidates = planner.identify_candidates()

    order_candidate = next(
        item for item in candidates
        if item["endpoint"] == "/api/orders"
    )

    assert order_candidate["execution_mode"] == "manual_review"
    assert order_candidate["active_testing_allowed"] is False


def test_browser_discovery_never_confirms_vulnerability():
    planner = BrowserDiscoveryPlanner(sample_records())
    candidates = planner.identify_candidates()

    assert candidates
    assert all(
        item["vulnerability_confirmed"] is False
        for item in candidates
    )


def test_plan_contains_no_actual_path_identifier_values():
    planner = BrowserDiscoveryPlanner(sample_records())
    plan = planner.generate_test_plan()

    assert "123" not in str(plan)
    assert "456" not in str(plan)
    assert "789" not in str(plan)


def test_plan_does_not_contain_query_values():
    records = sample_records()
    records[1]["query_parameters"] = ["report_id"]

    planner = BrowserDiscoveryPlanner(records)
    plan = planner.generate_test_plan()

    assert "report_id" in str(plan)
    assert "123" not in str(plan)


def test_summary_reports_no_active_tests():
    planner = BrowserDiscoveryPlanner(sample_records())

    plan = planner.generate_test_plan()
    summary = planner.generate_summary(plan)

    assert summary["active_tests_performed"] == 0
    assert summary["confirmed_vulnerabilities"] == 0
    assert summary["total_candidates"] == 3
