
from pathlib import Path

from src.parser.openapi_parser import OpenAPIParser
from src.engine.test_planner import TestPlanner


def create_planner():
    spec_path = (
        Path(__file__).resolve().parents[1]
        / "config"
        / "sample_api.yaml"
    )

    parser = OpenAPIParser(spec_path)
    return TestPlanner(parser)


def test_identify_candidates():
    planner = create_planner()

    candidates = planner.identify_candidates()

    assert len(candidates) == 4

    read_only_candidates = [
        candidate for candidate in candidates
        if candidate["status"] == "candidate"
    ]

    review_candidates = [
        candidate for candidate in candidates
        if candidate["status"] == "security_review_recommended"
    ]

    assert len(read_only_candidates) == 3
    assert len(review_candidates) == 1


def test_candidates_contain_object_id_parameters():
    planner = create_planner()

    candidates = planner.identify_candidates()

    for candidate in candidates:
        assert len(candidate["object_id_parameters"]) > 0


def test_generate_test_plan():
    planner = create_planner()

    test_plan = planner.generate_test_plan()

    assert len(test_plan) == 4

    read_only_plans = [
        test for test in test_plan
        if test["execution_mode"] == "read_only_test"
    ]

    manual_review_plans = [
        test for test in test_plan
        if test["execution_mode"] == "manual_review"
    ]

    assert len(read_only_plans) == 3
    assert len(manual_review_plans) == 1

    for test in read_only_plans:
        assert test["test_type"] == "cross_account_authorization"
        assert test["status"] == "planned"
        assert len(test["steps"]) == 6

    for test in manual_review_plans:
        assert test["test_type"] == "authorization_review"
        assert test["status"] == "security_review_recommended"
        assert len(test["steps"]) == 4


def test_public_endpoint_is_not_planned_for_automatic_testing():
    planner = create_planner()

    test_plan = planner.generate_test_plan()

    public_plan = next(
        test for test in test_plan
        if test["endpoint"] == "/api/orders/{order_id}"
    )

    assert public_plan["execution_mode"] == "manual_review"
    assert public_plan["test_type"] == "authorization_review"

def test_query_parameter_is_identified_as_candidate():
    planner = create_planner()

    candidates = planner.identify_candidates()

    query_candidate = next(
        candidate for candidate in candidates
        if candidate["operation_id"] == "getOrderByQuery"
    )

    assert query_candidate["status"] == "candidate"
    assert query_candidate["execution_mode"] == "read_only_test"

    parameter = query_candidate["object_id_parameters"][0]

    assert parameter["name"] == "order_id"
    assert parameter["location"] == "query"


def test_query_parameter_is_included_in_test_plan():
    planner = create_planner()

    test_plan = planner.generate_test_plan()

    query_plan = next(
        test for test in test_plan
        if test["operation_id"] == "getOrderByQuery"
    )

    assert query_plan["method"] == "GET"
    assert query_plan["execution_mode"] == "read_only_test"
    assert query_plan["object_id_parameters"][0]["location"] == "query"
