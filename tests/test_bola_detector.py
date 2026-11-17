
from unittest.mock import Mock

from src.engine.bola_detector import BOLADetector


def create_response(status_code, data, content_type="application/json"):
    response = Mock()
    response.status_code = status_code
    response.json.return_value = data
    response.text = str(data)
    response.headers = {"Content-Type": content_type}
    return response


def vehicle_response(owner):
    return {"vehicle": {"owner": {"email": owner}}}


def test_same_owner_is_not_flagged():
    detector = BOLADetector(None)
    result = detector.check_ownership(
        vehicle_response("account_a@example.com"),
        "account_a@example.com",
    )
    assert result["vulnerable"] is False
    assert result["ownership_mismatch"] is False
    assert result["owner_found"] is True
    assert result["owner_matches"] is True


def test_different_owner_is_flagged():
    detector = BOLADetector(None)
    result = detector.check_ownership(
        vehicle_response("account_a@example.com"),
        "account_b@example.com",
    )
    assert result["vulnerable"] is False
    assert result["ownership_mismatch"] is True
    assert result["owner_found"] is True
    assert result["owner_matches"] is False


def test_missing_owner_is_not_confirmed():
    detector = BOLADetector(None)
    result = detector.check_ownership(
        {"vehicle": {"id": 7}},
        "account_a@example.com",
    )
    assert result["vulnerable"] is False
    assert result["ownership_mismatch"] is False
    assert result["owner_found"] is False


def test_custom_owner_path():
    detector = BOLADetector(None)
    result = detector.check_ownership(
        {"user": {"id": 12}},
        expected_owner=15,
        owner_path="user.id",
    )
    assert result["vulnerable"] is False
    assert result["ownership_mismatch"] is True
    assert result["actual_owner"] == 12


def test_invalid_owner_path():
    detector = BOLADetector(None)
    result = detector.check_ownership(
        {"user": {"id": 12}},
        expected_owner=15,
        owner_path="user.profile.id",
    )
    assert result["owner_found"] is False
    assert result["vulnerable"] is False


def test_cross_account_access_detected():
    auth_manager = Mock()
    auth_manager.get.return_value = create_response(
        200,
        vehicle_response("account_b@example.com"),
    )
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
        object_id=7,
    )

    assert result["vulnerable"] is False
    assert result["status"] == "potential_bola"
    assert result["severity"] == "Unconfirmed"
    assert result["finding_type"] is None
    assert result["evidence"]["ownership_mismatch"] is True
    assert result["evidence"]["ownership_baseline_verified"] is False
    assert len(detector.results) == 1


def test_cross_account_access_confirmed_with_real_baseline():
    auth_manager = Mock()
    auth_manager.get.side_effect = [
        create_response(200, vehicle_response("account_b@example.com")),
        create_response(200, vehicle_response("account_b@example.com")),
    ]
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
        object_id=7,
        owner_account="account_b",
        baseline_owner="account_b@example.com",
    )

    assert result["vulnerable"] is True
    assert result["status"] == "confirmed_bola"
    assert result["severity"] == "High"
    assert result["finding_type"] == "BOLA"
    assert result["evidence"]["ownership_baseline_verified"] is True
    assert result["evidence"]["ownership_mismatch"] is True
    assert len(detector.results) == 1
    assert auth_manager.get.call_count == 2


def test_baseline_failure_prevents_confirmation():
    auth_manager = Mock()
    auth_manager.get.return_value = create_response(
        403, {"message": "Forbidden"}
    )
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
        object_id=7,
        owner_account="account_b",
        baseline_owner="account_b@example.com",
    )

    assert result["status"] == "not_confirmed"
    assert result["evidence"]["ownership_baseline_verified"] is False
    assert auth_manager.get.call_count == 1
    assert len(detector.results) == 1


def test_baseline_owner_mismatch_prevents_confirmation():
    auth_manager = Mock()
    auth_manager.get.return_value = create_response(
        200, vehicle_response("account_c@example.com")
    )
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
        object_id=7,
        owner_account="account_b",
        baseline_owner="account_b@example.com",
    )

    assert result["status"] == "not_confirmed"
    assert result["evidence"]["ownership_baseline_verified"] is False
    assert auth_manager.get.call_count == 1
    assert len(detector.results) == 1


def test_baseline_and_attacker_must_be_different_accounts():
    auth_manager = Mock()
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
        owner_account="account_a",
        baseline_owner="account_a@example.com",
    )

    assert result["status"] == "inconclusive"
    assert auth_manager.get.call_count == 0
    assert len(detector.results) == 1


def test_cross_account_access_denied():
    auth_manager = Mock()
    auth_manager.get.return_value = create_response(
        403, {"message": "Forbidden"}
    )
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
    )

    assert result["vulnerable"] is False
    assert result["status"] == "not_confirmed"
    assert result["status_code"] == 403
    assert len(detector.results) == 1


def test_cross_account_access_same_owner():
    auth_manager = Mock()
    auth_manager.get.return_value = create_response(
        200, vehicle_response("account_a@example.com")
    )
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/6",
        expected_owner="account_a@example.com",
    )

    assert result["vulnerable"] is False
    assert result["status"] == "not_confirmed"
    assert result["evidence"]["ownership_mismatch"] is False
    assert len(detector.results) == 1


def test_cross_account_access_missing_owner():
    auth_manager = Mock()
    auth_manager.get.return_value = create_response(
        200,
        {"vehicle": {"id": 7, "model": "Test Vehicle"}},
    )
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
    )

    assert result["vulnerable"] is False
    assert result["status"] == "inconclusive"
    assert result["reason"] == "Owner information not found."
    assert len(detector.results) == 1


def test_cross_account_access_network_error():
    auth_manager = Mock()
    auth_manager.get.side_effect = Exception("Connection refused")
    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
    )

    assert result["vulnerable"] is False
    assert result["status"] == "inconclusive"
    assert result["reason"] == "The API request could not be completed."
    assert result["technical_detail"] == "Request failed (Exception)."
    assert "Connection refused" not in result["technical_detail"]
    assert len(detector.results) == 1


def test_non_json_response_is_not_confirmed():
    auth_manager = Mock()
    response = Mock()
    response.status_code = 200
    response.json.side_effect = ValueError("Not JSON")
    response.text = "Request successful"
    response.headers = {"Content-Type": "text/plain"}
    auth_manager.get.return_value = response

    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
    )

    assert result["vulnerable"] is False
    assert result["status"] == "inconclusive"
    assert result["reason"] == "Response is not a JSON object."
    assert len(detector.results) == 1


def test_ownership_comparison_is_case_insensitive():
    detector = BOLADetector(None)

    result = detector.check_ownership(
        vehicle_response("Account_A@Example.com"),
        "account_a@example.com",
    )

    assert result["owner_matches"] is True
    assert result["ownership_mismatch"] is False
