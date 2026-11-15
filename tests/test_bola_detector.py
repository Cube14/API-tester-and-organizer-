
from src.engine.bola_detector import BOLADetector


def test_same_owner_is_not_flagged():
    detector = BOLADetector(None)

    response = {
        "vehicle": {
            "owner": {
                "email": "account_a@example.com"
            }
        }
    }

    result = detector.check_ownership(
        response,
        "account_a@example.com"
    )

    assert result["vulnerable"] is False
    assert result["reason"] == "Object ownership matches."


def test_different_owner_is_flagged():
    detector = BOLADetector(None)

    response = {
        "vehicle": {
            "owner": {
                "email": "account_a@example.com"
            }
        }
    }

    result = detector.check_ownership(
        response,
        "account_b@example.com"
    )

    assert result["vulnerable"] is True
    assert result["actual_owner"] == "account_a@example.com"


def test_missing_owner_is_not_confirmed():
    detector = BOLADetector(None)

    response = {
        "vehicle": {
            "id": 6
        }
    }

    result = detector.check_ownership(
        response,
        "account_a@example.com"
    )

    assert result["vulnerable"] is False
    assert result["reason"] == "Owner information not found."

def test_custom_owner_path():
    detector = BOLADetector(None)

    response = {
        "user": {
            "id": 12
        }
    }

    result = detector.check_ownership(
        response,
        expected_owner=15,
        owner_path="user.id"
    )

    assert result["vulnerable"] is True
    assert result["actual_owner"] == 12

from unittest.mock import Mock


def test_cross_account_access_detected():
    auth_manager = Mock()

    auth_manager.get.return_value = Mock(
        status_code=200,
        json=lambda: {
            "vehicle": {
                "owner": {
                    "email": "account_b@example.com"
                }
            }
        },
        text=""
    )

    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com",
        object_id=7
    )

    assert result["vulnerable"] is True
    assert result["status"] == "potential_bola"
    assert result["expected_owner"] == "account_a@example.com"
    assert result["actual_owner"] == "account_b@example.com"
    assert len(detector.results) == 1


def test_cross_account_access_denied():
    auth_manager = Mock()

    auth_manager.get.return_value = Mock(
        status_code=403,
        json=lambda: {"message": "Forbidden"},
        text=""
    )

    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com"
    )

    assert result["vulnerable"] is False
    assert result["status"] == "not_confirmed"
    assert result["status_code"] == 403
    assert len(detector.results) == 0


def test_cross_account_access_same_owner():
    auth_manager = Mock()

    auth_manager.get.return_value = Mock(
        status_code=200,
        json=lambda: {
            "vehicle": {
                "owner": {
                    "email": "account_a@example.com"
                }
            }
        },
        text=""
    )

    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/6",
        expected_owner="account_a@example.com"
    )

    assert result["vulnerable"] is False
    assert result["status"] == "not_confirmed"
    assert len(detector.results) == 0

def test_cross_account_access_missing_owner():
    auth_manager = Mock()

    auth_manager.get.return_value = Mock(
        status_code=200,
        json=lambda: {
            "vehicle": {
                "id": 7,
                "model": "Test Vehicle"
            }
        },
        text=""
    )

    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com"
    )

    assert result["vulnerable"] is False
    assert result["status"] == "not_confirmed"
    assert result["reason"] == "Owner information not found."
    assert len(detector.results) == 0


def test_cross_account_access_network_error():
    auth_manager = Mock()

    auth_manager.get.side_effect = Exception("Connection refused")

    detector = BOLADetector(auth_manager)

    result = detector.test_cross_account_access(
        attacker_account="account_a",
        target_url="http://localhost:8888/test/vehicle/7",
        expected_owner="account_a@example.com"
    )

    assert result["vulnerable"] is False
    assert result["status"] == "inconclusive"
    assert "Connection refused" in result["reason"]
    assert len(detector.results) == 0
