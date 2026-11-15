
from src.auth.auth_manager import AuthManager


def test_register_and_retrieve_accounts():
    manager = AuthManager()

    manager.register_account("account_a", "fake-token-a")
    manager.register_account("account_b", "fake-token-b")

    session_a = manager.get_session("account_a")
    session_b = manager.get_session("account_b")

    assert session_a is not session_b

    assert (
        session_a.headers["Authorization"]
        == "Bearer fake-token-a"
    )

    assert (
        session_b.headers["Authorization"]
        == "Bearer fake-token-b"
    )

    manager.close()
