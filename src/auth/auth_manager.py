
import os
import requests


class AuthManager:
    """Manages authenticated HTTP sessions for security testing."""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.sessions = {}

    def register_account(self, account_name, token):
        """
        Register an account using its Bearer token.

        Tokens are supplied at runtime, not hardcoded.
        """
        if not account_name:
            raise ValueError("Account name cannot be empty.")

        if not token:
            raise ValueError("Authentication token cannot be empty.")

        session = requests.Session()

        session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        })

        self.sessions[account_name] = session

    def get_session(self, account_name):
        """Return the authenticated session for an account."""

        if account_name not in self.sessions:
            raise ValueError(
                f"Account '{account_name}' is not registered."
            )

        return self.sessions[account_name]

    def get(self, account_name, url):
        """Send an authenticated GET request."""

        session = self.get_session(account_name)

        response = session.get(
            url,
            timeout=self.timeout
        )

        return response

    def close(self):
        """Close all registered HTTP sessions."""

        for session in self.sessions.values():
            session.close()

        self.sessions.clear()
