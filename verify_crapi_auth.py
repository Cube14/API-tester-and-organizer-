
import os
from dotenv import load_dotenv

from src.auth.auth_manager import AuthManager

load_dotenv()

base_url = os.getenv("CRAPI_BASE_URL")

auth_manager = AuthManager(timeout=10)

accounts = {
    "account_a": os.getenv("CRAPI_ACCOUNT_A_TOKEN"),
    "account_b": os.getenv("CRAPI_ACCOUNT_B_TOKEN"),
}

try:
    for account_name, token in accounts.items():

        if not token:
            print(f"[MISSING] {account_name} token")
            continue

        auth_manager.register_account(account_name, token)

        response = auth_manager.get(
            account_name,
            f"{base_url}/identity/api/v2/user/dashboard"
        )

        print(
            f"[{account_name}] "
            f"HTTP {response.status_code}"
        )

finally:
    auth_manager.close()
