
import os
from dotenv import load_dotenv

from src.auth.auth_manager import AuthManager

load_dotenv()

base_url = os.getenv("CRAPI_BASE_URL")
token = os.getenv("CRAPI_ACCOUNT_A_TOKEN")

auth_manager = AuthManager()

try:
    auth_manager.register_account("account_a", token)

    url = (
        f"{base_url}/workshop/api/mechanic/"
        "mechanic_report?report_id=7"
    )

    response = auth_manager.get("account_a", url)

    print("HTTP Status:", response.status_code)

    try:
        data = response.json()
        print("Response JSON:")
        print(data)
    except ValueError:
        print("Response is not JSON.")
        print(response.text[:1000])

finally:
    auth_manager.close()
