
import os
from dotenv import load_dotenv

load_dotenv()

required_variables = [
    "CRAPI_BASE_URL",
    "CRAPI_ACCOUNT_A_TOKEN",
    "CRAPI_ACCOUNT_B_TOKEN",
    "CRAPI_ACCOUNT_A_EMAIL",
    "CRAPI_ACCOUNT_B_EMAIL",
]

all_configured = True

for variable in required_variables:
    value = os.getenv(variable)

    if value and value.strip():
        print(f"[OK] {variable} configured")
    else:
        print(f"[MISSING] {variable}")
        all_configured = False

if all_configured:
    print("\nConfiguration ready!")
else:
    print("\nComplete the missing entries in .env")
