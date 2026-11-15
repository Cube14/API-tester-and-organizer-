
class BOLADetector:
    """
    Detects potential Broken Object Level Authorization (BOLA)
    vulnerabilities in authorized API security tests.
    """

    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
        self.results = []

    def fetch_object(self, account_name, url):
        """
        Fetch an API object using a registered account's session.
        """

        try:
            response = self.auth_manager.get(account_name, url)

            try:
                response_data = response.json()
            except ValueError:
                response_data = response.text

            return {
                "account": account_name,
                "status_code": response.status_code,
                "data": response_data
            }

        except Exception as error:
            return {
                "account": account_name,
                "error": str(error)
            }

    @staticmethod
    def extract_value(data, field_path):
        """
        Extract a nested value using a dot-separated field path.

        Example:
        vehicle.owner.email
        """

        current = data

        for field in field_path.split("."):
            if not isinstance(current, dict):
                return None

            current = current.get(field)

            if current is None:
                return None

        return current

    def check_ownership(
        self,
        response_data,
        expected_owner,
        owner_path="vehicle.owner.email"
    ):
        """
        Compare expected ownership against the API response.
        """

        if not isinstance(response_data, dict):
            return {
                "vulnerable": False,
                "reason": "Response is not a JSON object."
            }

        actual_owner = self.extract_value(
            response_data,
            owner_path
        )

        if actual_owner is None:
            return {
                "vulnerable": False,
                "reason": "Owner information not found."
            }

        if str(actual_owner).casefold() != str(expected_owner).casefold():
            return {
                "vulnerable": True,
                "reason": "Object belongs to a different account.",
                "expected_owner": expected_owner,
                "actual_owner": actual_owner
            }

        return {
            "vulnerable": False,
            "reason": "Object ownership matches."
        }

    def test_cross_account_access(
        self,
        attacker_account,
        target_url,
        expected_owner,
        owner_path="vehicle.owner.email",
        object_id=None
    ):
        """
        Test whether one authenticated account can access
        an object belonging to another account.
        """

        result = self.fetch_object(attacker_account, target_url)

        # Step 1: Check whether the request failed.
        if "error" in result:
            return {
                "vulnerable": False,
                "status": "inconclusive",
                "reason": result["error"]
            }

        # Step 2: Check the HTTP response.
        status_code = result["status_code"]

        if not 200 <= status_code < 300:
            return {
                "vulnerable": False,
                "status": "not_confirmed",
                "reason": "The API did not return a successful response.",
                "status_code": status_code
            }

        # Step 3: Verify the object's ownership.
        ownership = self.check_ownership(
            result["data"],
            expected_owner,
            owner_path
        )

        if not ownership["vulnerable"]:
            return {
                "vulnerable": False,
                "status": "not_confirmed",
                "reason": ownership["reason"],
                "status_code": status_code
            }

        # Step 4: Record the potential security finding.
        finding = {
            "vulnerable": True,
            "status": "potential_bola",
            "severity": "High",
            "endpoint": target_url,
            "method": "GET",
            "authenticated_account": attacker_account,
            "object_id": object_id,
            "status_code": status_code,
            "expected_owner": ownership["expected_owner"],
            "actual_owner": ownership["actual_owner"],
            "reason": ownership["reason"]
        }

        self.results.append(finding)

        return finding
