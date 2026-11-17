
class BOLADetector:
    """Detect potential and confirmed Broken Object Level Authorization issues."""

    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
        self.results = []

    def _record_result(self, result):
        """Record every executed test exactly once."""
        self.results.append(result)
        return result

    def fetch_object(self, account_name, url):
        """Fetch an object without exposing raw exception messages."""
        try:
            response = self.auth_manager.get(account_name, url)

            try:
                data = response.json()
                response_type = "json"
            except (ValueError, TypeError):
                data = getattr(response, "text", "")
                response_type = "text"

            headers = getattr(response, "headers", {}) or {}

            return {
                "account": account_name,
                "status_code": response.status_code,
                "data": data,
                "response_type": response_type,
                "content_type": headers.get("Content-Type", "unknown"),
            }

        except Exception as error:
            return {
                "account": account_name,
                "error_type": type(error).__name__,
            }

    @staticmethod
    def extract_value(data, field_path):
        """Extract a nested value using a dot-separated path."""
        if not isinstance(data, dict):
            return None

        if not isinstance(field_path, str) or not field_path:
            return None

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
        owner_path="vehicle.owner.email",
    ):
        """
        Compare the returned owner with the expected owner.

        An ownership mismatch is evidence, not proof of a vulnerability.
        Confirmation requires a verified legitimate-owner baseline.
        """
        if not isinstance(response_data, dict):
            return {
                "vulnerable": False,
                "ownership_mismatch": False,
                "owner_found": False,
                "reason": "Response is not a JSON object.",
            }

        actual_owner = self.extract_value(response_data, owner_path)

        if actual_owner is None:
            return {
                "vulnerable": False,
                "ownership_mismatch": False,
                "owner_found": False,
                "reason": "Owner information not found.",
            }

        owner_matches = (
            str(actual_owner).casefold()
            == str(expected_owner).casefold()
        )

        return {
            "vulnerable": False,
            "ownership_mismatch": not owner_matches,
            "owner_found": True,
            "owner_matches": owner_matches,
            "actual_owner": actual_owner,
            "expected_owner": expected_owner,
            "reason": (
                "Object ownership matches."
                if owner_matches
                else "Object ownership does not match the requesting account."
            ),
        }

    def _build_result(
        self,
        status,
        attacker_account,
        target_url,
        object_id,
        status_code,
        reason,
        evidence,
        technical_detail=None,
    ):
        """Build a finding with severity based on verification status."""
        confirmed = status == "confirmed_bola"

        result = {
            "vulnerable": confirmed,
            "status": status,
            "severity": (
                "High"
                if confirmed
                else "Unconfirmed"
                if status == "potential_bola"
                else "None"
            ),
            "finding_type": "BOLA" if confirmed else None,
            "endpoint": target_url,
            "method": "GET",
            "authenticated_account": attacker_account,
            "object_id": object_id,
            "status_code": status_code,
            "reason": reason,
            "evidence": evidence,
        }

        if technical_detail:
            result["technical_detail"] = technical_detail

        return result

    def _finish(
        self,
        status,
        attacker_account,
        target_url,
        object_id,
        status_code,
        reason,
        evidence,
        technical_detail=None,
    ):
        """Build and record every test outcome."""
        result = self._build_result(
            status=status,
            attacker_account=attacker_account,
            target_url=target_url,
            object_id=object_id,
            status_code=status_code,
            reason=reason,
            evidence=evidence,
            technical_detail=technical_detail,
        )

        return self._record_result(result)

    def test_cross_account_access(
        self,
        attacker_account,
        target_url,
        expected_owner,
        owner_path="vehicle.owner.email",
        object_id=None,
        owner_account=None,
        baseline_owner=None,
    ):
        """
        Test cross-account access to an object.

        Confirmation requires:
        1. A legitimate owner retrieves the object successfully.
        2. The baseline response identifies the expected owner.
        3. A different account retrieves the same resource successfully.
        4. The second response identifies the same legitimate owner.

        Without a verified baseline, an ownership mismatch is potential BOLA.
        """

        baseline_verified = False
        baseline_status = None

        evidence = {
            "http_status": None,
            "owner_field_found": False,
            "ownership_mismatch": False,
            "ownership_baseline_verified": False,
        }

        # Verify the legitimate owner's access first.
        if owner_account is not None and baseline_owner is not None:

            if owner_account == attacker_account:
                return self._finish(
                    "inconclusive",
                    attacker_account,
                    target_url,
                    object_id,
                    None,
                    "The baseline account and requesting account must be different.",
                    evidence,
                )

            baseline = self.fetch_object(owner_account, target_url)

            if "error_type" in baseline:
                return self._finish(
                    "inconclusive",
                    attacker_account,
                    target_url,
                    object_id,
                    None,
                    "The legitimate-owner baseline request could not be completed.",
                    evidence,
                    f"Request failed ({baseline['error_type']}).",
                )

            baseline_status = baseline["status_code"]
            evidence["baseline_http_status"] = baseline_status

            if not 200 <= baseline_status < 300:
                evidence["http_status"] = baseline_status

                return self._finish(
                    "not_confirmed",
                    attacker_account,
                    target_url,
                    object_id,
                    baseline_status,
                    "The legitimate owner could not successfully retrieve the object. Baseline verification failed.",
                    evidence,
                )

            baseline_ownership = self.check_ownership(
                baseline["data"],
                baseline_owner,
                owner_path,
            )

            if not baseline_ownership.get("owner_matches", False):
                evidence["http_status"] = baseline_status
                evidence["owner_field_found"] = (
                    baseline_ownership.get("owner_found", False)
                )

                return self._finish(
                    "not_confirmed",
                    attacker_account,
                    target_url,
                    object_id,
                    baseline_status,
                    "The legitimate-owner response did not verify the expected object ownership.",
                    evidence,
                )

            baseline_verified = True

        # Request the same object using the different account.
        attacker_result = self.fetch_object(
            attacker_account,
            target_url,
        )

        if "error_type" in attacker_result:
            evidence["ownership_baseline_verified"] = baseline_verified

            return self._finish(
                "inconclusive",
                attacker_account,
                target_url,
                object_id,
                None,
                "The API request could not be completed.",
                evidence,
                f"Request failed ({attacker_result['error_type']}).",
            )

        status_code = attacker_result["status_code"]

        evidence["http_status"] = status_code
        evidence["ownership_baseline_verified"] = baseline_verified
        evidence["baseline_http_status"] = baseline_status

        if not 200 <= status_code < 300:
            return self._finish(
                "not_confirmed",
                attacker_account,
                target_url,
                object_id,
                status_code,
                "The API did not return a successful response. Cross-account access was not demonstrated.",
                evidence,
            )

        ownership = self.check_ownership(
            attacker_result["data"],
            expected_owner,
            owner_path,
        )

        evidence["owner_field_found"] = ownership["owner_found"]
        evidence["response_type"] = attacker_result["response_type"]
        evidence["content_type"] = attacker_result["content_type"]

        # Without owner information, the result cannot be evaluated.
        if not ownership["owner_found"]:
            return self._finish(
                "inconclusive",
                attacker_account,
                target_url,
                object_id,
                status_code,
                ownership["reason"],
                evidence,
            )

        # The returned owner matches the requesting account.
        if not ownership["ownership_mismatch"]:
            return self._finish(
                "not_confirmed",
                attacker_account,
                target_url,
                object_id,
                status_code,
                ownership["reason"],
                evidence,
            )

        evidence["ownership_mismatch"] = True
        evidence["owner_field"] = owner_path

        actual_owner = ownership["actual_owner"]

        # A verified baseline must identify the same owner in both responses.
        if baseline_verified:
            same_owner = (
                str(actual_owner).casefold()
                == str(baseline_owner).casefold()
            )

            if not same_owner:
                return self._finish(
                    "inconclusive",
                    attacker_account,
                    target_url,
                    object_id,
                    status_code,
                    "The cross-account response did not match the ownership established by the baseline.",
                    evidence,
                )

            status = "confirmed_bola"
            explanation = (
                "The legitimate owner successfully retrieved this object, "
                "and a different account also retrieved the same requested "
                "resource. Both responses identified the same legitimate owner."
            )

        else:
            status = "potential_bola"
            explanation = (
                "The API returned an object whose owner differs from the "
                "requesting account. A legitimate-owner baseline has not "
                "been verified."
            )

        result = self._finish(
            status,
            attacker_account,
            target_url,
            object_id,
            status_code,
            ownership["reason"],
            evidence,
        )

        result["expected_owner"] = expected_owner
        result["actual_owner"] = actual_owner
        result["explanation"] = explanation
        result["recommendation"] = (
            "Verify that the server checks object-level authorization "
            "against the authenticated user before returning the object."
        )

        return result
