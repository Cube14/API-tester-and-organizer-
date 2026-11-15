
class BOLADetector:
    """
    Detects potential and confirmed BOLA vulnerabilities.

    A finding is confirmed only when:
    1. The legitimate owner can retrieve the object.
    2. The baseline response identifies that legitimate owner.
    3. A different account can retrieve the same object.
    4. The cross-account response still identifies the legitimate owner.
    """

    def __init__(self, auth_manager):
        self.auth_manager = auth_manager
        self.results = []

    def fetch_object(self, account_name, url):
        """Fetch an object and return safe response metadata."""

        try:
            response = self.auth_manager.get(account_name, url)

            try:
                response_data = response.json()
                response_type = "json"
            except (ValueError, TypeError):
                response_data = response.text
                response_type = "text"

            headers = getattr(response, "headers", {}) or {}

            return {
                "account": account_name,
                "status_code": response.status_code,
                "data": response_data,
                "response_type": response_type,
                "content_type": headers.get(
                    "Content-Type", "unknown"
                )
            }

        except Exception as error:
            return {
                "account": account_name,
                "error": str(error)
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
        owner_path="vehicle.owner.email"
    ):
        """
        Compare an object's returned owner with an expected identity.

        A mismatch is an observation. It is not independently
        sufficient to establish a confirmed BOLA vulnerability.
        """

        if not isinstance(response_data, dict):
            return {
                "vulnerable": False,
                "owner_found": False,
                "reason": "Response is not a JSON object."
            }

        actual_owner = self.extract_value(
            response_data,
            owner_path
        )

        if actual_owner is None:
            return {
                "vulnerable": False,
                "owner_found": False,
                "reason": "Owner information not found."
            }

        owner_matches = (
            str(actual_owner).casefold()
            == str(expected_owner).casefold()
        )

        if not owner_matches:
            return {
                "vulnerable": True,
                "owner_found": True,
                "owner_matches": False,
                "actual_owner": actual_owner,
                "expected_owner": expected_owner,
                "reason": "Object ownership does not match the requesting account."
            }

        return {
            "vulnerable": False,
            "owner_found": True,
            "owner_matches": True,
            "reason": "Object ownership matches."
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
        vulnerable=False,
        technical_detail=None
    ):
        """Build a consistent finding/result structure."""

        result = {
            "vulnerable": vulnerable,
            "status": status,
            "severity": (
                "High" if vulnerable else "None"
            ),
            "finding_type": (
                "BOLA" if vulnerable else None
            ),
            "endpoint": target_url,
            "method": "GET",
            "authenticated_account": attacker_account,
            "object_id": object_id,
            "status_code": status_code,
            "reason": reason,
            "evidence": evidence
        }

        if technical_detail is not None:
            result["technical_detail"] = technical_detail

        return result

    def test_cross_account_access(
        self,
        attacker_account,
        target_url,
        expected_owner,
        owner_path="vehicle.owner.email",
        object_id=None,
        owner_account=None,
        baseline_owner=None
    ):
        """
        Test cross-account access.

        expected_owner:
            Identity of the account making the cross-account request.

        owner_account:
            Registered account that legitimately owns the object.

        baseline_owner:
            Expected identity returned by the legitimate owner's request.

        Without a verified legitimate-owner baseline, an ownership
        mismatch remains potential_bola.
        """

        baseline_verified = False
        baseline_status = None

        # Step 1: Independently verify legitimate ownership.
        if owner_account is not None and baseline_owner is not None:

            if owner_account == attacker_account:
                return self._build_result(
                    status="inconclusive",
                    attacker_account=attacker_account,
                    target_url=target_url,
                    object_id=object_id,
                    status_code=None,
                    reason=(
                        "The baseline account and requesting account "
                        "must be different."
                    ),
                    evidence={
                        "http_status": None,
                        "ownership_mismatch": False,
                        "ownership_baseline_verified": False
                    }
                )

            baseline = self.fetch_object(
                owner_account,
                target_url
            )

            if "error" in baseline:
                return self._build_result(
                    status="inconclusive",
                    attacker_account=attacker_account,
                    target_url=target_url,
                    object_id=object_id,
                    status_code=None,
                    reason=(
                        "The legitimate-owner baseline request "
                        "could not be completed."
                    ),
                    evidence={
                        "http_status": None,
                        "ownership_mismatch": False,
                        "ownership_baseline_verified": False
                    },
                    technical_detail=baseline["error"]
                )

            baseline_status = baseline["status_code"]

            if not 200 <= baseline_status < 300:
                return self._build_result(
                    status="not_confirmed",
                    attacker_account=attacker_account,
                    target_url=target_url,
                    object_id=object_id,
                    status_code=baseline_status,
                    reason=(
                        "The legitimate owner could not successfully "
                        "retrieve the object. Baseline verification failed."
                    ),
                    evidence={
                        "http_status": baseline_status,
                        "ownership_mismatch": False,
                        "ownership_baseline_verified": False
                    }
                )

            baseline_ownership = self.check_ownership(
                baseline["data"],
                baseline_owner,
                owner_path
            )

            if not baseline_ownership.get("owner_matches", False):
                return self._build_result(
                    status="not_confirmed",
                    attacker_account=attacker_account,
                    target_url=target_url,
                    object_id=object_id,
                    status_code=baseline_status,
                    reason=(
                        "The legitimate-owner response did not "
                        "verify the expected object ownership."
                    ),
                    evidence={
                        "http_status": baseline_status,
                        "owner_field_found": baseline_ownership.get(
                            "owner_found", False
                        ),
                        "ownership_mismatch": False,
                        "ownership_baseline_verified": False
                    }
                )

            baseline_verified = True

        # Step 2: Make the cross-account request.
        attacker_result = self.fetch_object(
            attacker_account,
            target_url
        )

        if "error" in attacker_result:
            return self._build_result(
                status="inconclusive",
                attacker_account=attacker_account,
                target_url=target_url,
                object_id=object_id,
                status_code=None,
                reason="The API request could not be completed.",
                evidence={
                    "http_status": None,
                    "ownership_mismatch": False,
                    "ownership_baseline_verified": baseline_verified
                },
                technical_detail=attacker_result["error"]
            )

        status_code = attacker_result["status_code"]

        if not 200 <= status_code < 300:
            return self._build_result(
                status="not_confirmed",
                attacker_account=attacker_account,
                target_url=target_url,
                object_id=object_id,
                status_code=status_code,
                reason=(
                    "The API did not return a successful response. "
                    "Cross-account access was not demonstrated."
                ),
                evidence={
                    "http_status": status_code,
                    "ownership_mismatch": False,
                    "ownership_baseline_verified": baseline_verified
                }
            )

        # Step 3: Inspect the ownership in the attacker's response.
        ownership = self.check_ownership(
            attacker_result["data"],
            expected_owner,
            owner_path
        )

        if not ownership.get("owner_found", False):
            return self._build_result(
                status="not_confirmed",
                attacker_account=attacker_account,
                target_url=target_url,
                object_id=object_id,
                status_code=status_code,
                reason=ownership["reason"],
                evidence={
                    "http_status": status_code,
                    "owner_field_found": False,
                    "ownership_mismatch": False,
                    "ownership_baseline_verified": baseline_verified
                }
            )

        if not ownership.get("vulnerable", False):
            return self._build_result(
                status="not_confirmed",
                attacker_account=attacker_account,
                target_url=target_url,
                object_id=object_id,
                status_code=status_code,
                reason=ownership["reason"],
                evidence={
                    "http_status": status_code,
                    "owner_field_found": True,
                    "ownership_mismatch": False,
                    "ownership_baseline_verified": baseline_verified
                }
            )

        actual_owner = ownership["actual_owner"]

        # Step 4: A verified baseline must identify the same owner
        # returned to the different requesting account.
        if baseline_verified:
            same_object_owner = (
                str(actual_owner).casefold()
                == str(baseline_owner).casefold()
            )

            if not same_object_owner:
                return self._build_result(
                    status="inconclusive",
                    attacker_account=attacker_account,
                    target_url=target_url,
                    object_id=object_id,
                    status_code=status_code,
                    reason=(
                        "The cross-account response did not match "
                        "the ownership established by the baseline."
                    ),
                    evidence={
                        "http_status": status_code,
                        "owner_field_found": True,
                        "ownership_mismatch": True,
                        "ownership_baseline_verified": True,
                        "owner_field": owner_path,
                        "response_type": attacker_result["response_type"],
                        "content_type": attacker_result["content_type"]
                    }
                )

            status = "confirmed_bola"
            explanation = (
                "The legitimate owner successfully retrieved this "
                "object, and a different account also retrieved it. "
                "Both responses identified the same legitimate owner."
            )

        else:
            status = "potential_bola"
            explanation = (
                "The API returned an object whose owner differs from "
                "the requesting account. A legitimate-owner baseline "
                "has not yet been verified."
            )

        finding = self._build_result(
            status=status,
            attacker_account=attacker_account,
            target_url=target_url,
            object_id=object_id,
            status_code=status_code,
            reason=ownership["reason"],
            evidence={
                "http_status": status_code,
                "owner_field_found": True,
                "ownership_mismatch": True,
                "ownership_baseline_verified": baseline_verified,
                "owner_field": owner_path,
                "response_type": attacker_result["response_type"],
                "content_type": attacker_result["content_type"],
                "baseline_http_status": baseline_status
            },
            vulnerable=True
        )

        finding["expected_owner"] = expected_owner
        finding["actual_owner"] = actual_owner
        finding["explanation"] = explanation
        finding["recommendation"] = (
            "Verify that the server checks object ownership against "
            "the authenticated user before returning the requested object."
        )

        self.results.append(finding)

        return finding
