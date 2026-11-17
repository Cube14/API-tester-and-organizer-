
import re
from collections import Counter


SUPPORTED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
READ_ONLY_METHODS = {"GET", "HEAD"}

BACKGROUND_CLASSIFICATIONS = {
    "analytics",
    "security_infrastructure",
    "telemetry",
    "media_delivery",
    "static_resource",
    "other",
}

TRUSTED_ORIGINS = {"first_party", "same_site"}

# Match common object-identifier parameter names:
# id, user_id, reportId, object_uuid, etc.
IDENTIFIER_NAME_PATTERN = re.compile(
    r"(?:^|[_-])(?:id|uuid)$|(?:id|uuid)$",
    re.IGNORECASE
)


class BrowserDiscoveryPlanner:
    """
    Generate security test plans from passive browser discovery.

    This class never sends HTTP requests.

    Browser observations do not prove authentication requirements or
    authorization vulnerabilities. Consequently, discovered candidates
    require manual review before active testing.
    """

    def __init__(self, endpoint_records):
        self.endpoint_records = list(endpoint_records or [])

    @staticmethod
    def _get_origin(record):
        return record.get(
            "origin_category",
            record.get("origin", "unclassified")
        )

    @staticmethod
    def _get_path_identifiers(record):
        identifiers = []

        for identifier in record.get("path_identifiers", []):
            if not isinstance(identifier, dict):
                continue

            identifiers.append({
                "location": "path",
                "type": identifier.get("type", "unknown"),
                "position": identifier.get("position"),
            })

        return identifiers

    @staticmethod
    def _get_query_identifiers(record):
        identifiers = []

        for parameter in record.get("query_parameters", []):
            if not isinstance(parameter, str):
                continue

            if IDENTIFIER_NAME_PATTERN.search(parameter):
                identifiers.append({
                    "name": parameter,
                    "location": "query",
                    "type": "identifier_parameter",
                })

        return identifiers

    def _extract_identifiers(self, record):
        return (
            self._get_path_identifiers(record)
            + self._get_query_identifiers(record)
        )

    @staticmethod
    def _is_functional(record):
        classification = record.get("classification", "other")

        return classification not in BACKGROUND_CLASSIFICATIONS

    def identify_candidates(self):
        """Identify first-party and same-site endpoints with object IDs."""

        candidates = []
        seen = set()

        for record in self.endpoint_records:
            if not isinstance(record, dict):
                continue

            method = str(record.get("method", "")).upper()

            if method not in SUPPORTED_METHODS:
                continue

            origin = self._get_origin(record)

            # Never create active-testing candidates for third-party APIs.
            if origin not in TRUSTED_ORIGINS:
                continue

            if not self._is_functional(record):
                continue

            identifiers = self._extract_identifiers(record)

            if not identifiers:
                continue

            endpoint = record.get("endpoint_template")

            if not endpoint:
                continue

            domain = record.get("domain", "")
            key = (method, domain, endpoint)

            if key in seen:
                continue

            seen.add(key)

            read_only = method in READ_ONLY_METHODS

            candidates.append({
                "source": "browser_discovery",
                "endpoint": endpoint,
                "domain": domain,
                "method": method,
                "origin": origin,
                "classification": record.get(
                    "classification", "other"
                ),
                "object_id_parameters": identifiers,
                "authentication_requirement": "unknown",
                "observed_http_status": record.get("status"),
                "request_count": record.get("request_count", 0),
                "execution_mode": "manual_review",
                "status": "review_required",
                "reason": (
                    "Browser discovery observed object identifiers, "
                    "but authentication and ownership requirements "
                    "have not been independently established."
                ),
                "active_testing_allowed": False,
                "vulnerability_confirmed": False,
                "recommended_test_type": (
                    "cross_account_authorization"
                    if read_only
                    else "authorization_review"
                ),
            })

        return candidates

    def generate_test_plan(self):
        """Generate reviewable test cases without sending HTTP requests."""

        candidates = self.identify_candidates()
        plans = []

        for candidate in candidates:
            identifiers = candidate["object_id_parameters"]

            steps = [
                "Confirm that the endpoint belongs to an authorized test target.",
                "Review the endpoint's authentication requirements.",
                "Identify the object ownership field and legitimate owner.",
                "Prepare two explicitly authorized test accounts.",
            ]

            if candidate["method"] in READ_ONLY_METHODS:
                steps.extend([
                    "Request an object owned by the legitimate account.",
                    "Record the baseline response and ownership evidence.",
                    "Request the same object as the second test account.",
                    "Compare access results and ownership evidence.",
                ])
            else:
                steps.extend([
                    "Review the endpoint's state-changing behavior.",
                    "Inspect object-level authorization and ownership checks.",
                    "Obtain explicit approval before any active testing.",
                ])

            plans.append({
                "endpoint": candidate["endpoint"],
                "domain": candidate["domain"],
                "method": candidate["method"],
                "source": candidate["source"],
                "origin": candidate["origin"],
                "classification": candidate["classification"],
                "object_id_parameters": identifiers,
                "authentication_requirement": "unknown",
                "test_type": candidate["recommended_test_type"],
                "execution_mode": "manual_review",
                "status": "review_required",
                "steps": steps,
                "reason": candidate["reason"],
                "active_testing_allowed": False,
                "vulnerability_confirmed": False,
            })

        return plans

    def generate_summary(self, test_plan=None):
        """Return counts for the generated discovery-based test plan."""

        if test_plan is None:
            test_plan = self.generate_test_plan()

        methods = Counter(
            item["method"] for item in test_plan
        )

        origins = Counter(
            item["origin"] for item in test_plan
        )

        return {
            "total_candidates": len(test_plan),
            "first_party_candidates": origins.get("first_party", 0),
            "same_site_candidates": origins.get("same_site", 0),
            "read_only_candidates": sum(
                item["method"] in READ_ONLY_METHODS
                for item in test_plan
            ),
            "manual_review_required": sum(
                item["execution_mode"] == "manual_review"
                for item in test_plan
            ),
            "active_tests_performed": 0,
            "confirmed_vulnerabilities": 0,
            "methods": dict(sorted(methods.items())),
        }
