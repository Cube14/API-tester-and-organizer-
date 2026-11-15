
class TestPlanner:
    __test__ = False

    """
    Creates safe test plans for identifying potential BOLA risks.
    """

    def __init__(self, parser):
        self.parser = parser

    def identify_candidates(self):
        """
        Identify endpoints suitable for BOLA security testing.

        Read-only operations are candidates for controlled testing.
        Modifying operations are restricted to manual review.
        """

        endpoints = self.parser.extract_endpoints()
        candidates = []

        read_only_methods = {"GET", "HEAD"}
        review_methods = {"POST", "PUT", "PATCH", "DELETE"}

        for endpoint in endpoints:
            method = endpoint["method"]

            if method not in read_only_methods | review_methods:
                continue

            object_ids = self.parser.identify_object_parameters(
                endpoint
            )

            if not object_ids:
                continue

            candidate = {
                "path": endpoint["path"],
                "method": method,
                "operation_id": endpoint["operation_id"],
                "object_id_parameters": object_ids
            }

            if not endpoint["auth_required"]:
                candidate.update({
                    "status": "security_review_recommended",
                    "execution_mode": "manual_review",
                    "reason": (
                        "Endpoint contains object ID parameters "
                        "but has no declared authentication requirement."
                    )
                })

            elif method in read_only_methods:
                candidate.update({
                    "status": "candidate",
                    "execution_mode": "read_only_test",
                    "reason": (
                        "Authenticated read-only endpoint contains "
                        "one or more object ID parameters."
                    )
                })

            else:
                candidate.update({
                    "status": "manual_review_required",
                    "execution_mode": "manual_review",
                    "reason": (
                        "Endpoint may involve object-level authorization "
                        "but requires manual review before testing."
                    )
                })

            candidates.append(candidate)

        return candidates

    def generate_test_plan(self):
        """
        Generate structured plans based on endpoint classification.

        Does not send HTTP requests.
        """

        candidates = self.identify_candidates()
        test_plan = []

        for candidate in candidates:

            if candidate["status"] == "candidate":
                plan = {
                    "endpoint": candidate["path"],
                    "method": candidate["method"],
                    "operation_id": candidate["operation_id"],
                    "object_id_parameters": candidate[
                        "object_id_parameters"
                    ],
                    "test_type": "cross_account_authorization",
                    "steps": [
                        "Authenticate as the legitimate object owner.",
                        "Request an object owned by that account.",
                        "Record the baseline response and ownership.",
                        "Authenticate as a different test account.",
                        "Request the same object using the same object ID.",
                        "Compare access results and ownership evidence."
                    ],
                    "execution_mode": "read_only_test",
                    "status": "planned"
                }

            else:
                plan = {
                    "endpoint": candidate["path"],
                    "method": candidate["method"],
                    "operation_id": candidate["operation_id"],
                    "object_id_parameters": candidate[
                        "object_id_parameters"
                    ],
                    "test_type": "authorization_review",
                    "steps": [
                        "Review the endpoint's authentication requirements.",
                        "Inspect its object-level authorization logic.",
                        "Determine whether ownership is verified.",
                        "Obtain explicit approval before active testing."
                    ],
                    "execution_mode": "manual_review",
                    "status": candidate["status"]
                }

            test_plan.append(plan)

        return test_plan
