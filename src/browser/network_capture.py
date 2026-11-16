
import re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit


STATIC_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".mp4", ".webm", ".mp3", ".pdf"
}

ANALYTICS_HOST_HINTS = (
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "hotjar.com",
    "clarity.ms",
    "sentry.io"
)

SECURITY_HOST_HINTS = (
    "cloudflare.com",
    "challenges.cloudflare.com",
    "captcha",
    "recaptcha",
    "hcaptcha"
)

AUTH_PATH_HINTS = (
    "/login",
    "/logout",
    "/signin",
    "/signout",
    "/oauth",
    "/authorize",
    "/token",
    "/refresh",
    "/session",
    "/authentication",
    "/auth/"
)

GRAPHQL_PATH_HINTS = (
    "/graphql",
    "/graphiql"
)

API_PATH_HINTS = (
    "/api/",
    "/rest/",
    "/v1/",
    "/v2/",
    "/v3/"
)


def sanitize_url(url):
    """Remove credentials, query values and fragments from a URL."""

    try:
        parts = urlsplit(str(url))

        if not parts.scheme or not parts.hostname:
            return "[URL OMITTED]"

        host = parts.hostname

        if parts.port:
            host = f"{host}:{parts.port}"

        safe_query = "&".join(
            f"{parameter.split('=', 1)[0]}=[REDACTED]"
            for parameter in parts.query.split("&")
            if parameter
        )

        return urlunsplit((
            parts.scheme,
            host,
            parts.path,
            safe_query,
            ""
        ))

    except Exception:
        return "[URL OMITTED]"


def normalize_path(path):
    """
    Replace common dynamic path identifiers with placeholders.

    Examples:
        /api/users/123 -> /api/users/{id}
        /api/orders/550e8400-e29b-41d4-a716-446655440000
        -> /api/orders/{uuid}
    """

    segments = []

    for segment in path.split("/"):
        if not segment:
            segments.append(segment)
            continue

        if re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{12}",
            segment
        ):
            segments.append("{uuid}")

        elif re.fullmatch(r"\d+", segment):
            segments.append("{id}")

        else:
            segments.append(segment)

    return "/".join(segments)


class NetworkCapture:
    """Passively classify and inventory browser network traffic."""

    def __init__(self, target_url=None):
        self.target_host = (
            urlsplit(target_url).hostname.lower()
            if target_url and urlsplit(target_url).hostname
            else None
        )

        self.endpoints = {}
        self.resource_counts = Counter()
    def set_target_url(self, target_url):
        """Set the target hostname after manual browser navigation."""

        host = urlsplit(target_url).hostname

        if host:
            self.target_host = host.lower()
    @staticmethod
    def _is_static(url, content_type=""):
        path = urlsplit(url).path.lower()

        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return True

        static_types = (
            "javascript",
            "text/css",
            "image/",
            "font/",
            "audio/",
            "video/"
        )

        return any(
            item in content_type.lower()
            for item in static_types
        )

    @staticmethod
    def _is_analytics(host):
        return any(
            hint in host
            for hint in ANALYTICS_HOST_HINTS
        )

    @staticmethod
    def _is_security_infrastructure(host):
        return any(
            hint in host
            for hint in SECURITY_HOST_HINTS
        )

    def classify_origin(self, host):
        """Classify traffic relative to the researched website."""

        host = (host or "").lower()

        if not self.target_host:
            return "unclassified"

        if host == self.target_host:
            return "first_party"

        if host.endswith("." + self.target_host):
            return "same_site"

        return "third_party"

    def classify_request(
        self,
        url,
        resource_type,
        content_type="unknown"
    ):
        """Determine the likely purpose of a network request."""

        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path.lower()

        if self._is_security_infrastructure(host):
            return "security_infrastructure"

        if self._is_analytics(host):
            return "analytics"

        if self._is_static(url, content_type):
            return "static_resource"

        if (
            path.endswith("/graphql")
            or "graphiql" in path
        ):
            return "graphql"

        if any(hint in path for hint in AUTH_PATH_HINTS):
            return "authentication"

        if (
            resource_type in ("xhr", "fetch")
            or any(hint in path for hint in API_PATH_HINTS)
            or "json" in content_type.lower()
        ):
            return "rest_api"

        return "other"

    @staticmethod
    def _endpoint_template(url):
        parts = urlsplit(url)

        return normalize_path(parts.path)

    def attach_page(self, page):
        """Attach passive request and response listeners."""

        def on_request(request):
            self.resource_counts[request.resource_type] += 1

            safe_url = sanitize_url(request.url)

            if safe_url == "[URL OMITTED]":
                return

            method = request.method.upper()
            key = (method, safe_url)

            if key not in self.endpoints:
                parts = urlsplit(request.url)
                host = parts.hostname or "unknown"

                self.endpoints[key] = {
                    "url": safe_url,
                    "method": method,
                    "domain": host,
                    "origin_category": self.classify_origin(host),
                    "classification": "pending",
                    "endpoint_template": self._endpoint_template(
                        request.url
                    ),
                    "status": None,
                    "content_type": "unknown",
                    "resource_type": request.resource_type,
                    "request_count": 0,
                    "failed": False
                }

            self.endpoints[key]["request_count"] += 1

        def on_response(response):
            request = response.request

            safe_url = sanitize_url(request.url)
            key = (request.method.upper(), safe_url)

            record = self.endpoints.get(key)

            if record is None:
                return

            headers = response.headers or {}
            content_type = headers.get(
                "content-type",
                "unknown"
            )

            classification = self.classify_request(
                request.url,
                request.resource_type,
                content_type
            )

            if classification in (
                "static_resource",
                "other"
            ):
                self.endpoints.pop(key, None)
                return

            record["classification"] = classification
            record["status"] = response.status
            record["content_type"] = content_type

        def on_request_failed(request):
            safe_url = sanitize_url(request.url)
            key = (request.method.upper(), safe_url)

            record = self.endpoints.get(key)

            if record is None:
                return

            classification = self.classify_request(
                request.url,
                request.resource_type
            )

            if classification in (
                "static_resource",
                "other"
            ):
                self.endpoints.pop(key, None)
                return

            record["classification"] = classification
            record["failed"] = True

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", on_request_failed)

    def attach_context(self, context):
        """Attach listeners to current and future pages."""

        for page in list(context.pages):
            self.attach_page(page)

        context.on("page", self.attach_page)

    def get_results(self):
        """Return discovered API and infrastructure records."""

        return sorted(
            self.endpoints.values(),
            key=lambda item: (
                item["origin_category"],
                item["classification"],
                item["domain"],
                item["endpoint_template"],
                item["method"]
            )
        )

    def get_inventory(self):
        """Split first-party and external traffic into inventories."""

        results = self.get_results()

        primary = [
            item for item in results
            if item["origin_category"] in (
                "first_party",
                "same_site"
            )
        ]

        external = [
            item for item in results
            if item["origin_category"] == "third_party"
        ]

        return {
            "primary": primary,
            "external": external
        }

    def get_resource_summary(self):
        return dict(self.resource_counts)
