
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit, urlunsplit


STATIC_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".pdf"
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

API_PATH_HINTS = (
    "/api/",
    "/rest/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/youtubei/"
)

TELEMETRY_PATH_HINTS = (
    "/api/stats/",
    "/ptracking",
    "/telemetry",
    "/metrics",
    "/events",
    "/log_event",
    "/collect",
    "/qoe",
    "/watchtime",
    "/playback"
)

TELEMETRY_EXACT_PATHS = {
    "/log",
    "/g/collect",
    "/pagead/id"
}

MEDIA_PATH_HINTS = (
    "/videoplayback",
)

MEDIA_HOST_HINTS = (
    "googlevideo.com",
)


# Common identifier patterns.
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)

MONGODB_OBJECT_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{24}$"
)

NUMERIC_ID_PATTERN = re.compile(
    r"^\d+$"
)

# Conservative opaque-ID detection:
# At least 8 characters, containing both letters and digits.
OPAQUE_ID_PATTERN = re.compile(
    r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{8,}$"
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


def identify_path_segment(segment):
    """Identify a likely dynamic identifier in a URL path segment."""

    if UUID_PATTERN.fullmatch(segment):
        return "uuid"

    if MONGODB_OBJECT_ID_PATTERN.fullmatch(segment):
        return "mongodb_object_id"

    if NUMERIC_ID_PATTERN.fullmatch(segment):
        return "numeric_id"

    if OPAQUE_ID_PATTERN.fullmatch(segment):
        return "opaque_alphanumeric"

    return None


def extract_path_identifiers(path):
    """
    Extract dynamic path identifiers.

    Actual values are retained for local security research.
    """

    identifiers = []

    for index, segment in enumerate(path.split("/")):
        if not segment:
            continue

        identifier_type = identify_path_segment(segment)

        if identifier_type:
            identifiers.append({
                "position": index,
                "value": segment,
                "type": identifier_type
            })

    return identifiers


def normalize_path(path):
    """Replace common dynamic path identifiers with placeholders."""

    segments = []

    for segment in path.split("/"):
        if not segment:
            segments.append(segment)
            continue

        identifier_type = identify_path_segment(segment)

        placeholders = {
            "uuid": "{uuid}",
            "mongodb_object_id": "{object_id}",
            "numeric_id": "{id}",
            "opaque_alphanumeric": "{object_id}"
        }

        if identifier_type:
            segments.append(placeholders[identifier_type])
        else:
            segments.append(segment)

    return "/".join(segments)


class NetworkCapture:
    """Passively classify and inventory browser network traffic."""

    def __init__(self, target_url=None):
        self.target_host = None
        self.endpoints = {}
        self.resource_counts = Counter()

        if target_url:
            self.set_target_url(target_url)

    def set_target_url(self, target_url):
        """Set target hostname and update previously captured records."""

        try:
            host = urlsplit(target_url).hostname

            if not host:
                return

            self.target_host = host.lower()

            for record in self.endpoints.values():
                origin = self.classify_origin(record["domain"])
                record["origin_category"] = origin
                record["origin"] = origin

        except Exception:
            return

    @staticmethod
    def _is_static(url, content_type=""):
        path = urlsplit(url).path.lower()

        if path.endswith(".webmanifest"):
            return True

        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return True

        static_types = (
            "javascript",
            "text/css",
            "image/",
            "font/"
        )

        return any(
            item in (content_type or "").lower()
            for item in static_types
        )

    @staticmethod
    def _is_analytics(host):
        host = (host or "").lower()

        return any(
            host == hint or host.endswith("." + hint)
            for hint in ANALYTICS_HOST_HINTS
        )

    @staticmethod
    def _is_security_infrastructure(host):
        host = (host or "").lower()

        return any(
            hint in host
            for hint in SECURITY_HOST_HINTS
        )

    @staticmethod
    def _is_media(url, resource_type, content_type=""):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path.lower()
        content_type = (content_type or "").lower()

        media_extensions = (
            ".mp4", ".webm", ".mp3",
            ".m3u8", ".mpd", ".m4s", ".ts"
        )

        if (resource_type or "").lower() == "media":
            return True

        if any(hint in host for hint in MEDIA_HOST_HINTS):
            return True

        if any(hint in path for hint in MEDIA_PATH_HINTS):
            return True

        if path.endswith(media_extensions):
            return True

        return (
            "video/" in content_type
            or "audio/" in content_type
        )

    @staticmethod
    def _is_telemetry(path):
        path = path.lower().rstrip("/") or "/"

        if path in TELEMETRY_EXACT_PATHS:
            return True

        return any(
            hint in path
            for hint in TELEMETRY_PATH_HINTS
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
        resource_type = (resource_type or "").lower()
        content_type = (content_type or "").lower()

        if self._is_security_infrastructure(host):
            return "security_infrastructure"

        if self._is_analytics(host):
            return "analytics"

        if self._is_media(url, resource_type, content_type):
            return "media_delivery"

        if self._is_static(url, content_type):
            return "static_resource"

        if resource_type == "manifest":
            return "static_resource"

        if (
            path.endswith("/graphql")
            or "graphiql" in path
        ):
            return "graphql"

        if any(hint in path for hint in AUTH_PATH_HINTS):
            return "authentication"

        if self._is_telemetry(path):
            return "telemetry"

        if (
            resource_type in ("xhr", "fetch")
            or any(hint in path for hint in API_PATH_HINTS)
            or "json" in content_type
        ):
            return "rest_api"

        return "other"

    @staticmethod
    def _endpoint_template(url):
        return normalize_path(urlsplit(url).path)

    @staticmethod
    def _query_parameter_names(url):
        """Return parameter names only. Never retain their values."""

        try:
            return sorted({
                name
                for name, _ in parse_qsl(
                    urlsplit(url).query,
                    keep_blank_values=True
                )
                if name
            })
        except Exception:
            return []

    @staticmethod
    def _endpoint_key(method, host, endpoint_template):
        return (
            method.upper(),
            host.lower(),
            endpoint_template
        )

    def _get_or_create_record(self, request):
        parts = urlsplit(request.url)
        host = parts.hostname or "unknown"
        method = request.method.upper()
        template = self._endpoint_template(request.url)

        key = self._endpoint_key(method, host, template)

        if key not in self.endpoints:
            origin = self.classify_origin(host)

            self.endpoints[key] = {
                "url": sanitize_url(request.url),
                "method": method,
                "domain": host,

                # Keep both names for compatibility.
                "origin_category": origin,
                "origin": origin,

                "classification": "pending",
                "endpoint_template": template,

                # Actual path IDs are available for local research.
                "path_identifiers": extract_path_identifiers(
                    parts.path
                ),

                "has_object_identifier": False,
                "object_identifier_count": 0,

                "query_parameters": [],
                "status": None,
                "status_codes": [],
                "content_type": "unknown",
                "resource_type": request.resource_type,
                "resource_types": [],
                "request_count": 0,
                "failed_count": 0,
                "failed": False
            }

            record = self.endpoints[key]

            record["has_object_identifier"] = bool(
                record["path_identifiers"]
            )

            record["object_identifier_count"] = len(
                record["path_identifiers"]
            )

        record = self.endpoints[key]
        record["request_count"] += 1

        parameter_names = self._query_parameter_names(
            request.url
        )

        record["query_parameters"] = sorted(
            set(record["query_parameters"]).union(parameter_names)
        )

        if request.resource_type not in record["resource_types"]:
            record["resource_types"].append(request.resource_type)

        return record

    def _remove_record_if_ignored(self, key, classification):
        if classification in ("static_resource", "other"):
            self.endpoints.pop(key, None)
            return True

        return False

    def attach_page(self, page):
        """Attach passive request and response listeners."""

        def on_request(request):
            self.resource_counts[request.resource_type] += 1

            if sanitize_url(request.url) == "[URL OMITTED]":
                return

            classification = self.classify_request(
                request.url,
                request.resource_type
            )

            parts = urlsplit(request.url)

            key = self._endpoint_key(
                request.method,
                parts.hostname or "unknown",
                self._endpoint_template(request.url)
            )

            if self._remove_record_if_ignored(key, classification):
                return

            record = self._get_or_create_record(request)
            record["classification"] = classification

        def on_response(response):
            request = response.request
            parts = urlsplit(request.url)

            key = self._endpoint_key(
                request.method,
                parts.hostname or "unknown",
                self._endpoint_template(request.url)
            )

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

            if self._remove_record_if_ignored(key, classification):
                return

            record["classification"] = classification
            record["status"] = response.status
            record["content_type"] = content_type

            if response.status not in record["status_codes"]:
                record["status_codes"].append(response.status)

            record["status_codes"].sort()

        def on_request_failed(request):
            parts = urlsplit(request.url)

            key = self._endpoint_key(
                request.method,
                parts.hostname or "unknown",
                self._endpoint_template(request.url)
            )

            record = self.endpoints.get(key)

            if record is None:
                return

            classification = self.classify_request(
                request.url,
                request.resource_type
            )

            if self._remove_record_if_ignored(key, classification):
                return

            record["classification"] = classification
            record["failed_count"] += 1
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
        """Return normalized endpoint records."""

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
        """Split primary and external traffic into inventories."""

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

    def get_object_identifier_findings(self):
        """Return endpoint records containing detected path identifiers."""

        return [
            record
            for record in self.get_results()
            if record.get("has_object_identifier")
        ]

    def get_resource_summary(self):
        return dict(self.resource_counts)
