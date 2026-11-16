
from src.browser.network_capture import sanitize_url


class PageDiscovery:
    """Collect a privacy-conscious inventory of visited website pages."""

    def __init__(self):
        self.pages = []
        self._seen = set()

    def attach_context(self, context):
        """Observe current and newly opened pages."""

        for page in context.pages:
            self._record_page(page)

        context.on("page", self._record_page)

    def _record_page(self, page):
        """Register main-frame navigation events."""

        def on_navigation(frame):
            if frame.parent_frame is not None:
                return

            self.capture_page(page)

        page.on("framenavigated", on_navigation)

    def capture_page(self, page):
        """Capture page structure without storing user-entered values."""

        try:
            page_url = sanitize_url(page.url)

            if page_url == "[URL OMITTED]":
                return

            if page_url.startswith("about:"):
                return

            structure = {
                "forms": [],
                "links": [],
                "button_count": 0,
                "input_count": 0
            }

            try:
                structure = page.evaluate("""
                    () => ({
                        forms: Array.from(document.forms).map(form => ({
                            method: (form.method || "GET").toUpperCase(),
                            action: form.action
                                ? new URL(form.action).origin
                                    + new URL(form.action).pathname
                                : location.origin + location.pathname,
                            input_types: Array.from(form.elements)
                                .filter(element =>
                                    element.tagName === "INPUT"
                                )
                                .map(element => element.type || "text")
                        })),
                        links: Array.from(
                            document.querySelectorAll("a[href]")
                        )
                            .map(link => link.href)
                            .slice(0, 100),
                        button_count:
                            document.querySelectorAll("button").length,
                        input_count:
                            document.querySelectorAll("input").length
                    })
                """)

            except Exception:
                pass

            safe_links = []

            for link in structure.get("links", []):
                safe_link = sanitize_url(link)

                if safe_link != "[URL OMITTED]":
                    safe_links.append(safe_link)

            forms = []

            for form in structure.get("forms", []):
                forms.append({
                    "method": form.get("method", "GET"),
                    "action": sanitize_url(
                        form.get("action", "")
                    ),
                    "input_types": form.get("input_types", [])
                })

            page_record = {
                "url": page_url,
                "forms": forms,
                "links": sorted(set(safe_links)),
                "button_count": structure.get("button_count", 0),
                "input_count": structure.get("input_count", 0)
            }

            if page_url not in self._seen:
                self._seen.add(page_url)
                self.pages.append(page_record)

            else:
                for existing in self.pages:
                    if existing["url"] == page_url:
                        existing.update(page_record)
                        break

        except Exception:
            # A page may close or navigate during inspection.
            return

    def capture_all(self, context):
        """Refresh all currently open page records."""

        for page in context.pages:
            if not page.is_closed():
                self.capture_page(page)

    def get_results(self):
        return list(self.pages)
