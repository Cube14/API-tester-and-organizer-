
from pathlib import Path

from playwright.sync_api import sync_playwright


class BrowserManager:
    """Manage dedicated and existing Chrome browser connections."""

    def __init__(
        self,
        mode="dedicated",
        profile_dir="browser_profile",
        cdp_url="http://127.0.0.1:9222"
    ):
        if mode not in ("dedicated", "existing"):
            raise ValueError(
                "Browser mode must be 'dedicated' or 'existing'."
            )

        self.mode = mode
        self.profile_dir = Path(profile_dir)
        self.cdp_url = cdp_url

        self.playwright = None
        self.browser = None
        self.context = None
        self.owns_browser = False

    def start(self):
        """Start a dedicated browser or attach to existing Chrome."""

        self.playwright = sync_playwright().start()

        try:
            if self.mode == "dedicated":
                self.profile_dir.mkdir(
                    parents=True,
                    exist_ok=True
                )

                self.context = (
                    self.playwright.chromium.launch_persistent_context(
                        user_data_dir=str(self.profile_dir.resolve()),
                        headless=False,
                        accept_downloads=False
                    )
                )

                self.browser = self.context.browser
                self.owns_browser = True

            else:
                self.browser = (
                    self.playwright.chromium.connect_over_cdp(
                        self.cdp_url
                    )
                )

                contexts = self.browser.contexts

                if not contexts:
                    raise RuntimeError(
                        "No browser context was found in the "
                        "existing Chrome session."
                    )

                self.context = contexts[0]
                self.owns_browser = False

            return self.context

        except Exception:
            self.stop()
            raise

    def get_pages(self):
        """Return currently open pages."""

        if self.context is None:
            return []

        return list(self.context.pages)

    def get_active_page(self):
        """Return the most recently opened page, if available."""

        pages = self.get_pages()

        if pages:
            return pages[-1]

        if self.context is None:
            raise RuntimeError("Browser has not been started.")

        return self.context.new_page()

    def stop(self):
        """Close only the browser resources owned by this manager."""

        try:
            if self.owns_browser and self.context is not None:
                self.context.close()

        finally:
            self.context = None
            self.browser = None
            self.owns_browser = False

            if self.playwright is not None:
                self.playwright.stop()
                self.playwright = None
