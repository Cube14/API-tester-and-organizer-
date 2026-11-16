
import html
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit


class HTMLReporter:
    """Generate a standalone, sanitized HTML security report."""

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def sanitize_endpoint(endpoint):
        """Remove query parameter values before displaying an endpoint."""

        if not endpoint:
            return "Unknown endpoint"

        try:
            parts = urlsplit(str(endpoint))

            if not parts.query:
                return html.escape(str(endpoint))

            safe_query = "&".join(
                f"{key}=[REDACTED]"
                for key in (
                    parameter.split("=", 1)[0]
                    for parameter in parts.query.split("&")
                )
            )

            safe_endpoint = urlunsplit((
                parts.scheme,
                parts.netloc,
                parts.path,
                safe_query,
                ""
            ))

            return html.escape(safe_endpoint)

        except Exception:
            return "Endpoint omitted for safety"

    @staticmethod
    def safe(value, default="Not available"):
        """HTML-escape values before inserting them into the report."""

        if value is None or value == "":
            value = default

        return html.escape(str(value))

    @staticmethod
    def status_label(status):
        labels = {
            "confirmed_bola": ("CONFIRMED BOLA", "confirmed"),
            "potential_bola": ("POTENTIAL BOLA", "potential"),
            "inconclusive": ("INCONCLUSIVE", "inconclusive"),
            "not_confirmed": ("NOT CONFIRMED", "neutral")
        }

        return labels.get(
            status,
            ("UNCLASSIFIED", "neutral")
        )

    def generate_report(self, findings, tests_performed):
        """Create a standalone HTML report without exposing identities."""

        timestamp = datetime.now(timezone.utc)

        confirmed = sum(
            1 for item in findings
            if item.get("status") == "confirmed_bola"
        )

        potential = sum(
            1 for item in findings
            if item.get("status") == "potential_bola"
        )

        inconclusive = sum(
            1 for item in findings
            if item.get("status") == "inconclusive"
        )

        cards = []

        for index, finding in enumerate(findings, start=1):
            status = finding.get("status", "unknown")
            label, css_class = self.status_label(status)
            evidence = finding.get("evidence") or {}

            baseline_verified = evidence.get(
                "ownership_baseline_verified", False
            )

            ownership_mismatch = evidence.get(
                "ownership_mismatch", False
            )

            endpoint = self.sanitize_endpoint(
                finding.get("endpoint")
            )

            object_id = self.safe(
                finding.get("object_id")
            )

            reason = self.safe(
                finding.get("reason")
            )

            explanation = self.safe(
                finding.get(
                    "explanation",
                    "The scan did not provide an additional explanation."
                )
            )

            recommendation = self.safe(
                finding.get(
                    "recommendation",
                    "Review server-side authorization checks for this object."
                )
            )

            status_code = self.safe(
                finding.get("status_code")
            )

            owner_field = self.safe(
                evidence.get("owner_field")
            )

            response_type = self.safe(
                evidence.get("response_type")
            )

            content_type = self.safe(
                evidence.get("content_type")
            )

            baseline_status = self.safe(
                evidence.get("baseline_http_status")
            )

            cards.append(f"""
            <article class="finding">
                <div class="finding-top">
                    <div>
                        <span class="eyebrow">FINDING {index:02d}</span>
                        <h2>Broken Object Level Authorization</h2>
                    </div>
                    <span class="status {css_class}">{label}</span>
                </div>

                <div class="endpoint">
                    <span class="field-label">ENDPOINT</span>
                    <code>GET {endpoint}</code>
                </div>

                <div class="details-grid">
                    <div class="detail">
                        <span class="field-label">OBJECT ID</span>
                        <strong>{object_id}</strong>
                    </div>
                    <div class="detail">
                        <span class="field-label">HTTP STATUS</span>
                        <strong>{status_code}</strong>
                    </div>
                    <div class="detail">
                        <span class="field-label">BASELINE</span>
                        <strong>{'Verified' if baseline_verified else 'Not verified'}</strong>
                    </div>
                    <div class="detail">
                        <span class="field-label">OWNERSHIP MISMATCH</span>
                        <strong>{'Detected' if ownership_mismatch else 'Not detected'}</strong>
                    </div>
                </div>

                <section class="report-section">
                    <h3>What happened?</h3>
                    <p>{explanation}</p>
                </section>

                <section class="report-section">
                    <h3>Evidence</h3>
                    <ul>
                        <li>Cross-account HTTP status: {status_code}</li>
                        <li>Legitimate-owner baseline verified: {'Yes' if baseline_verified else 'No'}</li>
                        <li>Ownership mismatch: {'Yes' if ownership_mismatch else 'No'}</li>
                        <li>Ownership field inspected: {owner_field}</li>
                        <li>Response format: {response_type}</li>
                        <li>Content type: {content_type}</li>
                        <li>Baseline HTTP status: {baseline_status}</li>
                    </ul>
                </section>

                <section class="report-section">
                    <h3>Technical observation</h3>
                    <p>{reason}</p>
                </section>

                <section class="recommendation">
                    <h3>Recommended remediation</h3>
                    <p>{recommendation}</p>
                </section>
            </article>
            """)

        findings_html = "\n".join(cards)

        if not findings_html:
            findings_html = """
            <div class="empty-state">
                <h2>No recorded findings</h2>
                <p>No BOLA findings were recorded during this scan.</p>
            </div>
            """

        generated_at = timestamp.strftime(
            "%d %B %Y, %H:%M:%S UTC"
        )

        document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Sentinel | Security Assessment</title>
<style>
:root {{
    color-scheme: dark;
    --background: #090909;
    --surface: #121212;
    --surface-2: #191919;
    --border: #303030;
    --text: #f4f4f4;
    --muted: #999999;
    --red: #e34242;
    --green: #45c58a;
    --yellow: #e7b84b;
}}

* {{ box-sizing: border-box; }}

body {{
    margin: 0;
    background: var(--background);
    color: var(--text);
    font-family: Inter, Segoe UI, Arial, sans-serif;
    line-height: 1.6;
}}

.container {{
    width: min(1100px, calc(100% - 40px));
    margin: 0 auto;
}}

header {{
    border-bottom: 1px solid var(--border);
    padding: 30px 0;
}}

.brand {{
    font-size: 23px;
    font-weight: 800;
    letter-spacing: 2px;
}}

.brand span {{ color: var(--red); }}

.tagline {{
    color: var(--muted);
    font-size: 12px;
    letter-spacing: 2px;
    margin-top: 3px;
}}

.hero {{
    padding: 54px 0 34px;
}}

.eyebrow {{
    color: var(--red);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
}}

h1 {{
    font-size: clamp(30px, 5vw, 46px);
    line-height: 1.15;
    margin: 12px 0;
}}

.subtitle, .muted {{
    color: var(--muted);
}}

.stats {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin: 26px 0 44px;
}}

.stat {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
}}

.stat strong {{
    display: block;
    font-size: 30px;
}}

.stat span {{
    color: var(--muted);
    font-size: 12px;
}}

.stat.danger strong {{ color: var(--red); }}
.stat.warning strong {{ color: var(--yellow); }}
.stat.success strong {{ color: var(--green); }}

.section-heading {{
    font-size: 20px;
    margin: 0 0 18px;
}}

.finding {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 26px;
    margin-bottom: 22px;
}}

.finding-top {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
}}

.finding h2 {{
    margin: 5px 0 18px;
    font-size: 21px;
}}

.status {{
    border: 1px solid currentColor;
    border-radius: 30px;
    padding: 5px 12px;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}}

.confirmed {{ color: var(--red); }}
.potential {{ color: var(--yellow); }}
.inconclusive {{ color: #c18bfa; }}
.neutral {{ color: var(--muted); }}

.endpoint {{
    background: #080808;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    overflow-wrap: anywhere;
}}

.endpoint code {{
    display: block;
    color: #f0aaaa;
    margin-top: 5px;
}}

.field-label {{
    color: var(--muted);
    display: block;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
}}

.details-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin: 16px 0 24px;
}}

.detail {{
    background: var(--surface-2);
    border-radius: 8px;
    padding: 13px;
    overflow-wrap: anywhere;
}}

.detail strong {{
    display: block;
    margin-top: 5px;
}}

.report-section {{
    border-top: 1px solid var(--border);
    padding-top: 15px;
    margin-top: 17px;
}}

.report-section h3, .recommendation h3 {{
    font-size: 14px;
    margin: 0 0 7px;
}}

.report-section p, .recommendation p {{
    color: #c7c7c7;
    margin: 0;
}}

.report-section ul {{
    color: #c7c7c7;
    padding-left: 20px;
    margin-bottom: 0;
}}

.recommendation {{
    background: #211313;
    border-left: 3px solid var(--red);
    border-radius: 6px;
    padding: 17px;
    margin-top: 20px;
}}

.empty-state {{
    border: 1px dashed var(--border);
    border-radius: 12px;
    padding: 30px;
    color: var(--muted);
}}

footer {{
    border-top: 1px solid var(--border);
    margin-top: 45px;
    padding: 25px 0 40px;
    color: var(--muted);
    font-size: 12px;
}}

@media (max-width: 700px) {{
    .stats {{ grid-template-columns: repeat(2, 1fr); }}
    .details-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .finding {{ padding: 18px; }}
}}
</style>
</head>
<body>
<header>
    <div class="container">
        <div class="brand">API <span>SENTINEL</span></div>
        <div class="tagline">DISCOVER. ANALYZE. TEST. PROTECT.</div>
    </div>
</header>

<main class="container">
    <section class="hero">
        <div class="eyebrow">SECURITY ASSESSMENT REPORT</div>
        <h1>API Security Findings</h1>
        <p class="subtitle">
            Local authorized assessment · Generated {self.safe(generated_at)}
        </p>
        <p class="muted">
            This report summarizes observed authorization behavior.
            Findings are based on the evidence recorded by API Sentinel.
        </p>
    </section>

    <section class="stats">
        <div class="stat">
            <strong>{tests_performed}</strong>
            <span>Test cases executed</span>
        </div>
        <div class="stat danger">
            <strong>{confirmed}</strong>
            <span>Confirmed BOLA findings</span>
        </div>
        <div class="stat warning">
            <strong>{potential}</strong>
            <span>Potential BOLA findings</span>
        </div>
        <div class="stat success">
            <strong>{inconclusive}</strong>
            <span>Inconclusive tests</span>
        </div>
    </section>

    <section>
        <h2 class="section-heading">Finding details</h2>
        {findings_html}
    </section>
</main>

<footer>
    <div class="container">
        <strong>API SENTINEL</strong> · Automated API authorization assessment
        <br>
        Generated locally. Review findings and validate remediation
        before making production security decisions.
    </div>
</footer>
</body>
</html>
"""

        filename = (
            "api_sentinel_"
            + timestamp.strftime("%Y%m%d_%H%M%S")
            + ".html"
        )

        report_path = self.output_dir / filename

        report_path.write_text(
            document,
            encoding="utf-8"
        )

        return report_path
