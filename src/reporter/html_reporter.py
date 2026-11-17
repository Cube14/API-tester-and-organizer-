
import html
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


class HTMLReporter:
    """Generate a standalone, sanitized HTML security assessment report."""

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def safe(value, default="Not available"):
        """Escape dynamic values before inserting them into HTML."""
        if value is None or value == "":
            value = default
        return html.escape(str(value), quote=True)

    @staticmethod
    def sanitize_endpoint(endpoint):
        """Redact query parameter values before displaying an endpoint."""
        if not endpoint:
            return "Unknown endpoint"

        try:
            original = str(endpoint)
            parsed = urlsplit(original)

            if not parsed.query:
                return html.escape(original, quote=True)

            query_params = parse_qsl(
                parsed.query,
                keep_blank_values=True
            )

            redacted_query = urlencode(
                [(key, "[REDACTED]") for key, _ in query_params],
                doseq=True,
                safe="[]"
            )

            sanitized = urlunsplit((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                redacted_query,
                ""
            ))

            return html.escape(sanitized, quote=True)

        except (TypeError, ValueError):
            return "Endpoint omitted for safety"

    @staticmethod
    def status_label(status):
        """Return a readable status label and CSS class."""
        labels = {
            "confirmed_bola": ("CONFIRMED BOLA", "confirmed"),
            "potential_bola": ("POTENTIAL BOLA", "potential"),
            "inconclusive": ("INCONCLUSIVE", "inconclusive"),
            "not_confirmed": ("NOT CONFIRMED", "neutral"),
        }

        return labels.get(status, ("UNCLASSIFIED", "neutral"))

    @staticmethod
    def _summary(findings, tests_performed):
        """Calculate report statistics from recorded findings."""
        statuses = [
            item.get("status")
            for item in findings
            if isinstance(item, dict)
        ]

        return {
            "tests": tests_performed,
            "confirmed": statuses.count("confirmed_bola"),
            "potential": statuses.count("potential_bola"),
            "inconclusive": statuses.count("inconclusive"),
            "not_confirmed": statuses.count("not_confirmed"),
            "recorded": len(statuses),
        }

    def _render_finding(self, finding, index):
        """Render one finding with safely escaped evidence."""
        if not isinstance(finding, dict):
            finding = {}

        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}

        status = finding.get("status")
        label, css_class = self.status_label(status)

        confirmed = status == "confirmed_bola"
        baseline_verified = evidence.get(
            "ownership_baseline_verified", False
        )
        ownership_mismatch = evidence.get(
            "ownership_mismatch", False
        )

        method = self.safe(finding.get("method", "GET")).upper()
        endpoint = self.sanitize_endpoint(finding.get("endpoint"))

        severity = self.safe(finding.get("severity"))
        object_id = self.safe(finding.get("object_id"))
        status_code = self.safe(finding.get("status_code"))
        reason = self.safe(finding.get("reason"))

        explanation = self.safe(
            finding.get(
                "explanation",
                "No additional explanation was provided."
            )
        )

        recommendation = self.safe(
            finding.get(
                "recommendation",
                "Review server-side object-level authorization."
            )
        )

        owner_field = self.safe(evidence.get("owner_field"))
        response_type = self.safe(evidence.get("response_type"))
        content_type = self.safe(evidence.get("content_type"))
        baseline_status = self.safe(
            evidence.get("baseline_http_status")
        )

        finding_title = (
            "Broken Object Level Authorization"
            if confirmed or status == "potential_bola"
            else "Authorization Test Result"
        )

        classification = (
            "Confirmed vulnerability"
            if confirmed
            else "Not confirmed"
            if status == "not_confirmed"
            else "Requires review"
        )

        severity_class = (
            "severity-" + css_class
            if css_class in {
                "confirmed", "potential", "inconclusive", "neutral"
            }
            else "severity-neutral"
        )

        return f"""
        <article class="finding">
            <div class="finding-top">
                <div>
                    <span class="eyebrow">FINDING {index:02d}</span>
                    <h2>{finding_title}</h2>
                    <p class="finding-context">
                        {method} authorization assessment
                    </p>
                </div>
                <span class="status {css_class}">{label}</span>
            </div>

            <div class="endpoint">
                <span class="field-label">ENDPOINT</span>
                <code>{method} {endpoint}</code>
            </div>

            <div class="details-grid">
                <div class="detail">
                    <span class="field-label">SEVERITY</span>
                    <strong class="{severity_class}">{severity}</strong>
                </div>

                <div class="detail">
                    <span class="field-label">OBJECT ID</span>
                    <strong>{object_id}</strong>
                </div>

                <div class="detail">
                    <span class="field-label">HTTP STATUS</span>
                    <strong>{status_code}</strong>
                </div>

                <div class="detail">
                    <span class="field-label">OWNER BASELINE</span>
                    <strong>
                        {"Verified" if baseline_verified else "Not verified"}
                    </strong>
                </div>

                <div class="detail">
                    <span class="field-label">OWNERSHIP MISMATCH</span>
                    <strong>
                        {"Detected" if ownership_mismatch else "Not detected"}
                    </strong>
                </div>

                <div class="detail">
                    <span class="field-label">CLASSIFICATION</span>
                    <strong>{classification}</strong>
                </div>
            </div>

            <section class="report-section">
                <h3>What happened?</h3>
                <p>{explanation}</p>
            </section>

            <section class="report-section">
                <h3>Technical evidence</h3>
                <ul>
                    <li>Cross-account HTTP status: {status_code}</li>
                    <li>
                        Legitimate-owner baseline:
                        {"Verified" if baseline_verified else "Not verified"}
                    </li>
                    <li>
                        Ownership mismatch:
                        {"Yes" if ownership_mismatch else "No"}
                    </li>
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
        """

    def generate_report(self, findings, tests_performed):
        """Generate a standalone HTML security assessment report."""
        timestamp = datetime.now(timezone.utc)

        # Materialize once so generators and lists behave consistently.
        findings = list(findings or [])

        summary = self._summary(findings, tests_performed)

        cards = [
            self._render_finding(finding, index)
            for index, finding in enumerate(findings, start=1)
        ]

        findings_html = "\n".join(cards)

        if not findings_html:
            findings_html = """
            <div class="empty-state">
                <h2>No recorded findings</h2>
                <p>No BOLA test results were recorded during this scan.</p>
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
    --purple: #b98bea;
}}

* {{
    box-sizing: border-box;
}}

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

.brand span {{
    color: var(--red);
}}

.tagline {{
    color: var(--muted);
    font-size: 12px;
    letter-spacing: 2px;
    margin-top: 3px;
}}

.hero {{
    padding: 54px 0 30px;
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
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin: 26px 0 44px;
}}

.stat {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 19px;
}}

.stat strong {{
    display: block;
    font-size: 29px;
}}

.stat span {{
    color: var(--muted);
    font-size: 11px;
}}

.stat.danger strong {{ color: var(--red); }}
.stat.warning strong {{ color: var(--yellow); }}
.stat.success strong {{ color: var(--green); }}
.stat.purple strong {{ color: var(--purple); }}

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
    margin: 5px 0 0;
    font-size: 21px;
}}

.finding-context {{
    color: var(--muted);
    font-size: 12px;
    margin: 3px 0 18px;
}}

.status {{
    border: 1px solid currentColor;
    border-radius: 30px;
    padding: 5px 12px;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}}

.confirmed, .severity-confirmed {{ color: var(--red); }}
.potential, .severity-potential {{ color: var(--yellow); }}
.inconclusive, .severity-inconclusive {{ color: var(--purple); }}
.neutral, .severity-neutral {{ color: var(--muted); }}

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
    grid-template-columns: repeat(3, 1fr);
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
    overflow-wrap: anywhere;
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

@media (max-width: 850px) {{
    .stats {{
        grid-template-columns: repeat(3, 1fr);
    }}
}}

@media (max-width: 600px) {{
    .stats {{
        grid-template-columns: repeat(2, 1fr);
    }}

    .details-grid {{
        grid-template-columns: repeat(2, 1fr);
    }}

    .finding {{
        padding: 18px;
    }}
}}

@media print {{
    :root {{
        color-scheme: light;
        --background: #ffffff;
        --surface: #ffffff;
        --surface-2: #f3f3f3;
        --border: #dddddd;
        --text: #111111;
        --muted: #555555;
    }}

    body {{
        background: white;
        color: #111111;
    }}

    .finding {{
        break-inside: avoid;
    }}

    .recommendation {{
        background: #fff1f1;
    }}
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
            Authorized local assessment &middot;
            Generated {self.safe(generated_at)}
        </p>
        <p class="muted">
            This report summarizes observed API authorization behavior.
            Findings are based on the evidence recorded by API Sentinel.
        </p>
    </section>

    <section class="stats">
        <div class="stat">
            <strong>{summary["tests"]}</strong>
            <span>Tests executed</span>
        </div>

        <div class="stat danger">
            <strong>{summary["confirmed"]}</strong>
            <span>Confirmed BOLA</span>
        </div>

        <div class="stat warning">
            <strong>{summary["potential"]}</strong>
            <span>Potential BOLA</span>
        </div>

        <div class="stat purple">
            <strong>{summary["inconclusive"]}</strong>
            <span>Inconclusive</span>
        </div>

        <div class="stat success">
            <strong>{summary["not_confirmed"]}</strong>
            <span>Not confirmed</span>
        </div>
    </section>

    <section>
        <h2 class="section-heading">Finding details</h2>
        {findings_html}
    </section>

</main>

<footer>
    <div class="container">
        <strong>API SENTINEL</strong>
        &middot; Automated API authorization assessment
        <br>
        Generated locally. Review findings and validate remediation
        before making production security decisions.
        <br>
        Recorded results: {summary["recorded"]}
    </div>
</footer>

</body>
</html>
"""

        filename = (
            "api_sentinel_"
            + timestamp.strftime("%Y%m%d_%H%M%S_%f")
            + ".html"
        )

        report_path = self.output_dir / filename

        report_path.write_text(
            document,
            encoding="utf-8"
        )

        return report_path
