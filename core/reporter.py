"""Report generation for Phantom campaigns.

The :class:`Reporter` consumes a :class:`CampaignResult` and produces
formatted reports in HTML (via Jinja2 templates), JSON, or Markdown.
Reports include an executive summary, per-severity findings breakdown,
OWASP LLM Top 10 mapping, detailed attack logs, and remediation
recommendations.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

try:
    from jinja2 import Template
except ImportError:  # pragma: no cover
    Template = None  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from core.engine import CampaignResult


# ------------------------------------------------------------------
# Recommendations knowledge-base
# ------------------------------------------------------------------

_RECOMMENDATIONS: Dict[str, List[str]] = {
    "LLM01: Prompt Injection": [
        "Implement strict input validation and sanitisation for all user inputs.",
        "Use instruction hierarchy with clear privilege boundaries.",
        "Deploy prompt injection detection classifiers before the LLM.",
        "Apply output filtering to prevent instruction leakage.",
    ],
    "LLM02: Insecure Output Handling": [
        "Validate and sanitise all LLM outputs before rendering.",
        "Apply Content Security Policy (CSP) headers for web interfaces.",
        "Implement output format enforcement and schema validation.",
    ],
    "LLM04: Model Denial of Service": [
        "Set strict token limits on both input and output.",
        "Implement rate limiting per user and per session.",
        "Deploy resource monitoring with automatic circuit breakers.",
    ],
    "LLM06: Sensitive Information Disclosure": [
        "Never embed secrets, API keys, or PII in system prompts.",
        "Implement output scanning for sensitive data patterns.",
        "Use retrieval-based architectures instead of embedding context directly.",
        "Apply differential privacy techniques where appropriate.",
    ],
    "LLM08: Excessive Agency": [
        "Enforce principle of least privilege for all tool/plugin access.",
        "Require human-in-the-loop confirmation for sensitive actions.",
        "Implement comprehensive audit logging for all LLM-initiated actions.",
    ],
}

# ------------------------------------------------------------------
# HTML template (embedded to avoid external file dependency)
# ------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phantom Report &mdash; {{ name }}</title>
<style>
  :root {
    --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff;
    --red: #f85149; --orange: #d29922; --yellow: #e3b341;
    --green: #3fb950; --card: #161b22; --border: #30363d;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--fg); line-height: 1.6; padding: 2rem; }
  h1, h2, h3 { color: var(--accent); margin-bottom: 0.5rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  .card { background: var(--card); border: 1px solid var(--border);
          border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .severity-critical { border-left: 4px solid var(--red); }
  .severity-high { border-left: 4px solid var(--orange); }
  .severity-medium { border-left: 4px solid var(--yellow); }
  .severity-low { border-left: 4px solid var(--green); }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px;
           font-size: 0.8rem; font-weight: 600; margin-right: 6px; }
  .badge-critical { background: var(--red); color: #fff; }
  .badge-high { background: var(--orange); color: #fff; }
  .badge-medium { background: var(--yellow); color: #000; }
  .badge-low { background: var(--green); color: #000; }
  .badge-info { background: var(--border); color: var(--fg); }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  th { color: var(--accent); }
  pre { background: #0d1117; border: 1px solid var(--border);
        border-radius: 6px; padding: 1rem; overflow-x: auto;
        font-size: 0.85rem; max-height: 300px; }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }
  .stat-box { text-align: center; }
  .stat-number { font-size: 2rem; font-weight: 700; color: var(--accent); }
  .stat-label { font-size: 0.85rem; color: #8b949e; }
  .recommendation { padding: 0.5rem 0; border-bottom: 1px solid var(--border); }
  footer { text-align: center; color: #484f58; margin-top: 3rem; font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">
  <h1>Phantom Red Team Report</h1>
  <p style="color:#8b949e;">Campaign: <strong>{{ name }}</strong> | Target: <strong>{{ target }}</strong></p>
  <p style="color:#8b949e;">{{ start_time }} &mdash; {{ end_time }}</p>

  <!-- Executive Summary -->
  <div class="card" style="margin-top:1.5rem;">
    <h2>Executive Summary</h2>
    <div class="stat-grid" style="margin-top:1rem;">
      <div class="stat-box">
        <div class="stat-number">{{ total_attacks }}</div>
        <div class="stat-label">Total Attacks</div>
      </div>
      <div class="stat-box">
        <div class="stat-number" style="color:var(--red);">{{ successful_attacks }}</div>
        <div class="stat-label">Successful</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">{{ success_rate }}%</div>
        <div class="stat-label">Success Rate</div>
      </div>
    </div>
  </div>

  <!-- Severity Breakdown -->
  <div class="card">
    <h2>Findings by Severity</h2>
    <table>
      <tr><th>Severity</th><th>Count</th></tr>
      {% for sev, count in severity_breakdown.items() %}
      <tr>
        <td><span class="badge badge-{{ sev }}">{{ sev | upper }}</span></td>
        <td>{{ count }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <!-- OWASP Mapping -->
  <div class="card">
    <h2>OWASP LLM Top 10 Mapping</h2>
    <table>
      <tr><th>Category</th><th>Findings</th></tr>
      {% for cat, count in owasp_breakdown.items() %}
      <tr><td>{{ cat }}</td><td>{{ count }}</td></tr>
      {% endfor %}
    </table>
  </div>

  <!-- Detailed Findings -->
  <div class="card">
    <h2>Vulnerability Details</h2>
    {% for finding in findings %}
    <div class="card severity-{{ finding.severity }}" style="margin-top:1rem;">
      <h3>{{ finding.attack_name }}</h3>
      <p><span class="badge badge-{{ finding.severity }}">{{ finding.severity | upper }}</span> {{ finding.category }}</p>
      <p style="margin-top:0.5rem;"><strong>Prompt:</strong></p>
      <pre>{{ finding.prompt_sent }}</pre>
      <p style="margin-top:0.5rem;"><strong>Response:</strong></p>
      <pre>{{ finding.response }}</pre>
      <p style="margin-top:0.5rem;"><strong>Evidence:</strong> {{ finding.details }}</p>
    </div>
    {% endfor %}
  </div>

  <!-- Recommendations -->
  <div class="card">
    <h2>Recommendations</h2>
    {% for cat, recs in recommendations.items() %}
    <h3 style="margin-top:1rem;">{{ cat }}</h3>
    {% for rec in recs %}
    <div class="recommendation">&bull; {{ rec }}</div>
    {% endfor %}
    {% endfor %}
  </div>

  <footer>
    Generated by Phantom LLM Red Teaming Platform &mdash; {{ generated_at }}
  </footer>
</div>
</body>
</html>
"""


class Reporter:
    """Generates formatted reports from campaign results.

    Supports HTML (with an embedded Jinja2 template), JSON, and Markdown
    output formats.  Reports are written to disk and the output path is
    returned.
    """

    def __init__(self, output_dir: str = "reports") -> None:
        self._output_dir = Path(output_dir)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        campaign_result: CampaignResult,
        format: str = "html",
    ) -> str:
        """Generate a report and write it to disk.

        Args:
            campaign_result: The completed campaign to report on.
            format: One of ``html``, ``json``, or ``markdown``.

        Returns:
            Absolute path to the generated report file.

        Raises:
            ValueError: If *format* is not recognised.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in campaign_result.name
        )

        dispatch = {
            "html": self.generate_html,
            "json": self.generate_json,
            "markdown": self.generate_markdown,
        }

        if format not in dispatch:
            raise ValueError(
                f"Unknown report format '{format}'. "
                f"Supported: {list(dispatch.keys())}"
            )

        ext = {"html": "html", "json": "json", "markdown": "md"}[format]
        filename = f"phantom_{safe_name}_{timestamp}.{ext}"
        path = self._output_dir / filename

        content = dispatch[format](campaign_result)
        path.write_text(content, encoding="utf-8")

        return str(path.resolve())

    def generate_html(self, result: CampaignResult) -> str:
        """Render a rich HTML report with charts and findings.

        Falls back to a simple HTML document if Jinja2 is not installed.
        """
        context = self._build_template_context(result)

        if Template is not None:
            template = Template(_HTML_TEMPLATE)
            return template.render(**context)

        return self._generate_html_fallback(context)

    def generate_json(self, result: CampaignResult) -> str:
        """Produce a machine-readable JSON report."""
        data = {
            "campaign": {
                "name": result.name,
                "target": result.target,
                "start_time": result.start_time,
                "end_time": result.end_time,
                "summary": result.summary,
            },
            "findings": [
                {
                    "attack_name": r.attack_name,
                    "category": r.category,
                    "prompt_sent": r.prompt_sent,
                    "response": r.response,
                    "success": r.success,
                    "severity": r.severity,
                    "details": r.details,
                    "timestamp": r.timestamp,
                }
                for r in result.results
                if r.success
            ],
            "all_results": [
                {
                    "attack_name": r.attack_name,
                    "category": r.category,
                    "success": r.success,
                    "severity": r.severity,
                    "timestamp": r.timestamp,
                }
                for r in result.results
            ],
            "recommendations": self._get_recommendations(result),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def generate_markdown(self, result: CampaignResult) -> str:
        """Generate a Markdown summary report."""
        lines: List[str] = []
        summary = result.summary or {}

        lines.append(f"# Phantom Red Team Report: {result.name}")
        lines.append("")
        lines.append(f"**Target:** {result.target}  ")
        lines.append(f"**Period:** {result.start_time} -- {result.end_time}  ")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        total = summary.get("total_attacks", 0)
        successful = summary.get("successful_attacks", 0)
        rate = summary.get("success_rate", 0)
        lines.append(f"- **Total attacks:** {total}")
        lines.append(f"- **Successful attacks:** {successful}")
        lines.append(f"- **Success rate:** {rate * 100:.1f}%")
        lines.append("")

        # Severity breakdown
        sev = summary.get("severity_breakdown", {})
        if sev:
            lines.append("## Findings by Severity")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for level in ("critical", "high", "medium", "low", "info"):
                if level in sev:
                    lines.append(f"| {level.upper()} | {sev[level]} |")
            lines.append("")

        # OWASP mapping
        owasp = self._compute_owasp_breakdown(result)
        if owasp:
            lines.append("## OWASP LLM Top 10 Mapping")
            lines.append("")
            lines.append("| Category | Findings |")
            lines.append("|----------|----------|")
            for cat, count in owasp.items():
                lines.append(f"| {cat} | {count} |")
            lines.append("")

        # Successful findings detail
        successes = [r for r in result.results if r.success]
        if successes:
            lines.append("## Vulnerability Details")
            lines.append("")
            for finding in successes:
                sev_label = finding.severity.upper()
                lines.append(f"### [{sev_label}] {finding.attack_name}")
                lines.append("")
                lines.append(f"**Category:** {finding.category}  ")
                lines.append("")
                lines.append("**Prompt:**")
                lines.append("```")
                lines.append(finding.prompt_sent[:500])
                lines.append("```")
                lines.append("")
                lines.append("**Response:**")
                lines.append("```")
                lines.append(finding.response[:500])
                lines.append("```")
                lines.append("")
                lines.append(f"**Evidence:** {finding.details}")
                lines.append("")
                lines.append("---")
                lines.append("")

        # Recommendations
        recs = self._get_recommendations(result)
        if recs:
            lines.append("## Recommendations")
            lines.append("")
            for cat, items in recs.items():
                lines.append(f"### {cat}")
                lines.append("")
                for item in items:
                    lines.append(f"- {item}")
                lines.append("")

        lines.append("---")
        lines.append(
            f"*Generated by Phantom LLM Red Teaming Platform -- "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*"
        )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_template_context(self, result: CampaignResult) -> Dict[str, Any]:
        """Assemble the context dict for the HTML template."""
        summary = result.summary or {}
        total = summary.get("total_attacks", 0)
        successful = summary.get("successful_attacks", 0)
        rate = summary.get("success_rate", 0)

        return {
            "name": result.name,
            "target": result.target,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "total_attacks": total,
            "successful_attacks": successful,
            "success_rate": f"{rate * 100:.1f}",
            "severity_breakdown": summary.get("severity_breakdown", {}),
            "owasp_breakdown": self._compute_owasp_breakdown(result),
            "findings": [r for r in result.results if r.success],
            "recommendations": self._get_recommendations(result),
            "generated_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
        }

    def _compute_owasp_breakdown(self, result: CampaignResult) -> Dict[str, int]:
        """Count successful findings per OWASP category."""
        counts: Dict[str, int] = {}
        for r in result.results:
            if r.success:
                cat = r.category
                counts[cat] = counts.get(cat, 0) + 1
        return counts

    def _get_recommendations(
        self, result: CampaignResult
    ) -> Dict[str, List[str]]:
        """Select relevant recommendations based on triggered categories."""
        triggered: set = set()
        for r in result.results:
            if r.success:
                triggered.add(r.category)

        from core.evaluator import _OWASP_MAP

        recs: Dict[str, List[str]] = {}
        for cat in triggered:
            owasp = _OWASP_MAP.get(cat, "")
            if owasp in _RECOMMENDATIONS and owasp not in recs:
                recs[owasp] = _RECOMMENDATIONS[owasp]

        # Always include general recommendations if there were any successes
        if triggered:
            recs["General"] = [
                "Conduct regular red-teaming exercises with updated attack libraries.",
                "Implement defence-in-depth with multiple independent safety layers.",
                "Monitor production logs for anomalous prompt patterns.",
                "Keep model and safety classifier versions up to date.",
            ]

        return recs

    def _generate_html_fallback(self, context: Dict[str, Any]) -> str:
        """Simple HTML report without Jinja2 dependency."""
        findings_html = ""
        for f in context.get("findings", []):
            sev = f.severity if hasattr(f, "severity") else "info"
            name = f.attack_name if hasattr(f, "attack_name") else "Unknown"
            prompt = f.prompt_sent if hasattr(f, "prompt_sent") else ""
            response = f.response if hasattr(f, "response") else ""
            details = f.details if hasattr(f, "details") else ""
            findings_html += (
                f'<div class="card severity-{sev}">'
                f"<h3>{name}</h3>"
                f"<p><strong>Severity:</strong> {sev.upper()}</p>"
                f"<pre>{prompt[:500]}</pre>"
                f"<pre>{response[:500]}</pre>"
                f"<p>{details}</p></div>"
            )

        return (
            "<!DOCTYPE html><html><head>"
            "<meta charset='utf-8'>"
            f"<title>Phantom Report - {context['name']}</title>"
            "</head><body style='font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem;'>"
            f"<h1>Phantom Report: {context['name']}</h1>"
            f"<p>Target: {context['target']}</p>"
            f"<p>Attacks: {context['total_attacks']} | "
            f"Successful: {context['successful_attacks']} | "
            f"Rate: {context['success_rate']}%</p>"
            f"{findings_html}"
            "</body></html>"
        )
