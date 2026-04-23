"""HTML report renderer."""

from __future__ import annotations

from jinja2 import Environment, select_autoescape

from mcpwn_red.attacks.base import ScanReport

_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{{ report.tool }} report</title>
    <style>
      body { font-family: "IBM Plex Sans", "Segoe UI", sans-serif; background: #f4efe8; color: #1d1b18; margin: 2rem; }
      h1, h2 { color: #7a2f24; }
      table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; background: #fffdf8; }
      th, td { border: 1px solid #d9c8b8; padding: 0.75rem; vertical-align: top; text-align: left; }
      th { background: #f1dfcd; }
      .PASS { color: #1f7a1f; font-weight: 700; }
      .FAIL { color: #9b1c1c; font-weight: 700; }
      .UNKNOWN { color: #8a6500; font-weight: 700; }
      .ERROR { color: #6a1b1b; font-weight: 700; }
      code { background: #f5eee4; padding: 0.1rem 0.3rem; border-radius: 3px; }
    </style>
  </head>
  <body>
    <h1>{{ report.tool }} report</h1>
    <p>
      Version <code>{{ report.version }}</code><br>
      Timestamp <code>{{ report.timestamp.isoformat() }}</code><br>
      MCPwn version <code>{{ report.mcpwn_version or "unknown" }}</code><br>
      Transport <code>{{ report.transport }}</code>
    </p>

    <h2>Summary</h2>
    <table>
      <tr><th>Status</th><th>Count</th></tr>
      {% for status, count in report.summary.items() %}
      <tr><td>{{ status }}</td><td>{{ count }}</td></tr>
      {% endfor %}
    </table>

    <h2>Results</h2>
    <table>
      <tr>
        <th>ID</th><th>Module</th><th>Status</th><th>Severity</th><th>Name</th><th>Evidence</th><th>Recommendation</th>
      </tr>
      {% for result in report.results %}
      <tr>
        <td>{{ result.id }}</td>
        <td>{{ result.module }}</td>
        <td class="{{ result.status }}">{{ result.status }}</td>
        <td>{{ result.severity }}</td>
        <td>{{ result.name }}</td>
        <td>{{ result.evidence }}</td>
        <td>{{ result.recommendation }}</td>
      </tr>
      {% endfor %}
    </table>
  </body>
</html>
""".strip()


def render_html_report(report: ScanReport) -> str:
    environment = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = environment.from_string(_TEMPLATE)
    return template.render(report=report)

