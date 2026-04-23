from __future__ import annotations

from jinja2 import Template

from mcpwn_red.attacks.base import ScanReport


def render_html(report: ScanReport) -> str:
    template = Template(
        """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>mcpwn-red Scan Report</title>
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    >
    <style>
      @media print {
        .no-print { display: none !important; }
        body { margin: 0; }
      }
      .evidence-pre {
        white-space: pre-wrap;
        word-break: break-word;
      }
    </style>
  </head>
  <body class="bg-light">
    <div class="container py-4">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h1 class="h3 mb-1">mcpwn-red Scan Report</h1>
          <div class="text-muted">{{ report.timestamp.isoformat() }}</div>
        </div>
        <span class="badge text-bg-dark">{{ report.transport }}</span>
      </div>

      <div class="row g-3 mb-4">
        {% for status, count in report.summary.items() %}
        <div class="col-sm-6 col-lg-3">
          <div class="card shadow-sm">
            <div class="card-body">
              <div class="text-muted small">{{ status }}</div>
              <div class="fs-3 fw-bold">{{ count }}</div>
            </div>
          </div>
        </div>
        {% endfor %}
      </div>

      <div class="card shadow-sm">
        <div class="card-header">Results</div>
        <div class="table-responsive">
          <table class="table table-striped mb-0">
            <thead>
              <tr>
                <th>ID</th>
                <th>Module</th>
                <th>Name</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {% for result in report.results %}
              <tr>
                <td>{{ result.id }}</td>
                <td>{{ result.module }}</td>
                <td>{{ result.name }}</td>
                <td>
                  {% if result.status == "PASS" %}
                  <span class="badge text-bg-success">PASS</span>
                  {% elif result.status == "FAIL" %}
                  <span class="badge text-bg-danger">FAIL</span>
                  {% elif result.status == "UNKNOWN" %}
                  <span class="badge text-bg-warning">UNKNOWN</span>
                  {% else %}
                  <span class="badge text-bg-secondary">ERROR</span>
                  {% endif %}
                </td>
                <td>{{ result.severity }}</td>
                <td>
                  <button
                    class="btn btn-sm btn-outline-secondary no-print"
                    data-bs-toggle="collapse"
                    data-bs-target="#evidence-{{ loop.index }}"
                  >
                    Toggle
                  </button>
                  <div class="collapse show mt-2" id="evidence-{{ loop.index }}">
                    <div class="evidence-pre small">{{ result.evidence }}</div>
                    <div class="small mt-2">
                      <strong>Recommendation:</strong> {{ result.recommendation }}
                    </div>
                  </div>
                </td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <script
      src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
    ></script>
  </body>
</html>
        """
    )
    return template.render(report=report)
