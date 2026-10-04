<img src="assets/mcpwn-red-upscaled-hero.jpeg" width="100%" alt="mcpwn-red hero">

# mcpwn-red 🛡️

**Adversarial safety harness for the MCPwn AI pentesting execution engine.**

[![CI](https://github.com/Mutasem-mk4/mcpwn-red/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Mutasem-mk4/mcpwn-red/actions/workflows/ci.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)
[![Parrot OS: Submission Active](https://img.shields.io/badge/Parrot%20OS-Submission%20Active-brightgreen.svg)](https://gitlab.com/parrotsec/project/community/-/work_items/62)

`mcpwn-red` is a pre-engagement safety validator designed for security professionals using MCPwn. It reports evidence from configured checks; a passing check does not establish the safety of an entire deployment.

---

## ⚡ Quick Start

```bash
# Install from source
git clone https://github.com/Mutasem-mk4/mcpwn-red.git
cd mcpwn-red
python3 -m venv .venv
. .venv/bin/activate
pip install .

# Probe reachability
mcpwn-red probe --transport stdio

# Run deployment checks (YAML launches temporary MCPwn instances)
mcpwn-red scan --all --transport stdio --confirm-write --policy examples/yaml-deny.json
```

Install and configure [MCPwn](https://gitlab.com/parrotsec/project/mcpwn) first, and make its `mcpwn` executable available on `PATH` for the stdio probe. Installing `mcpwn-red` does not install MCPwn. If the executable is elsewhere, `scan` accepts `--mcpwn-command /path/to/mcpwn`; `probe` uses `mcpwn` from `PATH`. On Debian/Ubuntu, install `python3-venv` if creating the environment fails.

---

## 🔍 Why mcpwn-red?

MCPwn accepts operator-defined tools. This project checks registration behavior and calls selected deployment tools with test inputs; its output needs an explicit operator policy and review.

A registered shell command or a tool available through MCP is not, by itself, evidence of unauthorized access, a container escape, or successful prompt injection. Local output tests are simulations, not tests of a deployed language model's behavior.

### Assessment Modules

* **YAML:** Submits fixture tool definitions and records registration or rejection.
* **Output:** Simulates propagation of hostile output through a local mock client.
* **Container:** Calls available deployment tools with boundary probes and records their responses.
* **Scope:** Calls selected tools in two-step test chains and records responses or refusals.

These checks do not certify deployment security or isolation. Review findings against your intended trust boundaries before acting on them.

---

## 🛠️ Features

- **Protocol Native:** Built on the official `mcp>=1.0,<2` SDK.
- **Visual Reports:** Professional terminal tables, Markdown, and HTML report generation.
- **Temporary YAML configurations:** `--confirm-write` acknowledges local fixture creation. Container and scope modules call the deployment's tools independently of this flag; run them in an authorized test environment.
- **Packaging:** Debian source packaging is included; archive acceptance requires maintainer review.

---

## 📦 Distro Integration (Parrot OS)

`mcpwn-red` is designed to be a first-class citizen in the Parrot OS ecosystem.
- **Manpages:** Full documentation available via `man mcpwn-red`.
- **Validation:** CI runs Debian builds, lintian, and CLI smoke tests.
- **Dependency:** Debian builds require a packaged `python3-mcp` version below 2.

---

## 🤝 Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details. 
We have active templates for:
- [Bug Reports](.github/ISSUE_TEMPLATE/bug_report.yml)
- [Feature Requests](.github/ISSUE_TEMPLATE/feature_request.yml)

---

## ⚖️ Legal & Ethical Use

Use `mcpwn-red` only against MCPwn deployments you are authorized to assess. The tool prints a mandatory ethical-use notice on every invocation to remind operators of their responsibilities.

---

## 📝 License

Distributed under the **GPL-3.0-only** License. See `LICENSE` for more information.

## Scan interpretation

`--all` runs YAML, container, and scope deployment checks. Container and scope
checks call tools on the selected deployment; use an authorized test environment.
YAML checks copy the executable selected by `--mcpwn-command` (default: `mcpwn`)
into a temporary directory and place a single `mcpwn.yaml` alongside it before
startup. They list tools without executing fixture commands. A baseline must
register the control tool before a rejection can count as PASS. Existing user
configuration files are not written.

A registered definition is an observation. With an explicit deny rule it is FAIL;
with an allow rule it is PASS. Without a rule it is UNKNOWN. None of these statuses
proves execution, unauthorized configuration access or a prompt injection exploit. An absent tool
without explicit configuration rejection is UNKNOWN. Server/transport errors are
ERROR, never proof of policy enforcement.

Run the local output simulation separately:

```bash
mcpwn-red scan --module output --output-dir simulation-results
```

The simulation starts a local mock server. It measures payload propagation and
does not assess an MCPwn deployment or an AI agent. Its JSON report contains
`assessment_kind: "simulation"`; deployment scans use `"deployment"`.

Scan exits 0 for completed checks without findings, 1 for FAIL findings, and
2 for ERROR, UNKNOWN, or an empty assessment. Incomplete checks take precedence
over findings. Inspect `results.json` before using a scan as an automated gate.

Terminal, Markdown, and HTML reports display the reason and recommendation for
incomplete checks. For a missing tool, run `mcpwn-red probe --transport stdio`
(or `--transport sse --url` with your endpoint) to inspect the exposed tool list.
Verify the selected server and configuration. If the capability is outside the
deployment's intended scope, record that coverage limitation rather than adding
powerful tools just to turn an UNKNOWN result into a completed test. Rerun only
the relevant module in your authorized test environment after resolving the cause.

## Explicit assessment policy (0.2.0)

Deployment scans require a declared rule before a completed probe can become a
policy judgment. `--policy` reads JSON; missing rules produce UNKNOWN, not FAIL
or PASS. A malformed policy, unknown check ID or unsupported field fails before
starting a server. The policy is recorded in `results.json`.

```json
{
  "name": "Restricted tool registration",
  "checks": {
    "YAML-01": {"action": "deny", "severity": "medium"}
  }
}
```

`deny` prohibits the condition the probe is looking for. A matched condition is
FAIL; a probe indicating rejection or absence is PASS for that specific check.
`allow` permits a matched condition, which becomes PASS. If it is not observed,
the result is UNKNOWN: permission does not imply that the capability is present.
Severity comes from the rule; undeclared checks use low severity. UNKNOWN and
ERROR remain incomplete regardless of the rule and retain exit 2.

The example policies `examples/yaml-allow.json` and `examples/yaml-deny.json`
deliberately differ over trusted operator-defined registrations. Both deny a
missing required command. They are examples, not recommended security policies.
They contain no container/scope rules, so `--all` still reports those checks as
UNKNOWN unless suitable rules and evidence are supplied.

```bash
mcpwn-red scan --module yaml --confirm-write --policy examples/yaml-allow.json
mcpwn-red scan --module yaml --confirm-write --policy examples/yaml-deny.json
```

`probe_status` preserves the original check classifier: FAIL means its candidate
condition matched, PASS means its rejection/absence test matched, and UNKNOWN or
ERROR means it could not decide. This is not an exploit verdict. `policy_action`
records the applicable rule, and `evidence_kind` distinguishes registration from
tool-response evidence. Reports display those fields beside the policy judgment.
Tool-response checks use textual indicators; they do not establish a container
escape or the provenance of returned content. Scope replies claiming successful
execution remain UNKNOWN because reply text alone does not verify the action.

The output module remains a separate local simulation; `--policy` is rejected
for it. Previously saved reports load without policy metadata, but their old
statuses must be read as historical probe classifications, not policy judgments.
