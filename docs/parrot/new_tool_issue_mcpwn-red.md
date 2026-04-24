# Basic tool information

### Name of the tool

mcpwn-red

### Purpose/functionality description

mcpwn-red is a pre-engagement safety validator for MCPwn deployments.

It is designed for authorized security professionals who want to verify that an MCPwn installation cannot be subverted before it is used in a real client environment. The tool focuses on four operator-safety risks:

- YAML tool-definition poisoning
- prompt-injection propagation through tool output
- container-boundary exposure
- unconstrained cross-tool escalation

It connects to MCPwn over stdio or SSE, runs targeted validation modules, and produces JSON, terminal, Markdown, and HTML reports.

### Project website

https://github.com/Mutasem-mk4/mcpwn-red

### Repository URL

https://github.com/Mutasem-mk4/mcpwn-red

### License

GPL-3.0-only

# Technical details

### Programming language(s) used

Python

### Dependencies required

At runtime and build time, the package currently depends on:

- python3-click
- python3-httpx
- python3-jinja2
- python3-mcp
- python3-pydantic
- python3-rich
- python3-yaml

The current archive-level blocker is `python3-mcp`. If Parrot already ships that dependency under the same or another binary package name, I can adjust the packaging accordingly. Otherwise, `python3-mcp` likely needs to be packaged first or in parallel.

### Installation method (source compilation, binary package, etc...)

The project is prepared as a Debian package and also supports Python installation from source:

```bash
python3 -m pip install .
```

For distro integration, the intended delivery method is a standard `.deb` package.

# Integration information

### How the tool fits into the ParrotOS ecosystem

mcpwn-red fits into Parrot as a defensive validation tool for operators using MCPwn during authorized security work.

It does not replace MCPwn or add a general-purpose offensive framework. Instead, it validates whether MCPwn itself can be manipulated through prompt injection, poisoned tool definitions, unsafe tool chaining, or container-boundary weaknesses before an operator trusts it in a client engagement.

The tool follows a structurally quiet model:

- it is a CLI utility
- it does not install background services
- it does not require structural changes to the operating system
- dangerous YAML write tests are gated behind an explicit `--confirm-write` flag

### Why it would benefit ParrotOS users

Parrot ships tools used in adversarial security workflows, and MCPwn-style execution engines increase the importance of pre-engagement trust validation.

mcpwn-red benefits Parrot users by giving them a focused way to assess whether the AI-assisted execution layer itself is safe to trust before they rely on it during an authorized engagement.

This aligns with Parrot's security-focused audience while preserving a clear defensive purpose.

# Documentation

### User documentation or manual

Project documentation is available in the repository README:

<https://github.com/Mutasem-mk4/mcpwn-red/blob/main/README.md>

The Debian package also includes a manpage:

- `debian/mcpwn-red.1`

### Installation instructions

Source installation:

```bash
git clone https://github.com/Mutasem-mk4/mcpwn-red.git
cd mcpwn-red
python3 -m pip install .
```

Development environment:

```bash
python3 -m pip install -e .[dev]
ruff check .
mypy mcpwn_red
pytest
```

# Maintenance commitment

### Contact information for the developer/maintainer

- Name: Mutasem Kharma
- Email: 140179052+Mutasem-mk4@users.noreply.github.com
- GitHub: Mutasem-mk4
- GitLab: kharma.mutasem

### Has it been tested on ParrotOS?

It has not yet been validated on a full Parrot host with `lintian` and `autopkgtest`, which I want to state clearly.

Current validation completed:

- `python -m ruff check .`
- `python -m mypy mcpwn_red`
- `python -m pytest`
- `python -m build`
- `python -m mcpwn_red --help`
- `python -m mcpwn_red list`
- GitHub Actions Python jobs passed
- GitHub Actions Debian package job passed

The remaining environment-specific validation still needed on Debian or Parrot is:

- `dpkg-buildpackage -us -uc`
- `lintian`
- `autopkgtest`
