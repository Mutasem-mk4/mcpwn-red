Subject: mcpwn-red package review request for Parrot OS

Hello Parrot team,

I am submitting `mcpwn-red` for package review.

`mcpwn-red` is a pre-engagement safety validator for MCPwn deployments. It is intended to help authorized operators verify that MCPwn cannot be manipulated through YAML tool poisoning, prompt-injection propagation, container-boundary exposure, or unsafe tool chaining before it is used in a real client engagement.

I prepared the repository for review with:

- Debian packaging metadata and policy-oriented packaging files
- README, manpage, and CLI parity for `probe`, `scan`, `list`, `report`, and `--version`
- explicit ethical-use messaging and fixture safety headers
- working GitHub CI for Python validation and Debian package build

Currently verified:

- `python -m ruff check .`
- `python -m mypy mcpwn_red`
- `python -m pytest`
- `python -m build`
- `python -m mcpwn_red --help`
- `python -m mcpwn_red list`
- GitHub Actions Python jobs passed
- GitHub Actions Debian package job passed

I also prepared a clean review branch and merge request for maintainers:

- GitLab branch: `parrot/submission-clean`
- GitLab MR: <https://gitlab.com/kharma.mutasem/mcpwn-red/-/merge_requests/2>

One blocker remains and I want to state it clearly:

the package currently depends on `python3-mcp`, and archive acceptance is gated on that dependency being available in Parrot or Debian, or being packaged separately first. If Parrot already ships the MCP Python SDK under the same or another binary package name, I can adjust the packaging accordingly.

The remaining distro-native validation that should still be run on Debian or Parrot before final archive acceptance is:

- `dpkg-buildpackage -us -uc`
- `lintian`
- `autopkgtest`

If useful, I can also prepare or help review a separate packaging submission for `python3-mcp`.

Regards,

Mutasem Kharma

- GitHub: <https://github.com/Mutasem-mk4/mcpwn-red>
- GitLab: <https://gitlab.com/kharma.mutasem/mcpwn-red>
