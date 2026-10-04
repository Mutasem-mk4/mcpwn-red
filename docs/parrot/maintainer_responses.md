# Likely Maintainer Questions and Ready Answers

These answers are written to be short, direct, and defensible in the Parrot
community issue or review threads.

## 1. Why should Parrot include this instead of leaving it upstream-only?

`mcpwn-red` is not a generic utility. It is specifically aimed at validating
the safety of MCPwn deployments before authorized engagement use. That makes it
relevant to Parrot's security workflow audience rather than just Python users in
general.

## 2. Is this an offensive tool or does it broaden attack surface?

It is framed and packaged as a defensive validation harness. It checks whether
MCPwn itself can be manipulated through poisoned tool definitions, prompt
injection, unsafe tool chaining, or container-boundary exposure. It does not
install services or change system structure.

## 3. Why is `python3-mcp` not already solved?

`mcpwn-red` depends on the official MCP Python SDK. Separate packaging work has
been prepared because that dependency is the real archive blocker. The follow-on
repo and MR are:

- <https://github.com/Mutasem-mk4/python3-mcp-debian>
- <https://gitlab.com/kharma.mutasem/python3-mcp-debian/-/merge_requests/1>

## 4. What is still not fully validated?

The remaining gap is Debian or Parrot native validation with:

- `dpkg-buildpackage -us -uc`
- `lintian`
- `autopkgtest`

Local Python validation and GitHub CI are already passing.

## 5. Does it change system behavior or install background services?

No. It is a CLI utility. It does not install background services or make
structural changes to the operating system. The YAML write path is explicitly
gated behind `--confirm-write`.

## 6. Who will maintain it?

The package is being submitted with an explicit maintainer contact and with the
expectation that I will handle review feedback, packaging fixes, and upstream
follow-up needed for acceptance.

## 7. What is the clean review branch?

The maintainer-facing branch and review links are:

- GitHub PR: <https://github.com/Mutasem-mk4/mcpwn-red/pull/1>
- GitLab MR: <https://gitlab.com/kharma.mutasem/mcpwn-red/-/merge_requests/2>

## 8. What should I post if they ask for current blocker status?

Use this:

```text
The remaining real blocker is python3-mcp archive readiness. Separate packaging
work for that dependency is already prepared here:
https://gitlab.com/kharma.mutasem/python3-mcp-debian/-/merge_requests/1

For mcpwn-red itself, local Python validation and GitHub CI are passing. The
remaining distro-native validation still to run on Debian or Parrot is:
- dpkg-buildpackage -us -uc
- lintian
- autopkgtest
```
