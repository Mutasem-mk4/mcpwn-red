# Conversation Handoff: `mcpwn-red` Parrot Submission

Date: 2026-04-24

## Goal
Continue the Parrot OS submission work for `mcpwn-red` without re-discovering context.

## Repositories
- `mcpwn-red`: `C:\Users\User\mcpwn-red`
- `python3-mcp-debian`: `C:\Users\User\python3-mcp-debian`

## Current Branches And Heads
### `mcpwn-red`
- Branch: `parrot/submission-clean`
- HEAD: `745e608`
- Purpose: clean review branch for Parrot-facing submission work

### `python3-mcp-debian`
- Branch: `debian/packaging`
- HEAD: `45d116b`
- Purpose: dependency packaging work for `python3-mcp`

## Review Links
### Parrot / submission links
- Parrot community issue: `https://gitlab.com/parrotsec/project/community/-/work_items/62`
- `mcpwn-red` GitHub PR: `https://github.com/Mutasem-mk4/mcpwn-red/pull/1`
- `mcpwn-red` GitLab MR: `https://gitlab.com/kharma.mutasem/mcpwn-red/-/merge_requests/2`

### Dependency packaging links
- `python3-mcp-debian` GitHub repo: `https://github.com/Mutasem-mk4/python3-mcp-debian`
- `python3-mcp-debian` GitLab repo: `https://gitlab.com/kharma.mutasem/python3-mcp-debian`
- `python3-mcp-debian` GitLab MR: `https://gitlab.com/kharma.mutasem/python3-mcp-debian/-/merge_requests/1`

## Validation Status
The previously-blocking Debian-native validation is now green in CI for both repositories.

### `mcpwn-red`
Successful run:
- GitHub Actions run: `24867412875`
- Workflow: `CI`
- Branch: `parrot/submission-clean`
- Result: `success`

Validated in CI:
- `dpkg-buildpackage -us -uc`
- `lintian`
- `autopkgtest`

### `python3-mcp-debian`
Successful runs:
- GitHub Actions run: `24867412770`
  - Workflow: `Debian Packaging`
  - Branch: `debian/packaging`
  - Result: `success`
- GitHub Actions run: `24867413637`
  - Workflow: `Debian Packaging`
  - Branch: `main`
  - Result: `success`
- GitHub Actions run: `24867413693`
  - Workflow: `Main branch checks`
  - Branch: `main`
  - Result: `success`

Validated in CI:
- `dpkg-buildpackage -us -uc`
- `lintian`
- `autopkgtest`
- upstream test matrix on `main`

## Important Packaging Fixes Already Applied
### `mcpwn-red`
- explicit Debian autopkgtests instead of `autopkgtest-pkg-pybuild`
- Debian validation job builds and installs local `python3-mcp` first
- autopkgtest runs against the built `mcpwn-red` package plus the locally-built `python3-mcp`
- superficial autopkgtest exit code `8` is treated correctly in CI
- ethical-use notice on `stderr` is suppressed in Debian smoke tests so package validation is not marked as a test failure

### `python3-mcp-debian`
- fixed invalid `debian/tests/control` format
- replaced auto-generated pybuild autopkgtests with explicit Debian smoke tests
- Debian Packaging workflow accepts superficial autopkgtest exit code `8`
- `main` branch checks are now green

## Files Added Earlier For Submission Support
In `C:\Users\User\mcpwn-red\docs\parrot`:
- `guide.md`
- `new_tool_issue_mcpwn-red.md`
- `submission_email.md`
- `submission_email.eml`
- `debian_validation.md`
- `maintainer_responses.md`
- `RELEASE_FREEZE.md`
- `README.md`

These are the maintainer-facing and submission-support artifacts.

## What Is Still Not Done
These were the three requested follow-up tasks:

1. Fix the failing upstream `python3-mcp-debian` main-branch test matrix
- Status: done
- Evidence: run `24867413693` is green

2. Post a maintainer update on the Parrot issue saying Debian package validation is now complete
- Status: not confirmed in this handoff
- Recommended next action: post a concise update on work item `62`

Suggested comment:

```text
Update: Debian package validation is now complete in CI for both the submitted package and its packaging dependency path.

Completed successfully:
- mcpwn-red: dpkg-buildpackage -us -uc, lintian, autopkgtest
- python3-mcp packaging path: dpkg-buildpackage -us -uc, lintian, autopkgtest
- python3-mcp-debian main-branch checks are also green

Relevant runs:
- mcpwn-red CI: 24867412875
- python3-mcp-debian Debian Packaging (debian/packaging): 24867412770
- python3-mcp-debian Debian Packaging (main): 24867413637
- python3-mcp-debian Main branch checks (main): 24867413693

The remaining acceptance question is archive readiness and maintainer review, not whether the package recipes build and validate in Debian CI.
```

3. Prepare a Parrot-host validation runbook so the same process can be reproduced outside GitHub Actions
- Status: partial
- Existing file: `C:\Users\User\mcpwn-red\docs\parrot\debian_validation.md`
- Recommended next action: review and, if needed, extend that file with the exact dependency-first order:
  1. build `python3-mcp`
  2. install it locally on Parrot/Debian test host
  3. build `mcpwn-red`
  4. run `lintian`
  5. run `autopkgtest`

## Recommended Next Steps
1. Post the maintainer update on Parrot work item `62`.
2. Review `docs/parrot/debian_validation.md` and tighten it into a Parrot-host runbook if it does not already capture the exact dependency-first workflow.
3. Do not add product features now. The repo is in submission-freeze mode.
4. Keep focus on maintainer feedback and archive acceptance, not scope expansion.

## Constraints / Rules In Effect
- Product scope is frozen unless a maintainer asks for a change or a real bug is found.
- Do not add new modules or feature work during review.
- Packaging, CI, documentation, and maintainer-requested changes are allowed.

## Short Summary
The engineering blocker around Debian-native package validation has been cleared. The remaining work is maintainer communication and archive acceptance follow-through.
