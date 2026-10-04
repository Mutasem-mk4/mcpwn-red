# Submission Freeze Policy

This project is under submission freeze for Parrot review.

The goal during this phase is not to expand functionality. The goal is to
reduce maintainer risk and close packaging and validation gaps.

## Allowed changes

- packaging fixes
- dependency fixes
- Debian metadata fixes
- CI fixes
- test fixes for existing behavior
- documentation clarifications
- manpage updates
- typo and safety wording fixes
- maintainer-requested changes
- bug fixes that do not expand scope
- validation artifacts and runbooks

## Disallowed changes

- new features
- new attack modules
- new CLI commands
- output format changes
- scan logic changes
- renamed files, commands, or packages
- branding churn
- README rewrites that change project positioning
- refactors without a packaging or bug-fix reason
- new dependencies unless strictly required

## Decision rule

Before making a change, ask:

1. Does this reduce maintainer risk?
2. Is this required for packaging, validation, or a real bug?
3. Can it be justified in one sentence to a distro maintainer?

If any answer is no, the change should wait until after submission review.

## Current priority order

1. `python3-mcp` archive readiness
2. Debian or Parrot native validation
3. maintainer feedback
4. only then product evolution

## Working rule

Treat `main` and `parrot/submission-clean` as review branches, not
experimentation branches.
