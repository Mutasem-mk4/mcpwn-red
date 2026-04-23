# Contributing

## Scope

`mcpwn-red` is intended for defensive validation of MCPwn deployments. Contributions should improve protocol correctness, packaging, test coverage, and operator safety.

## Requirements

- Keep the CLI non-destructive by default.
- Preserve the `--confirm-write` guard on YAML poisoning tests.
- Add or update tests for every behavior change.
- Keep network access mocked in the test suite.

## Submission

1. Run `ruff check .`
2. Run `mypy mcpwn_red`
3. Run `pytest`
4. Include a clear note if a change alters evidence strings or report formats

