# Contributing to mcpwn-red 🛡️

First off, thank you for considering contributing to `mcpwn-red`! It's people like you that make it such a great tool for the security community.

## 🚀 Getting Started

### 1. Environment Setup
We use `hatch` and `pip` for development. We recommend using a virtual environment.

```bash
# Clone the repository
git clone https://github.com/Mutasem-mk4/mcpwn-red.git
cd mcpwn-red

# Install development dependencies
pip install -e ".[dev]"
```

### 2. Code Standards
We maintain high standards for code quality and security:
- **Linting:** We use `ruff` for linting and formatting.
- **Type Checking:** All code must be strictly typed using `mypy`.
- **Security:** Never commit secrets, API keys, or real client data. Ensure all destructive operations (like YAML writes) are gated behind `--confirm-write`.

## 🛠️ Development Workflow

### Running Tests
All contributions must pass the test suite:
```bash
pytest
```

### Linting and Type Checking
```bash
# Linting
ruff check .

# Type checking
mypy mcpwn_red
```

## 📋 Submission Process

1. **Check for existing issues:** Before starting work, check the [Issue Tracker](https://github.com/Mutasem-mk4/mcpwn-red/issues) to see if someone is already working on it.
2. **Open a Bug Report/Feature Request:** Use our [templates](.github/ISSUE_TEMPLATE/) to describe your change.
3. **Branching:** Create a feature branch (e.g., `feature/add-new-module`).
4. **Pull Request:** Open a PR using our [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).

## 🛡️ Security & Scope

`mcpwn-red` is a defensive tool. Contributions should focus on:
- Improving protocol correctness (MCP/SSE/stdio).
- Enhancing test coverage and edge-case handling.
- Strengthening operator-safety boundaries.
- Improving packaging and distro-native compatibility (Parrot/Debian).

## ⚖️ License
By contributing, you agree that your contributions will be licensed under the project's **GPL-3.0-only** license.
