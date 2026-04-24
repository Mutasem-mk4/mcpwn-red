# v0.1.0 - Initial Public Release (Parrot OS Submission Ready) 🛡️

We are excited to announce the first official release of `mcpwn-red`, an adversarial safety harness for the MCPwn AI pentesting execution engine. This release is optimized for security professionals and is currently under review for inclusion in the official Parrot OS repositories.

## 🚀 Key Features
- **YAML Injection Tester:** Detects tool-definition poisoning and metadata subversion.
- **Output Injection Simulator:** Validates isolation against exfiltration and instruction smuggling.
- **Container Boundary Checker:** Verifies Docker/Host isolation and environment variable protection.
- **Tool Scope Escalation:** Confirms logical boundaries between different tool categories (Recon, Exploit, etc.).
- **Rich Reporting:** Professional output in JSON, HTML, and Markdown formats.
- **Multi-Transport Support:** Connect over `stdio` or `SSE` using the official MCP SDK.

## 🛠️ Technical Highlights
- **Compliance:** Fully compliant with Debian and Parrot OS packaging standards.
- **Safety First:** All destructive operations are gated behind an explicit `--confirm-write` flag.
- **CI/CD:** Green across the board for Python 3.11/3.12 and Debian build validation.

## 📦 Installation
Available via PyPI:
```bash
pip install mcpwn-red
```
Or from source:
```bash
pip install .
```

## 📜 Full Documentation
See the [README.md](https://github.com/Mutasem-mk4/mcpwn-red/blob/main/README.md) for usage guides and security background.

---
*Developed by Mutasem Kharma. For authorized security testing only.*
