# Debian and Parrot Validation Runbook

This runbook covers the remaining distro-native validation that should be run
for both `mcpwn-red` and the follow-on `python3-mcp` dependency packaging.

## 1. Prepare a Debian or Parrot host

Use a real Debian or Parrot machine, VM, or clean build environment. The key
requirement is that it provides normal Debian packaging tools rather than a
Windows-hosted approximation.

Install the common packaging toolchain:

```bash
sudo apt-get update
sudo apt-get install -y \
  autopkgtest \
  debhelper \
  devscripts \
  dh-python \
  lintian \
  pybuild-plugin-pyproject \
  python3-all \
  python3-build \
  python3-hatchling
```

## 2. Validate `python3-mcp` first

The `mcpwn-red` package depends on `python3-mcp`, so validate that dependency
before treating `mcpwn-red` as archive-ready.

Expected extra runtime/build dependencies for `python3-mcp` include:

```bash
sudo apt-get install -y \
  python3-anyio \
  python3-httpx \
  python3-httpx-sse \
  python3-jsonschema \
  python3-jwt \
  python3-multipart \
  python3-pydantic \
  python3-pydantic-settings \
  python3-sse-starlette \
  python3-starlette \
  python3-typer \
  python3-typing-extensions \
  python3-typing-inspection \
  python3-uvicorn \
  python3-websockets
```

Run:

```bash
cd /path/to/python3-mcp-debian
dpkg-buildpackage -us -uc
lintian ../python-mcp_1.27.0-1_*.changes
autopkgtest . -- null
```

If `python3-typing-inspection` is not available in the target archive, stop
there and resolve that dependency first.

## 3. Validate `mcpwn-red`

Once `python3-mcp` is available in the target archive or local test
environment, install the `mcpwn-red` package dependencies:

```bash
sudo apt-get install -y \
  python3-click \
  python3-httpx \
  python3-jinja2 \
  python3-mcp \
  python3-pydantic \
  python3-rich \
  python3-yaml
```

Run:

```bash
cd /path/to/mcpwn-red
python3 -m build
dpkg-buildpackage -us -uc
lintian ../mcpwn-red_0.1.0-1_*.changes
autopkgtest . -- null
```

## 4. What to attach in maintainer discussion

When reporting back to Parrot maintainers, include:

- exact distro and version used
- whether validation ran on Debian or Parrot
- `dpkg-buildpackage` result
- `lintian` result
- `autopkgtest` result
- any dependency gaps discovered during install

## 5. Decision rule

Do not claim archive-readiness until both of these are true:

1. `python3-mcp` dependency path is resolved
2. Debian or Parrot native validation succeeded or maintainers explicitly
   accepted remaining gaps
