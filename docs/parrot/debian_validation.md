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

## 2. Validate and Install `python3-mcp` first

The `mcpwn-red` package depends on `python3-mcp`. Since `python3-mcp` is also a 
newly submitted package, you must build and install it locally first to 
validate the full dependency path.

### Build `python3-mcp`

```bash
cd /path/to/python3-mcp-debian
dpkg-buildpackage -us -uc
```

### Run Validation

```bash
lintian ../python-mcp_1.27.0-1_*.changes
autopkgtest . -- null
```

### Local Installation for Follow-on Validation

Install the locally built package so `mcpwn-red` can find it during its own 
validation:

```bash
sudo apt-get install ../python3-mcp_1.27.0-1_all.deb
```

## 3. Validate `mcpwn-red`

Once the local `python3-mcp` is installed, proceed with `mcpwn-red`:

```bash
cd /path/to/mcpwn-red
dpkg-buildpackage -us -uc
lintian ../mcpwn-red_0.1.0-1_*.changes
autopkgtest . -- null
```

## 4. Known Validation Quirks

### Autopkgtest Exit Code 8
In some environments, `autopkgtest` may exit with code `8` (no tests found or 
skipped) if it only runs superficial smoke tests. This should be treated as 
success if the smoke tests actually executed as intended.

### Ethical-use Notice on Stderr
`mcpwn-red` prints an ethical-use notice to `stderr` on startup. In some 
Debian-native test environments, any output to `stderr` during a test is 
flagged as a failure. The project's CI suppresses this in smoke tests to 
ensure validation is not blocked by informational safety headers.

## 5. What to attach in maintainer discussion

When reporting back to Parrot maintainers, include:

- exact distro and version used
- whether validation ran on Debian or Parrot
- `dpkg-buildpackage` result
- `lintian` result
- `autopkgtest` result
- any dependency gaps discovered during install

## 6. Decision rule

Do not claim archive-readiness until both of these are true:

1. `python3-mcp` dependency path is resolved and validated
2. Debian or Parrot native validation succeeded or maintainers explicitly
   accepted remaining gaps
