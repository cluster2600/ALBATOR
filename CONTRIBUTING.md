# Contributing to Albator

Thanks for taking the time to contribute.

## Quick start

1. Fork the repository
2. Create a feature branch from `main`
3. Make changes with tests
4. Open a pull request

## Development setup

Requirements:

- macOS
- Python 3.8+
- `bash`
- `shellcheck`

Install Python dependencies:

```bash
pip3 install -r requirements.txt
```

## Running checks locally

### Shell scripts

Static analysis:

```bash
shellcheck -S error $(find . -name '*.sh')
```

Syntax check:

```bash
find . -name '*.sh' -exec bash -n {} \;
```

### Python

Core unit tests:

```bash
python3 -m unittest tests/test_core_behaviors.py -v
```

Integration-style checks (some tests are privileged or mutating):

```bash
python3 tests/test_framework.py --verbose
python3 tests/test_framework.py --verbose --include-privileged
python3 tests/test_framework.py --verbose --include-mutating
```

## Guidelines

- Prefer small, focused PRs.
- Keep scripts idempotent: re-running a hardening script should result in a clean no-op.
- Avoid breaking non-interactive flows: scripts must fail gracefully when required tools are missing.
- Security: do not introduce network calls without an opt-out/offline mode.
- Logging: keep log output stable; prefer machine-readable formats when adding new outputs.

## Reporting security issues

Please see `SECURITY.md`.
