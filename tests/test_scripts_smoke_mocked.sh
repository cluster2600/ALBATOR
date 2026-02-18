#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MOCK_BIN="$REPO_ROOT/tests/mocks/bin"

export PATH="$MOCK_BIN:$PATH"
export DRY_RUN=true
export MIN_MACOS_VERSION=26.3
export FIREWALL_CMD="socketfilterfw"

cd "$REPO_ROOT"

bash privacy.sh --dry-run >/tmp/albator_mock_privacy.log 2>&1
bash firewall.sh --dry-run >/tmp/albator_mock_firewall.log 2>&1
bash encryption.sh --dry-run >/tmp/albator_mock_encryption.log 2>&1
bash app_security.sh --dry-run >/tmp/albator_mock_appsec.log 2>&1

python3 albator_cli.py --json-output preflight --require-rules >/tmp/albator_mock_preflight.json
python3 albator_cli.py --json-output doctor >/tmp/albator_mock_doctor.json

echo "mocked_smoke_ok"
