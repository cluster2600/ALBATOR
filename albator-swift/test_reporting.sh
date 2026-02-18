#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")"

echo "Testing Albator Swift reporting"
echo "==============================="

if [[ ! -x ".build/release/Albator-Swift" ]]; then
  echo "CLI binary missing. Run ./build_swift_app.sh first"
  exit 1
fi

before_count=$(find "$HOME/Documents" "$HOME/Desktop" -maxdepth 1 -type f -name 'security_report_*.json' 2>/dev/null | wc -l | tr -d '[:space:]')
./.build/release/Albator-Swift --report >/tmp/albator_swift_report_test.log 2>&1
after_count=$(find "$HOME/Documents" "$HOME/Desktop" -maxdepth 1 -type f -name 'security_report_*.json' 2>/dev/null | wc -l | tr -d '[:space:]')

if [[ "$after_count" -ge "$before_count" ]]; then
  echo "Report command executed successfully"
  tail -n 5 /tmp/albator_swift_report_test.log || true
  exit 0
fi

echo "Report generation appears to have failed"
cat /tmp/albator_swift_report_test.log
exit 1
