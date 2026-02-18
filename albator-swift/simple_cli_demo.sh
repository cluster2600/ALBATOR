#!/bin/bash

set -euo pipefail

echo "Albator Swift - Simple CLI Demo"
echo "==============================="

if [[ ! -x ".build/release/Albator-Swift" ]]; then
  echo "Built CLI not found. Run ./build_swift_app.sh first"
  exit 1
fi

echo "Snapshot (text):"
./.build/release/Albator-Swift

echo ""
echo "Snapshot (json):"
./.build/release/Albator-Swift --json

echo ""
echo "Generating report..."
./.build/release/Albator-Swift --report

echo "Demo complete."
