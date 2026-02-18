#!/bin/bash

set -euo pipefail

echo "Albator Swift - Demo"
echo "===================="

if [[ ! -x ".build/release/Albator-Swift" ]]; then
  echo "CLI binary missing. Run ./build_swift_app.sh first"
  exit 1
fi

if [[ ! -x ".build/release/Albator-SwiftGUI" ]]; then
  echo "GUI binary missing. Run ./build_swift_app.sh first"
  exit 1
fi

echo "1) CLI health"
./.build/release/Albator-Swift --json | head -n 30

echo ""
echo "2) CLI report generation"
./.build/release/Albator-Swift --report

echo ""
echo "3) GUI launch smoke (5s timeout)"
if command -v timeout >/dev/null 2>&1; then
  timeout 5s ./.build/release/Albator-SwiftGUI >/dev/null 2>&1 || true
else
  ./.build/release/Albator-SwiftGUI >/dev/null 2>&1 &
  GUI_PID=$!
  sleep 5
  kill "$GUI_PID" >/dev/null 2>&1 || true
fi

echo "GUI smoke completed"
