#!/bin/bash

set -euo pipefail

echo "Building Albator Swift targets..."

if ! command -v swift >/dev/null 2>&1; then
  echo "Swift is not installed or not in PATH"
  exit 1
fi

if [[ ! -f "Package.swift" ]]; then
  echo "Package.swift not found. Run from albator-swift directory."
  exit 1
fi

swift build --configuration release --product Albator-Swift
swift build --configuration release --product Albator-SwiftGUI

DIST_DIR="dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

cp .build/release/Albator-Swift "$DIST_DIR/"
cp .build/release/Albator-SwiftGUI "$DIST_DIR/"

ZIP_NAME="Albator-Swift-$(date +%Y%m%d-%H%M%S).zip"
(
  cd "$DIST_DIR"
  zip "../$ZIP_NAME" Albator-Swift Albator-SwiftGUI >/dev/null
)

echo "Build completed."
echo "  CLI: .build/release/Albator-Swift"
echo "  GUI: .build/release/Albator-SwiftGUI"
echo "  Dist zip: $ZIP_NAME"
