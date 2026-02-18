#!/bin/bash

set -euo pipefail

VERSION_TAG="${1:-dev}"
OUTPUT_DIR="${2:-release}"
ARCH="$(uname -m)"

if ! command -v swift >/dev/null 2>&1; then
  echo "Swift is not installed or not in PATH"
  exit 1
fi

if [[ ! -f "Package.swift" ]]; then
  echo "Package.swift not found. Run from albator-swift directory."
  exit 1
fi

echo "Building release binaries for ${VERSION_TAG} (${ARCH})..."
swift build --configuration release --product Albator-Swift
swift build --configuration release --product Albator-SwiftGUI

mkdir -p "${OUTPUT_DIR}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

PACKAGE_DIR="albator-swift-${VERSION_TAG}-macos-${ARCH}"
STAGE_DIR="${WORK_DIR}/${PACKAGE_DIR}"
mkdir -p "${STAGE_DIR}"

cp .build/release/Albator-Swift "${STAGE_DIR}/"
cp .build/release/Albator-SwiftGUI "${STAGE_DIR}/"
cp README.md "${STAGE_DIR}/README.albator-swift.md"
if [[ -f "../LICENSE" ]]; then
  cp ../LICENSE "${STAGE_DIR}/LICENSE"
fi

cat > "${STAGE_DIR}/BUILD-INFO.txt" <<EOF
project=albator-swift
version_tag=${VERSION_TAG}
arch=${ARCH}
built_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

ARCHIVE_PATH="${OUTPUT_DIR}/${PACKAGE_DIR}.tar.gz"
tar -C "${WORK_DIR}" -czf "${ARCHIVE_PATH}" "${PACKAGE_DIR}"
shasum -a 256 "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"

echo "Release package created:"
echo "  ${ARCHIVE_PATH}"
echo "  ${ARCHIVE_PATH}.sha256"
