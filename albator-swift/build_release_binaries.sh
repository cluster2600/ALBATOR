#!/bin/bash

set -euo pipefail

VERSION_TAG="${1:-dev}"
OUTPUT_DIR="${2:-release}"
ARCH="$(uname -m)"

# Codesigning identity (Developer ID Application)
# Set via environment or fall back to ad-hoc
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"

# Notarisation credentials (optional — skipped if not set)
NOTARY_APPLE_ID="${NOTARY_APPLE_ID:-}"
NOTARY_TEAM_ID="${NOTARY_TEAM_ID:-}"
NOTARY_PASSWORD="${NOTARY_PASSWORD:-}"

if ! command -v swift >/dev/null 2>&1; then
  echo "Swift is not installed or not in PATH"
  exit 1
fi

if [[ ! -f "Package.swift" ]]; then
  echo "Package.swift not found. Run from albator-swift directory."
  exit 1
fi

echo "==> Building release binaries for ${VERSION_TAG} (${ARCH})..."
swift build --configuration release --product Albator-Swift
swift build --configuration release --product Albator-SwiftGUI

mkdir -p "${OUTPUT_DIR}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

PACKAGE_DIR="albator-swift-${VERSION_TAG}-macos-${ARCH}"
STAGE_DIR="${WORK_DIR}/${PACKAGE_DIR}"
mkdir -p "${STAGE_DIR}"

CLI_BIN=".build/release/Albator-Swift"
GUI_BIN=".build/release/Albator-SwiftGUI"
CLI_ENTITLEMENTS="entitlements/cli.entitlements"
GUI_ENTITLEMENTS="entitlements/gui.entitlements"

# --- Codesign with hardened runtime ---
echo "==> Codesigning binaries (identity: ${CODESIGN_IDENTITY})..."

codesign --force --options runtime \
  --entitlements "${CLI_ENTITLEMENTS}" \
  --sign "${CODESIGN_IDENTITY}" \
  --timestamp \
  "${CLI_BIN}"

codesign --force --options runtime \
  --entitlements "${GUI_ENTITLEMENTS}" \
  --sign "${CODESIGN_IDENTITY}" \
  --timestamp \
  "${GUI_BIN}"

echo "==> Verifying signatures..."
codesign --verify --deep --strict "${CLI_BIN}"
codesign --verify --deep --strict "${GUI_BIN}"

cp "${CLI_BIN}" "${STAGE_DIR}/"
cp "${GUI_BIN}" "${STAGE_DIR}/"
cp README.md "${STAGE_DIR}/README.albator-swift.md"
if [[ -f "../LICENSE" ]]; then
  cp ../LICENSE "${STAGE_DIR}/LICENSE"
fi

cat > "${STAGE_DIR}/BUILD-INFO.txt" <<EOF
project=albator-swift
version_tag=${VERSION_TAG}
arch=${ARCH}
built_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
codesign_identity=${CODESIGN_IDENTITY}
notarised=$(if [[ -n "${NOTARY_APPLE_ID}" ]]; then echo "yes"; else echo "no"; fi)
EOF

ARCHIVE_PATH="${OUTPUT_DIR}/${PACKAGE_DIR}.tar.gz"
tar -C "${WORK_DIR}" -czf "${ARCHIVE_PATH}" "${PACKAGE_DIR}"

# --- Notarisation ---
if [[ -n "${NOTARY_APPLE_ID}" && -n "${NOTARY_TEAM_ID}" && -n "${NOTARY_PASSWORD}" ]]; then
  echo "==> Submitting archive for notarisation..."

  # Notarytool needs a ZIP for submission — create a temporary one
  NOTARY_ZIP="${WORK_DIR}/notarize.zip"
  ditto -c -k --keepParent "${STAGE_DIR}" "${NOTARY_ZIP}"

  xcrun notarytool submit "${NOTARY_ZIP}" \
    --apple-id "${NOTARY_APPLE_ID}" \
    --team-id "${NOTARY_TEAM_ID}" \
    --password "${NOTARY_PASSWORD}" \
    --wait \
    --timeout 15m

  echo "==> Notarisation complete."

  # Staple the individual binaries (optional — works for .app bundles,
  # command-line tools benefit from the notarisation ticket being cached
  # by Apple's servers so Gatekeeper checks pass on first launch)
  xcrun stapler staple "${STAGE_DIR}/Albator-Swift" 2>/dev/null || echo "  (staple skipped for CLI — not a bundle)"
  xcrun stapler staple "${STAGE_DIR}/Albator-SwiftGUI" 2>/dev/null || echo "  (staple skipped for GUI — not a bundle)"

  # Recreate the archive with notarised binaries
  rm -f "${ARCHIVE_PATH}"
  tar -C "${WORK_DIR}" -czf "${ARCHIVE_PATH}" "${PACKAGE_DIR}"
else
  echo "==> Skipping notarisation (NOTARY_APPLE_ID not set)"
fi

# Checksum
shasum -a 256 "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"

echo ""
echo "Release package created:"
echo "  ${ARCHIVE_PATH}"
echo "  ${ARCHIVE_PATH}.sha256"
echo ""
echo "Codesign identity: ${CODESIGN_IDENTITY}"
if [[ -n "${NOTARY_APPLE_ID}" ]]; then
  echo "Notarised: yes (Apple ID: ${NOTARY_APPLE_ID})"
else
  echo "Notarised: no"
  echo ""
  echo "To enable notarisation, set these environment variables:"
  echo "  CODESIGN_IDENTITY  — Developer ID Application certificate name"
  echo "  NOTARY_APPLE_ID    — Apple ID email"
  echo "  NOTARY_TEAM_ID     — 10-character Team ID"
  echo "  NOTARY_PASSWORD     — App-specific password (generate at appleid.apple.com)"
fi
