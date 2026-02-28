#!/usr/bin/env bash
set -euo pipefail

VERSION_FILE="${VERSION_FILE:-./VERSION}"
REL_DIR="${REL_DIR:-./release}"
STAGE_DIR="${REL_DIR}/stage"

if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "missing VERSION file: ${VERSION_FILE}"
  exit 1
fi

VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"
if [[ -z "${VERSION}" ]]; then
  echo "empty version"
  exit 1
fi

mkdir -p "${REL_DIR}" "${STAGE_DIR}"
rm -rf "${STAGE_DIR}"/*

# Build binary first.
GOCACHE=/tmp/go-build-cache bash scripts/build-helper.sh "${STAGE_DIR}/com.clashfox.helper"

# Resolve changelog path for backward compatibility.
CHANGELOG_SRC=""
if [[ -f "docs/CHANGELOG.md" ]]; then
  CHANGELOG_SRC="docs/CHANGELOG.md"
elif [[ -f "CHANGELOG.md" ]]; then
  CHANGELOG_SRC="CHANGELOG.md"
else
  echo "missing changelog: docs/CHANGELOG.md or CHANGELOG.md"
  exit 1
fi

# Copy runtime assets.
cp deploy/com.clashfox.helper.plist "${STAGE_DIR}/"
cp scripts/install-helper.sh "${STAGE_DIR}/"
cp scripts/uninstall-helper.sh "${STAGE_DIR}/"
cp README.md "${STAGE_DIR}/"
cp LICENSE "${STAGE_DIR}/"
cp "${CHANGELOG_SRC}" "${STAGE_DIR}/CHANGELOG.md"

# Generate checksums.
(
  cd "${STAGE_DIR}"
  shasum -a 256 com.clashfox.helper com.clashfox.helper.plist install-helper.sh uninstall-helper.sh README.md LICENSE CHANGELOG.md > checksums.txt
)

BUILD_META="$("${STAGE_DIR}/com.clashfox.helper" --version)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "${STAGE_DIR}/manifest.json" <<JSON
{
  "name": "clashfox-helper",
  "version": "${VERSION}",
  "platform": "darwin",
  "arch": "$(uname -m)",
  "packagedAt": "${BUILD_TIME}",
  "build": ${BUILD_META}
}
JSON

TARBALL="${REL_DIR}/clashfox-helper-v${VERSION}-darwin-$(uname -m).tar.gz"
(
  cd "${STAGE_DIR}"
  tar -czf "../$(basename "${TARBALL}")" \
    com.clashfox.helper \
    com.clashfox.helper.plist \
    install-helper.sh \
    uninstall-helper.sh \
    checksums.txt \
    manifest.json \
    README.md \
    CHANGELOG.md \
    LICENSE
)

# Top-level checksum for tarball.
shasum -a 256 "${TARBALL}" > "${TARBALL}.sha256"

echo "release package ready: ${TARBALL}"
echo "sha256 file: ${TARBALL}.sha256"
