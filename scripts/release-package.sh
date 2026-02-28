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

# Generate changelog from git history (no local docs dependency).
LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
CHANGELOG_OUT="${STAGE_DIR}/CHANGELOG.md"
{
  echo "# Changelog"
  echo
  echo "## ${VERSION} - $(date -u +%Y-%m-%d)"
  echo
  echo "### Commits"
  if [[ -n "${LAST_TAG}" ]]; then
    git log --pretty=format:'- %h %s' "${LAST_TAG}..HEAD" || true
  else
    git log --pretty=format:'- %h %s' -n 50 || true
  fi
} > "${CHANGELOG_OUT}"

# Avoid empty changelog when history is not available in CI edge cases.
if ! grep -q "^- " "${CHANGELOG_OUT}"; then
  {
    echo
    echo "- automated release package"
  } >> "${CHANGELOG_OUT}"
fi

# Copy runtime assets.
cp deploy/com.clashfox.helper.plist "${STAGE_DIR}/"
cp scripts/install-helper.sh "${STAGE_DIR}/"
cp scripts/uninstall-helper.sh "${STAGE_DIR}/"
cp README.md "${STAGE_DIR}/"
cp LICENSE "${STAGE_DIR}/"

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
