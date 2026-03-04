#!/usr/bin/env bash
set -euo pipefail

VERSION_FILE="${VERSION_FILE:-./VERSION}"
REL_DIR="${REL_DIR:-./release}"
WORK_DIR="${REL_DIR}/work"

if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "missing VERSION file: ${VERSION_FILE}"
  exit 1
fi

VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"
if [[ -z "${VERSION}" ]]; then
  echo "empty version"
  exit 1
fi

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "${REL_DIR}" "${WORK_DIR}"
rm -rf "${WORK_DIR}"/*

build_binary() {
  local arch="$1"
  local out="$2"

  GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 \
  go build \
    -ldflags "-X main.appVersion=${VERSION} -X main.gitCommit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
    -o "${out}" \
    ./cmd/privileged-helper
}

# Build per-arch binaries.
X86_BIN="${WORK_DIR}/com.clashfox.helper.x86_64"
ARM_BIN="${WORK_DIR}/com.clashfox.helper.arm64"
UNI_BIN="${WORK_DIR}/com.clashfox.helper.universal"

GOCACHE=/tmp/go-build-cache build_binary "amd64" "${X86_BIN}"
GOCACHE=/tmp/go-build-cache build_binary "arm64" "${ARM_BIN}"

# Create universal binary.
lipo -create -output "${UNI_BIN}" "${X86_BIN}" "${ARM_BIN}"

LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"

gen_changelog() {
  local out="$1"
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
  } > "${out}"

  if ! grep -q "^- " "${out}"; then
    {
      echo
      echo "- automated release package"
    } >> "${out}"
  fi
}

make_variant() {
  local variant="$1"
  local bin_src="$2"
  local stage_dir tarball manifest_arch build_meta

  stage_dir="${REL_DIR}/stage-${variant}"
  rm -rf "${stage_dir}"
  mkdir -p "${stage_dir}"

  cp "${bin_src}" "${stage_dir}/com.clashfox.helper"
  chmod 755 "${stage_dir}/com.clashfox.helper"
  cp deploy/com.clashfox.helper.plist "${stage_dir}/"
  cp scripts/install-helper.sh "${stage_dir}/"
  cp scripts/uninstall-helper.sh "${stage_dir}/"
  cp scripts/doctor-helper.sh "${stage_dir}/"
  cp scripts/check-helper.sh "${stage_dir}/"
  cp VERSION "${stage_dir}/"
  cp README.md "${stage_dir}/"
  gen_changelog "${stage_dir}/CHANGELOG.md"

  (
    cd "${stage_dir}"
    shasum -a 256 com.clashfox.helper com.clashfox.helper.plist install-helper.sh uninstall-helper.sh doctor-helper.sh check-helper.sh VERSION README.md CHANGELOG.md > checksums.txt
  )

  build_meta="{\"version\":\"${VERSION}\",\"gitCommit\":\"${COMMIT}\",\"buildTime\":\"${BUILD_TIME}\",\"launchedAt\":\"\"}"

  manifest_arch="${variant}"
  cat > "${stage_dir}/manifest.json" <<JSON
{
  "name": "clashfox-helper",
  "version": "${VERSION}",
  "platform": "darwin",
  "arch": "${manifest_arch}",
  "packagedAt": "${BUILD_TIME}",
  "build": ${build_meta}
}
JSON

  tarball="${REL_DIR}/clashfox-helper-v${VERSION}-darwin-${variant}.tar.gz"
  (
    cd "${stage_dir}"
    tar -czf "../$(basename "${tarball}")" \
      com.clashfox.helper \
      com.clashfox.helper.plist \
      install-helper.sh \
      uninstall-helper.sh \
      doctor-helper.sh \
      check-helper.sh \
      VERSION \
      checksums.txt \
      manifest.json \
      README.md \
      CHANGELOG.md
  )

  echo "release package ready: ${tarball}"
}

make_variant "x86_64" "${X86_BIN}"
make_variant "arm64" "${ARM_BIN}"
make_variant "universal" "${UNI_BIN}"

# Keep work dir only when explicitly requested.
if [[ "${KEEP_WORK:-0}" != "1" ]]; then
  rm -rf "${WORK_DIR}"
fi
