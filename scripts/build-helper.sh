#!/usr/bin/env bash
set -euo pipefail

VERSION_FILE="${VERSION_FILE:-./VERSION.txt}"
OUT="${1:-./build/com.clashfox.helper}"

if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "missing VERSION.txt file: ${VERSION_FILE}"
  exit 1
fi

VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"
if [[ -z "${VERSION}" ]]; then
  echo "empty version"
  exit 1
fi

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$(dirname "${OUT}")"

go build \
  -ldflags "-X main.appVersion=${VERSION} -X main.gitCommit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
  -o "${OUT}" \
  ./cmd/privileged-helper

echo "built ${OUT}"
echo "version=${VERSION} commit=${COMMIT} build_time=${BUILD_TIME}"
