#!/usr/bin/env bash
set -euo pipefail

OS_VER="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
OS_MAJOR="${OS_VER%%.*}"

echo "Detected macOS: ${OS_VER}"

if [[ "${OS_VER}" == "unknown" ]]; then
  echo "sw_vers not available"
  exit 1
fi

if [[ "${OS_MAJOR}" -lt 12 ]]; then
  echo "Unsupported target for this helper test plan (requires macOS 12+)"
  exit 1
fi

echo "Running parser regression tests (covers macOS 12 style outputs)..."
GOCACHE=/tmp/go-build-cache go test ./cmd/privileged-helper -run 'Parse' -count=1

echo "Checking system command availability..."
for bin in /usr/sbin/networksetup /usr/sbin/sysctl /sbin/pfctl; do
  if [[ ! -x "${bin}" ]]; then
    echo "missing required binary: ${bin}"
    exit 1
  fi
  echo "ok: ${bin}"
done

echo "compat smoke passed"
