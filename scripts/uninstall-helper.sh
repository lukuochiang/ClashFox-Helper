#!/usr/bin/env bash
set -euo pipefail

echo "======================================"
echo "  ClashFox Helper Uninstall Script"
echo "======================================"

LABEL="com.clashfox.helper"
BIN_DST="/Library/PrivilegedHelperTools/${LABEL}"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
APP_BUNDLE_PATH="${CLASHFOX_APP_PATH:-/Applications/ClashFox.app}"
APP_HELPER_DIR="${CLASHFOX_HELPER_DIR:-${APP_BUNDLE_PATH}/Contents/Resources/helper}"
VERSION_META="/Library/Application Support/ClashFox/helper/version.json"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo $0"
  exit 1
fi

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  launchctl bootout system "${PLIST_DST}" || true
fi

if [[ -f "${PLIST_DST}" ]]; then
  rm -f "${PLIST_DST}"
fi
if [[ -f "${BIN_DST}" ]]; then
  rm -f "${BIN_DST}"
fi
if [[ -f "/var/run/${LABEL}.sock" ]]; then
  rm -f "/var/run/${LABEL}.sock"
fi

echo "uninstalled: ${LABEL}"
if [[ -f "${VERSION_META}" ]]; then
  echo "last installed version meta:"
  cat "${VERSION_META}"
fi
