#!/usr/bin/env bash
set -euo pipefail

LABEL="com.clashfox.helper"
BIN_SRC="${1:-./build/com.clashfox.helper}"
VERSION_IN="${2:-}"
BIN_DST="/Library/PrivilegedHelperTools/${LABEL}"
PLIST_SRC="./deploy/${LABEL}.plist"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"
TOKEN_DIR="/Library/Application Support/ClashFox/helper"
RELEASE_DIR="${TOKEN_DIR}/releases"
VERSION_META="${TOKEN_DIR}/version.json"
HISTORY_LOG="${TOKEN_DIR}/version-history.log"

SUCCESS=0
BIN_BAK=""
PLIST_BAK=""

rollback() {
  if [[ "${SUCCESS}" -eq 1 ]]; then
    return
  fi

  echo "install failed, rolling back..."

  if [[ -n "${BIN_BAK}" && -f "${BIN_BAK}" ]]; then
    cp -f "${BIN_BAK}" "${BIN_DST}"
    chown root:wheel "${BIN_DST}"
    chmod 755 "${BIN_DST}"
  else
    rm -f "${BIN_DST}"
  fi

  if [[ -n "${PLIST_BAK}" && -f "${PLIST_BAK}" ]]; then
    cp -f "${PLIST_BAK}" "${PLIST_DST}"
    chown root:wheel "${PLIST_DST}"
    chmod 644 "${PLIST_DST}"
  else
    rm -f "${PLIST_DST}"
  fi

  if [[ -f "${PLIST_DST}" ]]; then
    launchctl bootstrap system "${PLIST_DST}" || true
    launchctl enable "system/${LABEL}" || true
    launchctl kickstart -k "system/${LABEL}" || true
  fi
}
trap rollback EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo $0 [binary-path]"
  exit 1
fi

if [[ ! -f "${BIN_SRC}" ]]; then
  echo "binary not found: ${BIN_SRC}"
  exit 1
fi
if [[ ! -f "${PLIST_SRC}" ]]; then
  echo "plist not found: ${PLIST_SRC}"
  exit 1
fi

if [[ -n "${VERSION_IN}" ]]; then
  VERSION="${VERSION_IN}"
elif [[ -f "./VERSION" ]]; then
  VERSION="$(tr -d '[:space:]' < ./VERSION)"
else
  VERSION="unknown"
fi

mkdir -p "/Library/PrivilegedHelperTools" "/Library/LaunchDaemons" "${TOKEN_DIR}" "${RELEASE_DIR}"
chmod 700 "${TOKEN_DIR}"

if [[ -f "${BIN_DST}" ]]; then
  BIN_BAK="$(mktemp /tmp/${LABEL}.bin.bak.XXXXXX)"
  cp -f "${BIN_DST}" "${BIN_BAK}"
  TS="$(date +%Y%m%d-%H%M%S)"
  cp -f "${BIN_DST}" "${RELEASE_DIR}/${TS}-prev-${LABEL}" || true
fi
if [[ -f "${PLIST_DST}" ]]; then
  PLIST_BAK="$(mktemp /tmp/${LABEL}.plist.bak.XXXXXX)"
  cp -f "${PLIST_DST}" "${PLIST_BAK}"
fi

BIN_TMP="${BIN_DST}.new.$$"
PLIST_TMP="${PLIST_DST}.new.$$"
cp -f "${BIN_SRC}" "${BIN_TMP}"
cp -f "${PLIST_SRC}" "${PLIST_TMP}"
chown root:wheel "${BIN_TMP}" "${PLIST_TMP}"
chmod 755 "${BIN_TMP}"
chmod 644 "${PLIST_TMP}"

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  launchctl bootout system "${PLIST_DST}" || true
fi

mv -f "${BIN_TMP}" "${BIN_DST}"
mv -f "${PLIST_TMP}" "${PLIST_DST}"

if [[ -f "/var/run/${LABEL}.sock" ]]; then
  rm -f "/var/run/${LABEL}.sock"
fi

launchctl bootstrap system "${PLIST_DST}"
launchctl enable "system/${LABEL}"
launchctl kickstart -k "system/${LABEL}"

BIN_SHA="$(shasum -a 256 "${BIN_DST}" | awk '{print $1}')"
INSTALLED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "${VERSION_META}" <<EOF
{
  "label": "${LABEL}",
  "version": "${VERSION}",
  "installedAt": "${INSTALLED_AT}",
  "binaryPath": "${BIN_DST}",
  "binarySha256": "${BIN_SHA}"
}
EOF
chmod 600 "${VERSION_META}"
echo "${INSTALLED_AT} version=${VERSION} sha256=${BIN_SHA}" >> "${HISTORY_LOG}"

# Keep only the newest 10 binary backups.
ls -1t "${RELEASE_DIR}" 2>/dev/null | sed -n '11,$p' | while IFS= read -r old; do
  rm -f "${RELEASE_DIR}/${old}"
done

SUCCESS=1
echo "installed and started: ${LABEL} version=${VERSION}"
