# Release Checklist

## 0. Pre-check
1. Confirm version in `VERSION`.
2. Confirm release notes in `CHANGELOG.md`.
3. Run tests:
   - `GOCACHE=/tmp/go-build-cache go test ./cmd/privileged-helper`
   - `bash scripts/compat-smoke.sh`

## 1. Build artifacts
1. Build helper:
   - `GOCACHE=/tmp/go-build-cache bash scripts/build-helper.sh ./build/com.clashfox.helper`
2. Verify build metadata:
   - `./build/com.clashfox.helper --version`

## 2. Package
1. Run package script:
   - `bash scripts/release-package.sh`
2. Check outputs in `release/`:
   - `com.clashfox.helper` binary
   - `checksums.txt`
   - `manifest.json`
   - `clashfox-helper-v<version>-darwin-universal.tar.gz`

## 3. Install test (local)
1. `sudo bash scripts/install-helper.sh ./build/com.clashfox.helper`
2. Health/API smoke test via socket.
3. Core management smoke test (`start/status/reload/stop`).
4. `sudo bash scripts/uninstall-helper.sh`

## 4. Tag & publish
1. Create git tag: `v<version>`.
2. Attach tarball + checksums + changelog section to release.
3. Keep install notes and directory semantics in release description:
   - `meta-backup`: zashboard download artifacts only.
   - `cfox-backup`: GUI switch candidates + old-core backups.
   - `core`: active running mihomo.
