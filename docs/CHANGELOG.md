# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-02-28

### Added
- Root privileged helper service via launchd.
- Local unix-socket API with token authentication.
- Caller policy guard (`uid/pid/path`) and audit logs.
- Strict command allowlist for `networksetup`, `sysctl`, `pfctl`.
- Proxy/DNS/TUN transaction handling with rollback.
- Drift self-healing loop and baseline restore endpoint.
- Core management API:
  - `POST /v1/core/start`
  - `POST /v1/core/stop`
  - `POST /v1/core/restart`
  - `GET /v1/core/status`
  - `POST /v1/core/reload`
  - `POST /v1/core/config/validate`
  - `POST /v1/core/switch`
- Versioning support:
  - `VERSION` source file
  - `scripts/build-helper.sh` with ldflags metadata
  - `GET /v1/version` and `--version`
  - install-time `version.json` + `version-history.log`

### Security
- Rate limiting and circuit breaker for caller abuse control.
- Candidate binary integrity validation via SHA256 for core switch.
- PID record upgraded to structured format (`pid+binary+startedAt`) to reduce PID reuse risk.

### Ops
- Atomic install with rollback.
- Safe uninstall with pre-uninstall baseline restore.
- Compatibility smoke script with parser regression checks.
