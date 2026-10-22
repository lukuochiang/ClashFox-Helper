# Changelog

All notable changes to ClashFox Helper are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.1] - 2026-10-22

### Fixed
- **Helper token was unreadable by the GUI process.** `install-helper.sh` and
  `doctor-helper.sh` granted the console user read access on the auth token with
  `chmod +a "user:<uid> allow read"`, passing a **numeric UID**. macOS rejects this
  (`Unable to translate '<uid>' to a UUID`) and the failure was swallowed by
  `|| true`, so the token ended up `root:wheel 0600` with **no read ACL**. The GUI
  process could not read the token → `token_missing` → the app reported
  *"Helper installed (unreachable)"* / `helper_unavailable`. The grant now resolves
  the account name via `id -un` and uses `chmod +a "user:<name> allow read"`.
- **Fresh installs left `debug-config.json` at `enableConsoleCurl=false`.** The
  ClashFox client reaches the helper through `/usr/bin/curl` over the unix socket,
  so the caller path the helper authenticates is `/usr/bin/curl`, which the hardened
  default policy does not trust. This caused `FORBIDDEN_CALLER` even with a readable
  token. `install-helper.sh` (and the `doctor-helper.sh --repair` path) now lay down
  the documented runtime config (`enableConsoleCurl: true` + `/usr/bin/curl` prefix,
  matching `docs/debug-config.json`) when the file is missing; an existing,
  operator-edited file is left untouched.

## [0.4.0]

Initial tagged release of this changelog. See git tag `v0.4.0`.
