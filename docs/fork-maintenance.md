# httpx Fork Maintenance

This fork tracks `projectdiscovery/httpx` `dev` and carries Stackray-specific scanner behavior on top.

## Upstream Sync

`.github/workflows/sync-upstream-dev.yml` runs every day and can also be started manually. It:

- fetches `projectdiscovery/httpx:dev`
- merges upstream into `automation/sync-upstream-dev`
- opens or updates a sync pull request in this fork
- builds `cmd/httpx`
- runs the Stackray contract tests
- runs `go test ./...` on Ubuntu, Windows, and macOS
- auto-merges the sync PR only when validation passes and the changed files are not risk-sensitive

Risk-sensitive upstream changes leave the sync PR open for review instead of auto-merging. The current risk patterns are:

- `runner/`
- `common/httpx/`
- `cmd/httpx/`
- `go.mod`
- `go.sum`
- file paths containing `wappalyzer`, `fingerprint`, `headless`, or `tech`

Failed or blocked syncs create or update an issue named `Upstream httpx sync blocked`.

## Stackray Update Flow

`.github/workflows/notify-stackray-scanner-update.yml` dispatches `httpx-dev-updated` to `CarlosCommits/stackray` after a push to this fork's `dev` branch.

That keeps Stackray scanner pin updates automated. Stackray still owns final acceptance through its own pull request checks, CI, and tests.

## Contract Tests

The Stackray contract tests live in `runner/stackray_contract_test.go`.

They protect the behavior Stackray depends on rather than only proving upstream `httpx` still compiles. The current contract verifies:

- `runner.Options` can execute the Stackray-style technology detection path
- custom Wappalyzer fingerprints merge into the embedded fingerprint set
- the scanner result includes the expected `tech` array
- JSONL output keeps the fields Stackray consumes, including `url`, `status_code`, and `tech`
- internal `TechnologyDetails` data remains excluded from JSONL output

Add new contract tests here when Stackray starts depending on new scanner output fields, flags, or runtime detection behavior.

## Patch Stack

Fork-specific behavior currently includes:

- headless technology detection via `-tdh` / `--tech-detect-headless`
- custom fingerprint loading via `-cff` / `--custom-fingerprint-file`
- merged custom and embedded Wappalyzer fingerprints
- browser/runtime evidence collection for React, Vite, and TanStack technologies
- same-origin browser artifact handling for script, header, DOM, and cookie evidence
- Stackray update dispatch when fork `dev` changes
- upstream sync automation with risk-sensitive review gates

When resolving upstream conflicts, start with the patch areas above. Most Stackray-specific scanner behavior is concentrated in `runner/`, especially `runner/headless.go`, `runner/wappalyzer.go`, `runner/options.go`, and `runner/runner.go`.

## Dashboard

`.github/workflows/fork-maintenance-dashboard.yml` updates a persistent issue named `httpx fork maintenance dashboard` every day. It records:

- fork `dev` SHA
- upstream `dev` SHA
- whether upstream is contained
- ahead and behind counts
- latest upstream sync run
- any open upstream sync PR
- any open blocked-sync issue
