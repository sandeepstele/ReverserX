# Phase 3 — Dynamic Android and API Feedback Loop

**Duration:** 6–9 weeks full-time  
**Goal:** Correlate static code findings with authorized runtime and network
evidence.

## Deliverables

- Project scope and authorization gate for device, package, host, and network
  operations.
- ADB device discovery, selection, shell execution, and capability checks.
- Frida session manager with attach/spawn, lifecycle recovery, and structured
  event capture.
- Versioned bundled hooks for crypto, pinning observation/bypass where
  authorized, intents, and class tracing.
- Generated targeted hooks with validation and preview before execution.
- Package-filtered logcat collection.
- mitmproxy lifecycle and capture import.
- HAR/flow normalization and endpoint mapping.
- Authentication-flow observations, request replay, and constrained fuzzing.
- Correlation records connecting source location, hook event, and HTTP flow.
- Manual interaction checkpoints when the user must trigger an app action.

## Work breakdown

1. Define the supported emulator/device/Android/Frida matrix.
2. Build deterministic ADB wrappers and device-state diagnostics.
3. Add Frida session cleanup and reconnect behavior.
4. Treat hook scripts as versioned artifacts with schemas for emitted events.
5. Add proxy setup guidance and certificate-state diagnostics.
6. Normalize URLs while preserving raw captures.
7. Implement replay safeguards: allowlisted hosts, rate limits, and redaction.
8. Let the reviewer propose a dynamic step from a static finding.
9. Test the full encryption example against an app controlled by the project.

## Acceptance criteria

- No dynamic or network action runs without matching project scope.
- Device disconnect, app crash, and Frida detach leave recoverable session state.
- Hook output is timestamped and tied to device, process, script version, and
  originating plan step.
- Proxy secrets and tokens are redacted from normal logs and reports.
- Endpoint normalization groups variable IDs without losing original URLs.
- Replay cannot target a host outside the allowlist.
- A fixture demonstration connects a static crypto method to a runtime hook event
  and a captured API field with reproducible evidence.

## Implemented baseline

- 12 dynamic tools registered: `adb_device_list`, `adb_device_info`, `adb_shell`,
  `adb_logcat`, `frida_ps`, `frida_hook_list`, `frida_inject`, `proxy_start`,
  `proxy_stop`, `proxy_capture_import`, `proxy_flow_list`, `interaction_wait`.
- 4 bundled versioned Frida hook scripts: `crypto.js` (Cipher, SecretKeySpec, Mac),
  `http.js` (OkHttp, HttpURLConnection), `pinning.js` (SSL/TLS, CertificatePinner),
  `intents.js` (Intent construction, startActivity, sendBroadcast).
- `AdbClient` wrapper over `run_command()` with `AdbError` domain errors.
- `FridaSession` utilities: version probe, process listing, hook script loading
  with template substitution, structured JSON event parsing from Frida output.
- HAR import and normalization: URL path variable collapsing (`{id}`, `{uuid}`,
  `{token}`), endpoint grouping, secret header redaction (Authorization, Cookie,
  Set-Cookie → sha256 hashes).
- `CorrelationRecord` model and SQLite persistence (migration v6).
- Project scope gate: `_check_dynamic_scope()` in agent loop validates
  `dynamic_enabled`, package allowlists, device allowlists, and `allow_proxy`
  before executing dynamic tools.
- Agent prompt updates: planner and reviewer are now dynamic-aware.
- `WorkingMemory` extended with `active_device`, `active_frida_session`,
  `active_proxy_port`, `needs_user_interaction`.
- Evidence kind routing: Frida tools → `RUNTIME_EVENT`, proxy tools →
  `NETWORK_FLOW`, static/ADB tools → `TOOL_OUTPUT`.
- `device` and `proxy` CLI command groups with 7 commands.
- 9 new config fields with env var mappings.
- All tools handle missing binaries gracefully without crashing.

## Acceptance record

- [x] Project scope gate rejects dynamic tools when `dynamic_enabled` is false.
- [x] Package allowlist enforced for Frida/ADB tools.
- [x] Host allowlist (for proxy) and `allow_proxy` flag enforced.
- [x] Hook scripts are versioned (`// @version 1.0.0`) and content-fingerprinted.
- [x] Proxy secrets (Authorization, Cookie, Set-Cookie) are redacted to content
  hashes before persistence.
- [x] HAR URL normalization collapses variable IDs while preserving original URLs.
- [x] Dynamic tools handle missing external binaries gracefully (ADB, Frida,
  mitmproxy).
- [x] Correlation record model and SQLite table link static, runtime, and network
  evidence.
- [x] 232 repository tests pass with no regressions.
- [ ] Live-device acceptance: run ADB tools against a real device/emulator.
- [ ] Live Frida injection and event capture against the authorized fixture app.
- [ ] Live mitmproxy capture, HAR import, and endpoint grouping.
- [ ] Full fixture demo: static crypto method → runtime Frida hook → captured API
  field → correlation record → evidence-linked report.
- [ ] Device disconnect, app crash, and Frida detach recovery testing.

## What you can do

- Prepare a dedicated emulator and an app you control for runtime testing.
- Document the exact UI action that triggers the fixture crypto/API flow.
- Define which hosts and packages are permitted in the test project.
- Manually validate generated Frida scripts before enabling automatic execution.
- Test failure cases: locked device, missing server, wrong ABI, expired process,
  absent proxy certificate, and certificate pinning.

## Safety note

Request replay and fuzzing remain opt-in, scoped, and rate limited. Finding a
candidate vulnerability must not automatically trigger exploitation.
