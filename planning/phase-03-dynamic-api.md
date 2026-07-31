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
