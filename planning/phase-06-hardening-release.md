# Phase 6 — Hardening and Release

**Duration:** 6–8 weeks full-time  
**Goal:** Turn the working system into a dependable Android reverse-engineering
product with explicit support boundaries.

## Deliverables

- Published host, Android, architecture, and external-tool compatibility matrix.
- Clean-machine installer and dependency setup documentation.
- Unit, integration, scenario, migration, and end-to-end test suites.
- Performance benchmarks for small, medium, and large APKs.
- Retrieval, detector, call-graph, and report-quality evaluation results.
- Crash recovery, cancellation, disk-quota, and cleanup behavior.
- Threat model covering hostile artifacts, generated scripts, model output,
  subprocesses, secrets, and network actions.
- Scope enforcement and audit-log security review.
- User guide, troubleshooting guide, architecture guide, and contributor guide.
- Versioning, release notes, support policy, and known-limitations document.
- Signed/checksummed release artifacts where appropriate.

## Work breakdown

1. Freeze the supported matrix; unsupported combinations remain best effort.
2. Test clean installs and upgrades on every supported host.
3. Run hostile/malformed artifact tests and resource-exhaustion tests.
4. Benchmark time, memory, disk, tokens, and cost.
5. Conduct retrieval and detector regression evaluation.
6. Review subprocess arguments, generated Frida code, and report rendering.
7. Run the complete authorized fixture suite repeatedly.
8. Fix release-blocking reliability and documentation gaps.
9. Publish limitations honestly, especially for obfuscation and native tracing.

## Acceptance criteria

- A new user can install and complete the documented static tutorial on a clean
  supported machine.
- The supported dynamic fixture passes on every declared device configuration.
- Cancellation leaves no orphaned managed processes in tested workflows.
- Malformed artifacts and oversized output cannot escape storage limits.
- No known critical issue allows scope bypass, command injection, secret leakage,
  or unsafe report rendering.
- Benchmark and quality regressions are visible in automated checks.
- Backup, migration, resume, export, and cleanup paths are tested.
- Known limitations and troubleshooting steps are published.

## What you can do

- Recruit a small authorized beta group with varied environments.
- Run the installation guide without development-machine assumptions.
- Triage compatibility issues into supported, planned, and unsupported groups.
- Decide the release license and contribution policy.
- Set minimum quality gates and decide what blocks a release.
- Prepare example projects using only redistributable fixtures.

## Definition of done

The project is not “done” because every APK can be fully reversed. It is done
when declared workflows are reproducible on the supported matrix, failures are
honest and recoverable, evidence is traceable, and unsafe actions remain under
explicit user control.
