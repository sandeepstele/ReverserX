# Phase 0 — Foundation

**Duration:** 2–3 weeks full-time  
**Goal:** Establish the contracts and operational foundation needed by every
later integration.

## Deliverables

- Installable Python package with `reverserx` CLI entry point.
- Initial source tree described by the main plan.
- Configuration loaded from files and environment variables, with secret
  redaction in logs.
- Typed/versioned schemas for projects, artifacts, tool calls, evidence,
  findings, plan steps, and model usage.
- Tool registry and a small deterministic example tool.
- Safe subprocess runner supporting timeouts, cancellation, stdout/stderr
  limits, exit status, and version capture.
- SQLite migrations and project/session/tool-run tables.
- Immutable artifact store organized by project and content hash.
- `reverserx doctor` command for external dependency discovery.
- Automated unit-test, formatting, lint, and type-check commands.

## Work breakdown

1. Create package metadata, CLI, logging, and configuration.
2. Define core domain models before defining provider-specific response models.
3. Implement the tool interface and registry.
4. Implement process execution without shell interpolation by default.
5. Add SQLite repositories and migrations.
6. Add artifact import, hashing, metadata, and safe paths.
7. Add dependency probing for Java, JADX, ADB, Frida, mitmproxy, and Ghidra.
8. Add test fixtures and continuous checks.
9. Write architecture decisions for Python support, dependency management,
   schema versioning, and supported host operating systems.

## Acceptance criteria

- A clean environment can install the project and run `reverserx --help`.
- A user can create, list, open, and inspect a project.
- Imported artifacts cannot escape the project store or overwrite source files.
- A tool run records input, output, timestamps, status, version, and errors.
- A timed-out subprocess is terminated and reported without corrupting state.
- Logs never expose configured provider keys.
- Database migrations work from an empty database.
- The full Phase 0 test suite passes with one documented command.

## What you can do

- Choose the supported host OS and Python baseline.
- Decide whether the first release is a personal tool or distributable CLI.
- Prepare authorized APK fixtures and expected metadata.
- Review the schemas: this is the least expensive time to change terminology.
- Test installation instructions on a second clean machine or VM.

## Exit decision

Proceed only when tools and artifacts have stable IDs and a failed command can
be diagnosed from persisted records. Later phases depend on this provenance.
