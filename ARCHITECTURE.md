# ReverserX Architecture

This document describes the implemented foundation and the boundaries future
phases must preserve. The broader product vision remains in [Plan.md](Plan.md).

## Current implementation

```text
CLI (Typer + Rich)
  |
  +-- Settings -------- YAML + environment + explicit CLI overrides
  +-- Database -------- SQLite migrations and typed repositories
  +-- ArtifactStore --- immutable, content-addressed file storage
  +-- ToolRegistry ---- explicit allowlist and input validation
  +-- Doctor ---------- host capability and tool-version discovery
  `-- ProcessRunner --- no shell, timeout/cancel, bounded output

AgentService (bounded state machine)
  |
  +-- Planner --------- strict structured plan + one repair attempt
  +-- Executor -------- registered tools and validated arguments only
  +-- Reviewer -------- accept/retry/refine/inject/stop transitions
  +-- ModelRouter ----- capability, privacy, context, quality, then cost
  +-- Usage ledger ---- estimates, actual tokens/images/cost, hard limits
  `-- Checkpoints ----- persisted state, plan attempts, memory, findings
```

Source code uses a `src/` layout:

```text
src/reverserx/
├── agent/                    bounded planner/executor/reviewer service
├── ai/                       multimodal contracts, providers, router, pricing
├── main.py                  CLI composition and application boundary
├── config/settings.py       validated configuration and redaction
├── core/models.py           provider-independent versioned schemas
├── storage/database.py      SQLite migrations and repositories
├── storage/files.py         immutable content-addressed artifacts
├── tools/base.py            tool contract and execution context
├── tools/registry.py        registered-tool allowlist and validation
└── utils/
    ├── logging.py           central logging and secret redaction
    ├── platform.py          dependency probes
    └── subprocess.py        bounded process execution
```

## Stable boundaries

### Core models

Core models do not import model-provider, reverse-engineering, or UI code. Every
persisted and tool-facing object includes a schema version and typed identifier.
Provider-specific responses must be normalized before entering this layer.

### Tools

Every tool declares a unique name, semantic implementation version,
description, and Pydantic input schema. The registry validates untrusted
arguments before calling a tool. Future agent code can invoke only registered
tools and must not execute arbitrary model-generated commands.

### Artifacts

Imported files are copied into a content-addressed path based on SHA-256. The
source is never modified. Stored blobs are read-only and project-separated.
Artifact metadata in SQLite provides the original name, digest, size, media
type, and relative storage path.

### Persistence

SQLite is the durable source of truth. Schema changes use ordered, forward-only
migrations. Vector indexes introduced in Phase 1 are derived state and must be
rebuildable from durable artifacts and metadata.

### Process execution

External tools receive argument vectors with `shell=False`. Standard output and
error are drained continuously and retained only to configured limits. Timeouts
and cancellation terminate the managed process group.

## Future layers

Later phases add ADB, Frida, proxy, Ghidra, deeper evidence correlation, polished
resume, and HTML export. These layers must depend inward on core contracts rather
than placing provider logic inside storage or deterministic tool adapters.

## Runtime layout

The default data location is selected through `platformdirs`. It can be
overridden by `REVERSERX_DATA_DIR`, YAML, or `--data-dir`.

```text
data-dir/
├── reverserx.sqlite3
├── reverserx.sqlite3-shm
├── reverserx.sqlite3-wal
└── artifacts/
    └── <project-id>/<digest-prefix>/<sha256>/blob
```

Runtime data is intentionally not stored in the source tree by default.
