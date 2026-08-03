# ReverserX

ReverserX is a planned standalone, AI-orchestrated reverse-engineering platform
for Android applications, web APIs, and native binaries. It is intended to
combine traditional security tooling with multiple AI models in one persistent,
evidence-driven analysis workflow.

> **Project status:** Pre-alpha foundation. Phase 0 provides an installable CLI,
> validated configuration, versioned domain models, SQLite migrations,
> content-addressed artifact storage, a typed tool registry, bounded subprocess
> execution, dependency diagnostics, and automated quality checks. Reverse-
> engineering integrations begin in Phase 1.

## Quick start

ReverserX requires Python 3.11 or newer. Development uses
[uv](https://docs.astral.sh/uv/) for reproducible environments and commands.

```bash
uv sync --extra dev
uv run reverserx --help
uv run reverserx --data-dir .reverserx init
uv run reverserx doctor
```

Create a scoped project, import an authorized artifact, and verify the tool
execution pipeline:

```bash
uv run reverserx --data-dir .reverserx project create "Demo App" \
  --package com.example.demo \
  --host api.example.test

uv run reverserx --data-dir .reverserx artifact import demo-app ./fixture.apk

uv run reverserx --data-dir .reverserx tool run demo-app echo \
  --arguments '{"message":"foundation ready"}'
```

Runtime data is stored outside the repository by default. Use
`REVERSERX_DATA_DIR`, `--data-dir`, or a YAML configuration file to select a
different location. Provider secrets are accepted only through environment
variables and are redacted from configuration output and configured logs.

## What ReverserX is intended to do

A researcher should be able to provide an authorized target and a high-level
goal such as:

> Find how this APK encrypts its API requests and support the conclusion with
> static, runtime, and network evidence.

ReverserX will plan and execute the analysis across several domains:

```text
User goal
   |
   v
Planner -> Executor -> Reviewer -> Updated plan
              |
              +-- Static analysis: JADX, manifests, source search
              +-- Dynamic analysis: ADB, Frida, logcat
              +-- API analysis: mitmproxy, HAR mapping, replay
              +-- Native analysis: ELF tools, Ghidra, JNI tracing
              |
              v
      Evidence + findings + report
```

Unlike a collection of isolated wrappers, the planned application contains its
own planner, executor, reviewer, model router, context manager, session memory,
and report generator. It is designed to run as a local CLI or interactive shell
without depending on an external agent framework.

## Planned capabilities

### Android static analysis

- Decompile APKs using JADX.
- Parse permissions, components, intent filters, certificates, resources, and
  exported attack surfaces.
- Search Java, Kotlin, and Smali with exact-text and regular-expression queries.
- Trace relevant callers, callees, and Java-to-JNI boundaries.
- Identify native libraries and extract structured ELF metadata.

### Purpose-built AI context management

- Split decompiled output into method, class, package, native-function, and API
  endpoint chunks.
- Combine lexical search, semantic retrieval, metadata, and call-graph distance.
- Enforce model token budgets instead of sending entire decompiled projects.
- Generate cached method, class, and package summaries.
- Preserve exact source locations so model conclusions can cite evidence.

### Agent orchestration and model routing

- Convert a high-level research objective into validated analysis steps.
- Execute only registered tools with structured arguments.
- Review each result and insert justified follow-up steps.
- Represent model input as typed text, code, and image parts so screenshots,
  rendered resources, and UI evidence can be routed to multimodal models.
- Select providers by required capabilities and privacy policy before optimizing
  for price; unsupported modalities are never silently dropped.
- Route planning, code reasoning, reporting, and sensitive analysis to suitable
  hosted or local models.
- Estimate cost before execution and enforce cost, token, step, retry, and time
  limits.

### Dynamic and API analysis

- Connect to authorized Android devices or emulators through ADB.
- Attach or spawn applications with Frida and run versioned hooks.
- Generate targeted hooks from static findings with user review.
- Capture logcat and proxy traffic as structured evidence.
- Map endpoints, authentication behavior, and request/response schemas.
- Replay or fuzz requests only within explicitly allowed scope and rate limits.

### Native analysis and deobfuscation

- Analyze imports, exports, strings, sections, and suspicious ELF properties.
- Integrate headless Ghidra for deeper function and cross-reference analysis.
- Resolve conventionally exported and dynamically registered JNI methods.
- Detect supported obfuscators, packers, and control-flow-flattening patterns.
- Apply tested string-decryption handlers for explicitly supported patterns.
- Represent confirmed and inferred call-graph edges with different confidence.

### Persistence and reporting

- Store projects, plans, tool runs, findings, hypotheses, and model usage in
  SQLite.
- Store semantic indexes in ChromaDB and raw artifacts in an immutable project
  file store.
- Resume interrupted analysis while validating external device and tool state.
- Produce Markdown and HTML reports linking findings to source, hook events, and
  network captures.
- Clearly distinguish directly observed evidence from AI inference.

## Architecture

The planned implementation is a Python package organized into these layers:

| Layer | Responsibility |
|---|---|
| CLI / interactive shell | Project setup, analysis commands, progress, confirmation |
| Agent | Planning, execution, review, working memory, termination controls |
| AI | Provider adapters, routing, prompts, usage accounting, context management |
| Tools | Static, dynamic, API, native, and deobfuscation integrations |
| Storage | SQLite state, ChromaDB indexes, immutable artifacts |
| Reporting | Evidence graph, Markdown/HTML output, redaction and export |

All tools will return typed, versioned results. Raw tool output and imported
artifacts remain available for reproducibility, while derived findings record
their source, tool version, and confidence.

## Delivery roadmap

| Phase | Outcome | Solo full-time estimate |
|---|---|---:|
| [0 — Foundation](planning/phase-00-foundation.md) | CLI, contracts, storage, configuration, safe subprocesses | 2–3 weeks |
| [1 — Static intelligence](planning/phase-01-static-context.md) | APK ingestion, JADX, retrieval, context budgets, obfuscation signals | 6–8 weeks |
| [2 — Agent and router](planning/phase-02-agent-router.md) | Bounded agent loop, model routing, estimates and usage limits | 5–7 weeks |
| [3 — Dynamic and API](planning/phase-03-dynamic-api.md) | ADB, Frida, mitmproxy, endpoint mapping, evidence correlation | 6–9 weeks |
| [4 — Native and deobfuscation](planning/phase-04-native-deobfuscation.md) | Ghidra, packer/CFF detection, JNI/native graph | 8–12 weeks |
| [5 — Persistence and reporting](planning/phase-05-persistence-reporting.md) | Full resume, evidence provenance, Markdown/HTML reports | 4–6 weeks |
| [6 — Hardening and release](planning/phase-06-hardening-release.md) | Compatibility, security review, testing, packaging, documentation | 6–8 weeks |

The focused static-analysis MVP is targeted after Phases 0–2, approximately
**3–5 months** of full-time solo development. The complete production-quality
roadmap is expected to require approximately **11–17 months**, including
integration and research contingency.

See the [delivery roadmap](planning/README.md) for scope boundaries, phase
dependencies, and completion rules. See [what to do now](planning/NEXT_STEPS.md)
for the immediate preparation checklist.

## Repository documents

```text
ReverserX/
├── README.md                         # Project introduction and roadmap
├── Plan.md                           # Full product vision and architecture
└── planning/
    ├── README.md                     # Delivery strategy and estimates
    ├── NEXT_STEPS.md                 # Immediate owner actions and decisions
    ├── phase-00-foundation.md
    ├── phase-01-static-context.md
    ├── phase-02-agent-router.md
    ├── phase-03-dynamic-api.md
    ├── phase-04-native-deobfuscation.md
    ├── phase-05-persistence-reporting.md
    └── phase-06-hardening-release.md
```

The complete design rationale, proposed tool interfaces, dependency list, and
example end-to-end workflow are in the [original project plan](Plan.md).

## Continuing development

The Phase 0 foundation now supports these deterministic operations:

1. Install and expose a `reverserx` CLI.
2. Create and reopen a local project.
3. Import an artifact without modifying the source file.
4. Detect installed external tools and record their versions.
5. Execute a typed example tool with timeouts and bounded output.
6. Persist the tool run and its evidence in SQLite.
7. Run unit, lint, format, and type checks through one documented command.

The next implementation target is [Phase 1](planning/phase-01-static-context.md):
APK validation, JADX integration, manifest analysis, source chunking, retrieval,
context budgets, and measurable obfuscation signals. Before beginning it,
prepare authorized APK fixtures, establish a provider/API budget, and define the
first measurable demonstration goal. Remaining owner decisions are listed in
[NEXT_STEPS.md](planning/NEXT_STEPS.md).

## Planned external dependencies

The eventual feature set expects some or all of the following tools:

- JADX and a compatible Java runtime
- Android SDK Platform Tools / ADB
- Frida and `frida-tools`
- mitmproxy
- Ghidra for optional deep native analysis
- ChromaDB and a local embedding model
- SQLite
- Hosted model SDKs and/or Ollama
- Z3 and Smali tooling for later deobfuscation work

Phase 0 will define and publish exact supported versions. Optional integrations
must fail clearly when they are unavailable rather than preventing unrelated
features from running.

## Safety and authorized use

ReverserX is intended only for applications, devices, and network targets the
researcher is authorized to analyze. Planned safeguards include:

- Project-level allowlists for packages, devices, hosts, and endpoints.
- Explicit confirmation before dynamic, proxy, replay, or fuzzing operations.
- Rate limits and hard execution budgets.
- Immutable action logs and evidence provenance.
- Secret and personal-data redaction in ordinary logs and reports.
- No automatic exploitation.
- Local-model operation for artifacts that must not leave the machine.

The researcher remains responsible for authorization, applicable law, target
stability, and responsible disclosure.

## Development principles

- Prefer deterministic analysis before AI interpretation.
- Preserve evidence and label inference honestly.
- Build and test one vertical slice at a time.
- Treat model output, analyzed artifacts, and generated scripts as untrusted.
- Record enough environment and version information to reproduce a finding.
- Publish explicit limitations instead of claiming universal deobfuscation.
