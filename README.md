# ReverserX

ReverserX is a standalone reverse-engineering platform under active development
for Android applications, web APIs, and native binaries. It is intended to
combine traditional security tooling with multiple AI models in one persistent,
evidence-driven analysis workflow.

> **Project status:** Pre-alpha static-analysis implementation. Phases 0 and 1
> provide the foundation plus safe APK/APKM ingestion, JADX integration, manifest
> and signing metadata, persistent source indexing, Chroma-backed retrieval,
> context budgets, obfuscation signals, benchmarks, and Markdown reports. Dynamic
> analysis and autonomous model orchestration are not implemented yet.

## Quick start

ReverserX requires Python 3.11 or newer. Development uses
[uv](https://docs.astral.sh/uv/) for reproducible environments and commands.

```bash
uv sync --locked --extra dev --extra phase1
uv run reverserx --help
uv run reverserx --data-dir .reverserx init
uv run reverserx doctor
```

Create a scoped project and ingest an authorized Android package:

```bash
uv run reverserx --data-dir .reverserx project create "Demo App" \
  --package com.example.demo \
  --host api.example.test

uv run reverserx --data-dir .reverserx apk import demo-app ./fixture.apkm
uv run reverserx --data-dir .reverserx artifact list demo-app
uv run reverserx --data-dir .reverserx apk metadata demo-app
uv run reverserx --data-dir .reverserx apk decompile demo-app --timeout 3600
```

Then build and query the static context. Pass the base artifact ID shown by
`apk import` or `artifact list` so the index has explicit artifact lineage:

```bash
uv run reverserx --data-dir .reverserx manifest analyze demo-app
uv run reverserx --data-dir .reverserx source index demo-app \
  --artifact <base-artifact-id>
uv run reverserx --data-dir .reverserx source search demo-app \
  "Cipher.getInstance"
uv run reverserx --data-dir .reverserx context query demo-app \
  "Where is outbound request encryption performed?" --budget 60000
uv run reverserx --data-dir .reverserx obfuscation detect demo-app
uv run reverserx --data-dir .reverserx report static demo-app \
  --goal "Locate request encryption with source evidence"
```

JADX sometimes returns a non-zero code while producing useful output for a
large or intentionally difficult app. ReverserX records that as a failure by
default. After reviewing the diagnostics, rerun with `--show-bad-code` and
`--accept-partial` to retain explicitly labeled partial output; it is never
silently presented as a complete decompilation.

Runtime data is stored outside the repository by default. Use
`REVERSERX_DATA_DIR`, `--data-dir`, or a YAML configuration file to select a
different location. Provider secrets are accepted only through environment
variables and are redacted from configuration output and configured logs.

## Phase 1 validation status

Phase 1 implementation and engineering acceptance are complete. The final
repository gate has **213 passing tests** with **85% measured coverage**; Ruff
formatting and linting, strict MyPy checks, the locked dependency check, and
wheel/source-package builds also pass.

The authorized large APKM fixture was exercised locally and kept outside Git:

- Its 235,169,283-byte base APK contains 20 DEX files; the retained
  7,329,019-byte configuration split is resource-only.
- JADX 1.5.6 produced 155,643 source files and 9,809 resources while reporting
  1,095 errors. ReverserX preserves this as an explicitly accepted **partial**
  result, never as a clean decompilation.
- The authoritative chunker-v1.1 index accounts for all 155,643 source files
  with 0 skipped and 29 bounded oversized-file fallbacks. It contains 917,131
  chunks and 754,003 summaries, including an exact 594,112 method-chunk to
  594,112 method-summary match. Non-overlapping file-gap chunks preserve
  package/import lines, Kotlin top-level declarations, and Smali class fields.
- Exact and timeout-bounded regex searches completed in 32.1 and 28.1 seconds.
  A bounded query with a known-path hint completed in 1.48 seconds and packed
  10 chunks into 3,281 of 30,000 allowed tokens.
- The controlled committed retrieval benchmark records hit@1/3/5 and MRR of
  1.0. Those numbers describe only that benchmark, not the large private app.

Owner/product acceptance remains open. It requires scoring 20–30 owner-labeled
questions on the authorized app and manually reviewing representative manifest
and obfuscation results. The unguided natural-language real-app query was noisy,
`local-hashing-v1` is a lexical fallback rather than a learned semantic model,
and static candidates do not prove runtime behavior. See the
[Phase 1 acceptance record](planning/phase-01-static-context.md) and
[owner next steps](planning/NEXT_STEPS.md) for the complete evidence and open
decisions.

Phase 1 also integrity-checks every cached JADX output file before reuse,
rejects XML DTD/entity declarations, treats resource-backed manifest booleans
as indeterminate, and applies per-chunk regular-expression timeouts. Cache
markers created before schema v3 are intentionally not trusted; use
`apk decompile --force` to rebuild them. Hybrid context queries are ANN-first
and lexically rerank a bounded candidate set, so use exhaustive exact/regex
source search when a literal match must not be missed.

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
- Parse permissions, components, intent filters, resources, exported attack
  surfaces, and signing-certificate fingerprints.
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

| Phase | Status | Outcome | Solo full-time estimate |
|---|---|---|---:|
| [0 — Foundation](planning/phase-00-foundation.md) | Implemented | CLI, contracts, storage, configuration, safe subprocesses | 2–3 weeks |
| [1 — Static intelligence](planning/phase-01-static-context.md) | Implemented | APK ingestion, JADX, retrieval, context budgets, obfuscation signals | 6–8 weeks |
| [2 — Agent and router](planning/phase-02-agent-router.md) | Next | Bounded agent loop, model routing, estimates and usage limits | 5–7 weeks |
| [3 — Dynamic and API](planning/phase-03-dynamic-api.md) | Planned | ADB, Frida, mitmproxy, endpoint mapping, evidence correlation | 6–9 weeks |
| [4 — Native and deobfuscation](planning/phase-04-native-deobfuscation.md) | Planned | Ghidra, packer/CFF detection, JNI/native graph | 8–12 weeks |
| [5 — Persistence and reporting](planning/phase-05-persistence-reporting.md) | Planned | Full resume, evidence provenance, Markdown/HTML reports | 4–6 weeks |
| [6 — Hardening and release](planning/phase-06-hardening-release.md) | Planned | Compatibility, security review, testing, packaging, documentation | 6–8 weeks |

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

## Current implementation and next development stage

Phase 1 now supports a deterministic Android static pipeline:

1. Validate and import standalone APKs, APKM archives, or extracted APKM
   directories without trusting archive paths.
2. Preserve base and split identities in immutable, content-addressed storage.
3. Inventory DEX, resources, assets, native libraries, and conservative v1/v2/
   v3/v3.1 signing evidence.
4. Run JADX with bounded output, timeouts, caching, and explicit partial status.
5. Analyze manifest permissions, exported defaults, inherited guards, providers,
   and target-SDK-specific semantics with locators.
6. Chunk Java, Kotlin, and Smali deterministically; persist summaries and
   artifact-keyed Chroma collections.
7. Run exact, regex, and hybrid retrieval and pack the result under a hard token
   budget.
8. Record obfuscation evidence and render a lineage-checked Markdown report.

The next implementation target is [Phase 2](planning/phase-02-agent-router.md):
the bounded plan-execute-review loop, multimodal model capability routing,
provider privacy policy, usage accounting, and run budgets. Phase 1 commands are
usable without any hosted-model key; `hashing` is the deterministic local
embedding fallback, while Ollama is available as the learned local embedding
adapter.

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

The currently exercised static toolchain uses JADX 1.5.6, a compatible Java
runtime, SQLite, and ChromaDB 1.5.x. Optional integrations must fail clearly when
they are unavailable rather than preventing unrelated features from running.

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
