# ReverserX Delivery Roadmap

This directory converts the product vision in `../Plan.md` into an executable
engineering roadmap. Android is the only mobile platform in scope. Web API and
native binary analysis remain in scope.

## Current status — 2026-08-04

- **Phase 0 is complete.** The installable CLI, typed contracts, configuration,
  SQLite persistence, immutable artifact storage, safe process execution, CI,
  and development quality gates are operational.
- **Phase 1 implementation and engineering acceptance are complete; owner and
  product acceptance remain pending.** The final implementation baseline has
  213 passing tests with 85% measured coverage. The controlled
  production-`ContextService` benchmark has hit@1/3/5 and MRR of 1.0.
- The authorized large fixture has been safely inventoried and partially
  decompiled. Its 235,169,283-byte base contains 20 DEX files; its
  7,329,019-byte split is resource-only. JADX 1.5.6 produced 155,643 sources and
  9,809 resources while reporting 1,095 errors under explicit partial-result
  acceptance.
- Authoritative real-fixture run
  **`run_40cce1b79bc74186aa1ab39845920ac4`** completed in **905.2 seconds** with
  chunker **1.1.0**.
  It indexed all **155,643 sources** with **0 skipped** and **29 bounded
  oversized fallbacks**, producing **917,131 chunks**, **754,003 summaries**,
  and fingerprint
  **`4070e0d40dc0976ce1e9a3932f9e5c3a5e81483c745ea376d3035cea3d2f6b1e`**.
- The run has an exact **594,112 method chunks to 594,112 method summaries**
  match. Vector metadata records **917,131 documents**, **384 dimensions**, and
  **`local-hashing-v1`**. Exact and timeout-bounded regex searches completed in
  32.1 and 28.1 seconds; a bounded known-path hybrid query completed in 1.48
  seconds with 10 chunks and 3,281 of 30,000 tokens.
- The static report was generated with partial/error/signing/index-warning and
  provenance limitations intact. Owner-labeled 20–30 question scoring and
  manual manifest/obfuscation review remain open.
- Phase 2 implementation has not started.

APK signing certificate, signature, and public-key evidence is inventoried and
fingerprinted, but it is not cryptographically verified. The project must not
represent those fingerprints as proof of signature validity or signer trust.
The unguided natural-language real query was noisy, and `local-hashing-v1` is a
lexical hashing fallback rather than semantic understanding. The obfuscation
scan was capped at 100,000 files and operated on JADX-deobfuscated names. Static
report findings remain candidate evidence for analyst review, not proof.
The controlled benchmark is file-level and memory-backed. Production hybrid
queries are ANN-first bounded reranking, while exhaustive literal work belongs
in exact/regex search. Old fingerprint-specific vector collections currently
require manual lifecycle cleanup.

## Delivery strategy

Build one working vertical slice at a time. A phase is complete only when its
acceptance criteria pass against controlled fixtures and a representative
authorized workflow. JADX, Frida, mitmproxy, and Ghidra each introduce a
different set of environment and compatibility failures, so their acceptance
evidence must remain distinct.

| Phase | Outcome | Status | Solo full-time estimate |
|---|---|---|---:|
| [0 — Foundation](phase-00-foundation.md) | Installable CLI, contracts, storage, configuration, safe process execution | Complete | 2–3 weeks |
| [1 — Android Static Intelligence](phase-01-static-context.md) | APK ingestion, JADX analysis, context retrieval, initial obfuscation detection | Engineering accepted; owner/product acceptance pending | 6–8 weeks |
| [2 — Agent and Model Routing](phase-02-agent-router.md) | Planner/executor/reviewer loop, multimodal routing, cost controls | Planned | 5–7 weeks |
| [3 — Dynamic and API Loop](phase-03-dynamic-api.md) | ADB/Frida/mitmproxy workflow correlated with static findings | Planned | 6–9 weeks |
| [4 — Native and Deobfuscation](phase-04-native-deobfuscation.md) | Ghidra integration, packer/CFF analysis, Java-to-JNI tracing | Planned | 8–12 weeks |
| [5 — Persistence and Reporting](phase-05-persistence-reporting.md) | Reliable resume, evidence provenance, Markdown and HTML reports | Planned | 4–6 weeks |
| [6 — Hardening and Release](phase-06-hardening-release.md) | Compatibility testing, packaging, safety controls, documentation | Planned | 6–8 weeks |

The original straight-line implementation estimate is approximately **37–53
full-time weeks**. With 20–30% contingency for external-tool compatibility,
difficult fixtures, and research uncertainty, the production-quality solo
estimate remains **11–17 months**. Actual work completed in Phases 0 and 1 does
not remove the uncertainty in dynamic instrumentation, native analysis, and
agent reliability.

A focused static-analysis MVP still requires Phase 2 after Phase 1
owner/product acceptance. The original estimate for reaching that milestone
was approximately **3–5 months** from project start; use measured remaining
work rather than treating that early estimate as a delivery promise.

## Scope boundaries

In scope:

- Android APK analysis
- Java, Kotlin, Smali, JNI, and native Android libraries
- Authorized runtime analysis using ADB and Frida
- HTTP/API capture, mapping, replay, and constrained fuzzing
- AI-assisted planning, retrieval, review, and reporting
- Text, code, image, and artifact-reference model inputs under the multimodal
  policy
- Local/private model operation

Out of scope for the initial product:

- Non-Android mobile platforms and their device toolchains
- Automatic exploitation
- Unattended testing of arbitrary internet targets
- Guaranteed decryption of every custom obfuscation scheme
- Multi-tenant cloud hosting

## Rules used across all phases

1. Every tool returns a versioned, typed result; models do not parse arbitrary
   terminal output when a structured adapter can do it.
2. Every finding distinguishes observed evidence from model inference.
3. All external actions pass project scope and authorization checks.
4. Every agent run has limits for cost, tokens, tool calls, retries, and time.
5. Raw artifacts remain immutable; derived artifacts record their source.
6. External-tool versions and commands are recorded for reproducibility.
7. Partial external-tool output must remain visibly partial throughout
   retrieval and reporting.
8. A controlled benchmark cannot substitute for representative real-fixture
   acceptance.
9. No phase is complete with only mocked happy-path tests.

## Original-plan mapping

- Original Phase 1: context manager, obfuscation detection, router, and cost
  estimator are delivered across Phases 1 and 2 here.
- Original Phase 2: packer detection, cross-language tracing, and reporting are
  delivered in Phases 4 and 5.
- Original Phase 3: full resume and string decryption are delivered in Phases
  4 and 5.
- The foundation, dynamic/API integration, and release work were described in
  the architecture but were not scheduled in the original phase list. They now
  have explicit phases.

Continue with [NEXT_STEPS.md](NEXT_STEPS.md). Phase 1 engineering is accepted;
close the labeled-scoring and manual-review gates before treating it as
owner/product accepted or beginning the generic Phase 2 agent loop.
