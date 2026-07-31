# ReverserX Delivery Roadmap

This directory converts the product vision in `../Plan.md` into an executable
engineering roadmap. Android is the only mobile platform in scope. Web API and
native binary analysis remain in scope.

## Delivery strategy

Build one working vertical slice at a time. A phase is complete only when its
acceptance criteria pass against committed test fixtures. Do not begin several
large integrations at once: JADX, Frida, mitmproxy, and Ghidra each introduce a
different set of environment and compatibility failures.

| Phase | Outcome | Solo full-time estimate |
|---|---|---:|
| [0 — Foundation](phase-00-foundation.md) | Installable CLI, contracts, storage, configuration, safe process execution | 2–3 weeks |
| [1 — Android Static Intelligence](phase-01-static-context.md) | APK ingestion, JADX analysis, context retrieval, initial obfuscation detection | 6–8 weeks |
| [2 — Agent and Model Routing](phase-02-agent-router.md) | Planner/executor/reviewer loop, multi-model routing, cost controls | 5–7 weeks |
| [3 — Dynamic and API Loop](phase-03-dynamic-api.md) | ADB/Frida/mitmproxy workflow correlated with static findings | 6–9 weeks |
| [4 — Native and Deobfuscation](phase-04-native-deobfuscation.md) | Ghidra integration, packer/CFF analysis, Java-to-JNI tracing | 8–12 weeks |
| [5 — Persistence and Reporting](phase-05-persistence-reporting.md) | Reliable resume, evidence provenance, Markdown and HTML reports | 4–6 weeks |
| [6 — Hardening and Release](phase-06-hardening-release.md) | Compatibility testing, packaging, safety controls, documentation | 6–8 weeks |

The straight-line implementation total is approximately **37–53 full-time
weeks**. Add 20–30% contingency for external-tool compatibility, difficult APK
fixtures, and research uncertainty. A realistic production-quality solo
schedule is therefore **11–17 months**. A focused static-analysis MVP is
available after Phases 0–2, approximately **3–5 months**.

These estimates assume prior experience with Python, Android internals, JADX,
Frida, mitmproxy, Ghidra, and LLM tool calling. Part-time work will take longer
than a simple hours-to-calendar conversion because device and integration
problems interrupt momentum.

## Scope boundaries

In scope:

- Android APK analysis
- Java, Kotlin, Smali, JNI, and native Android libraries
- Authorized runtime analysis using ADB and Frida
- HTTP/API capture, mapping, replay, and constrained fuzzing
- AI-assisted planning, retrieval, review, and reporting
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
7. No phase is considered complete with only mocked happy-path tests.

## Original-plan mapping

- Original Phase 1: context manager, obfuscation detection, router and cost
  estimator are delivered across Phases 1 and 2 here.
- Original Phase 2: packer detection, cross-language tracing, and reporting are
  delivered in Phases 4 and 5.
- Original Phase 3: full resume and string decryption are delivered in Phases
  4 and 5.
- The foundation, dynamic/API integration, and release work were described in
  the architecture but were not scheduled in the original phase list. They now
  have explicit phases.

Start with [NEXT_STEPS.md](NEXT_STEPS.md) and do not start Phase 1 until the
Phase 0 decisions and fixture policy are settled.
