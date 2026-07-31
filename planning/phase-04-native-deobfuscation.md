# Phase 4 — Native Analysis and Mobile Deobfuscation

**Duration:** 8–12 weeks full-time  
**Goal:** Extend Android analysis through packers, obfuscated control flow, JNI,
and native libraries without claiming universal deobfuscation.

## Deliverables

- Native library inventory by ABI with ELF metadata, imports, exports, sections,
  strings, and suspicious-section signals.
- Packer/signature detector for explicitly supported products and versions.
- Headless Ghidra adapter with analysis profiles, timeout handling, and structured
  function/decompilation results.
- JNI mapping for conventionally exported and dynamically registered methods.
- Unified call-graph representation spanning Java/Kotlin, JNI mappings, and
  native functions, with confidence on inferred edges.
- Smali control-flow-flattening heuristics.
- A plug-in framework for supported static string-decryption patterns.
- AI deobfuscation reasoning grounded in tool evidence.
- Accuracy and performance corpus covering normal and obfuscated fixtures.

## Work breakdown

1. Implement deterministic ELF analysis before Ghidra integration.
2. Make packer signatures data-driven and cite matched indicators.
3. Add reproducible Ghidra project/cache management.
4. Resolve normal JNI exports, then `RegisterNatives`, then guarded heuristics.
5. Merge graphs while retaining source and confidence for every edge.
6. Detect CFF candidates; do not promise automatic restoration initially.
7. Implement string decryptors one known pattern at a time with test vectors.
8. Give the model constrained symbolic/helper tools only after deterministic
   analysis is stable.
9. Measure false positives, missed mappings, runtime, and cache size.

## Acceptance criteria

- ELF analysis supports each declared ABI and fails clearly on unsupported data.
- Every packer classification lists exact indicators and detector version.
- Repeated Ghidra analysis can reuse a valid cache and invalidate stale results.
- Known fixture JNI edges are recovered and carry source/confidence metadata.
- Inferred graph edges are visually and structurally distinct from confirmed
  edges.
- Each string-decryption implementation has known-answer tests.
- The system says “unsupported/unknown” instead of fabricating a deobfuscation.
- Model explanations cite code, graph nodes, or detector evidence.

## What you can do

- Build small JNI fixture apps with known static and dynamic registration.
- Collect legal samples for each advertised packer/obfuscator signature.
- Define the first two string-encryption patterns worth supporting.
- Manually compare Ghidra output and unified graph edges with source fixtures.
- Decide accuracy thresholds before advertising a detector as supported.

## Main risk

Cross-language tracing is the largest research risk in the roadmap. Ship useful
partial graphs with honest confidence instead of delaying the product for a
perfect graph that may be impossible on heavily stripped binaries.
