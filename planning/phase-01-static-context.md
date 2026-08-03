# Phase 1 — Android Static Intelligence and Context

**Duration:** 6–8 weeks full-time  
**Goal:** Turn an APK or APKM bundle into searchable, ranked, evidence-linked
source context.

## Deliverables

- APK and APKM validation, metadata extraction, and split inventory.
- Deterministic selection of the base APK for code analysis while retaining
  configuration splits as linked artifacts.
- JADX CLI adapter with structured results for sources, manifest, resources,
  certificates, assets, and native libraries.
- Manifest parser producing permissions, components, intent filters, exported
  surfaces, and source evidence.
- Exact-text and regular-expression source search.
- Chunkers for Java/Kotlin classes and methods and Smali methods.
- ChromaDB collection lifecycle tied to project/artifact IDs.
- Embedding adapter with a local default.
- Hybrid retrieval: keyword, semantic score, metadata, and known-location boost.
- Token-budget packing and deterministic context manifests.
- Method, class, and package summary hierarchy with cache invalidation.
- Initial obfuscation detector with measurable heuristics and confidence.
- Static-analysis CLI commands and a basic Markdown result.

## Work breakdown

1. Implement safe APK/APKM inspection and base/split selection.
2. Integrate JADX using the Phase 0 process runner.
3. Normalize paths and preserve exact file/line locations.
4. Implement manifest and certificate parsing without an LLM dependency.
5. Define chunk identities that remain stable across repeated indexing.
6. Add embedding and lexical indexes.
7. Implement retrieval scoring and token estimation.
8. Add summaries as derived, versioned artifacts.
9. Implement obfuscation signals: name entropy, short-name ratios, reflection
   density, encrypted-string indicators, and control-flow metrics.
10. Build a retrieval benchmark with known questions and expected methods.

## Acceptance criteria

- The same APK or APKM produces reproducible artifact and chunk identities.
- APKM ingestion identifies the base APK and every split without treating a
  resource-only split as the primary code target.
- Manifest results cite the originating manifest node or source location.
- Search results include file, line, enclosing type/method, and a bounded excerpt.
- Retrieval finds expected methods for the fixture questions at an agreed top-k
  success rate; record the metric rather than relying on visual judgment.
- Context packing never exceeds its configured token budget.
- Re-indexing does not duplicate chunks or summaries.
- Obfuscation results include evidence and confidence, and known clean fixtures
  do not produce uncontrolled false positives.
- The pipeline handles malformed APKs and JADX failures cleanly.

## What you can do

- Label the expected important methods for each fixture APK.
- Write 20–30 realistic retrieval questions without revealing the source names.
- Verify exported-component and permission findings manually.
- Collect obfuscation fixtures you own or can legally redistribute.
- Decide acceptable retrieval and false-positive targets.

## Deferred

Frida, network capture, Ghidra, generic string decryption, autonomous planning,
and HTML reporting are deliberately deferred.
