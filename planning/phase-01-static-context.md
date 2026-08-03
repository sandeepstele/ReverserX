# Phase 1 — Android Static Intelligence and Context

- **Original estimate:** 6–8 weeks full-time
- **Implementation status:** Complete
- **Engineering acceptance status:** Complete on the authorized real fixture
- **Owner/product acceptance status:** Pending labeled retrieval scoring and
  manual review
- **Goal:** Turn an APK or APKM bundle into searchable, ranked, evidence-linked
  source context

Phase 1 implementation and engineering acceptance are complete. The authorized
large fixture was indexed, searched, queried through a bounded known-path
workflow, and rendered into a report. Product acceptance remains open until the
app owner supplies and scores 20–30 labeled questions and manually reviews the
manifest and obfuscation findings. Engineering acceptance does not establish
that every result from a large, partially decompiled application is correct.

## Implemented capabilities

- Safe APK and APKM validation without wholesale extraction, including archive
  traversal, duplicate-entry, malformed-archive, symlink, CRC, and expansion
  safeguards.
- Deterministic base/split selection and content-addressed artifact import into
  project-confined storage.
- APK inventory for assets, resources, DEX files, and native libraries, with
  stable names, sizes, ABI information, and SHA-256 evidence.
- APK Signing Block v2, v3, and v3.1 evidence extraction plus legacy
  `META-INF` signature-file inventory.
- A bounded JADX 1.5.6 adapter with structured success, partial, failure,
  timeout, command, version, output-count, warning, and error results.
- A decoded-manifest analyzer with exact evidence locators, target-SDK-aware
  exported-component semantics, application permission inheritance, and
  provider read/write permission reasoning.
- Deterministic Java, Kotlin, and Smali chunking with stable identities and
  source locations, bounded oversized-file fallback, and explicit skip/fallback
  accounting.
- Exact and regular-expression source search with bounded excerpts and symbol,
  path, and line metadata.
- Local embedding and vector-index adapters, lexical and semantic retrieval,
  token-budget packing, and hierarchical summary support.
- Persistent context-index lifecycle, cache invalidation, and duplicate-safe
  re-indexing, including collision-free method-summary identities and a
  published vector-readiness marker.
- Initial obfuscation heuristics with structured signals, evidence, and
  confidence.
- Phase 1 CLI workflows and deterministic Markdown static reports.

## Verified evidence

### Automated verification

- The final implementation baseline has **213 passing tests** with **85%
  measured coverage**, including regressions for oversized-source handling,
  overloaded-method summaries, and vector-index lifecycle safety.
- Repository-wide Ruff formatting/linting and strict MyPy validation pass.
- The production `ContextService` achieved **hit@1 = 1.0, hit@3 = 1.0,
  hit@5 = 1.0, and MRR = 1.0** on the controlled benchmark corpus.

These retrieval scores describe the committed controlled benchmark only. They
must not be generalized to the authorized large application until its expected
methods and questions have been independently labeled and evaluated.

### Authorized fixture evidence

- Selected base APK: **235,169,283 bytes**, containing **20 DEX files**.
- Retained configuration split: **7,329,019 bytes**, confirmed as
  **resource-only** for primary-code selection purposes.
- JADX **1.5.6** completed under explicit partial-result acceptance and produced
  **155,643 source files** and **9,809 resource files**.
- JADX reported **1,095 errors**. The output is therefore a partial
  decompilation, not a clean or complete source reconstruction.
- Engineering index run **`run_40cce1b79bc74186aa1ab39845920ac4`** completed
  in **905.2 seconds** with chunker **1.1.0** and fingerprint
  **`4070e0d40dc0976ce1e9a3932f9e5c3a5e81483c745ea376d3035cea3d2f6b1e`**.
- All **155,643 source files** were indexed: **0 skipped**, with the **29 files**
  above the structured-parser threshold preserved through bounded fallback.
- The completed index contains **917,131 chunks** and **754,003 summaries**.
  Its **165,693 file chunks** include non-overlapping gaps outside parsed
  constructs so package/import lines, Kotlin top-level declarations, and Smali
  class fields remain searchable.
  Its **594,112 method chunks** have exactly **594,112 method summaries**,
  confirming that overloaded-method summary collisions were removed.
- Published vector metadata records **917,131 documents**, **384 dimensions**,
  and provider **`local-hashing-v1`**.
- Exact and timeout-bounded regular-expression searches succeeded against the
  real source tree in **32.1** and **28.1 seconds**, respectively.
- A bounded hybrid query with a known-path hint completed in **1.48 seconds**,
  returning **10 chunks** and packing **3,281 of 30,000 tokens**; its three
  relevant `C0KK7` chunks ranked first.
- The static report was generated successfully and preserves the partial JADX
  state, the 1,095 errors, signing limitations, index warnings, and provenance.
- Diagnostic omissions, overloaded-method summary collisions, and vector
  readiness issues found during the first large-tree run were corrected before
  this authoritative acceptance run.
- Final review also added JADX cache-content integrity snapshots, full-manifest
  DTD/entity rejection, indeterminate resource-backed boolean handling,
  `uses-permission-sdk-23` coverage, modern dangerous-permission labels, and
  per-chunk regular-expression timeouts before this run.

The signing subsystem inventories and fingerprints certificate, signature, and
public-key evidence. It does **not** cryptographically verify APK signatures,
certificate chains, trust, or signer identity, and reports this limitation in
its structured warnings.

## Acceptance checklist

- [x] Repeated APK/APKM inspection produces reproducible content identities.
- [x] APKM ingestion selects the 20-DEX base APK and retains the resource-only
  split without treating it as the primary code target.
- [x] Malformed APKs, unsafe archive names, duplicate entries, and tested JADX
  failure/timeout conditions produce structured failures.
- [x] Manifest analysis preserves component and permission evidence locators.
- [x] Search results preserve path, line range, enclosing symbol, and bounded
  content.
- [x] Controlled retrieval meets the recorded hit@k and MRR results above.
- [x] Context packing is covered by deterministic token-budget tests.
- [x] Re-indexing and cache lifecycle behavior are covered by automated tests.
- [x] Obfuscation output includes structured evidence and confidence in the
  controlled fixtures.
- [x] Index the authorized 155,643-source partial JADX output and record the
  fingerprint, chunk count, duration, skipped-file count, fallbacks, and
  failures.
- [x] Run exact and regular-expression searches plus a bounded known-path hybrid
  query against the authorized fixture.
- [x] Confirm that every method chunk has a collision-free method summary and
  that vector metadata is published only for the completed index.
- [ ] Score 20–30 owner-labeled authorized-fixture questions and record
  hit@1/3/5 and MRR separately from the controlled benchmark.
- [ ] Manually verify the authorized fixture's exported components, inherited
  permissions, and provider read/write guards against the decoded manifest.
- [ ] Review real-fixture obfuscation signals for actionable false positives.
- [x] Generate and inspect the evidence-linked static report, ensuring the
  1,095 JADX errors and partial-decompilation state remain visible.

## Owner actions needed for product acceptance

1. Label the expected important classes or methods for the authorized fixture.
2. Supply 20–30 realistic retrieval questions without embedding source names in
   each question.
3. Manually review a sample of manifest and obfuscation findings.
4. Decide whether the current partial JADX result is acceptable for the first
   MVP, or whether Phase 1 requires a stricter error threshold or a second
   decompiler.
5. Provide or approve a small redistributable fixture for repeatable CI and
   documentation; the authorized private APK must remain outside Git.

## Remaining limitations

- A JADX source tree is a best-effort reconstruction, and the authorized
  fixture currently contains 1,095 reported decompilation errors.
- Perfect controlled retrieval scores do not guarantee equivalent performance
  on obfuscated or partially recovered code.
- Signing evidence is fingerprinted and inventoried, not cryptographically
  verified.
- Static analysis cannot prove runtime behavior or recover code loaded only at
  runtime.
- The unguided natural-language real-fixture query was noisy. The recorded
  known-path result demonstrates a bounded engineering workflow, not general
  natural-language retrieval quality.
- `local-hashing-v1` is a lexical hashing fallback, not a semantic model; it
  must not be described as semantic understanding.
- The controlled retrieval benchmark is file-level and uses the memory backend;
  it does not validate exact method ranking or the production Chroma path.
- Hybrid context queries are ANN-first and lexically rerank at most a bounded
  semantic/known-path candidate set; exact or regex search is required for an
  exhaustive literal scan.
- Fingerprint-specific Chroma collections are retained rather than garbage
  collected automatically, so repeated large rebuilds currently consume
  additional private disk space.
- Cache markers predating JADX cache schema v3 are deliberately rejected and
  require an explicit forced rebuild before cache reuse.
- The obfuscation scan is capped at 100,000 files and ran on JADX-deobfuscated
  names, so owner review is required before interpreting its score.
- Report findings are candidate evidence for analyst review, not proof of a
  vulnerability or runtime behavior.
- Owner-labeled retrieval scoring and manual manifest/obfuscation review remain
  pending, so owner/product acceptance is not yet complete.

## Deferred

Frida, network capture, Ghidra, generic string decryption, autonomous planning,
and HTML reporting remain in later phases.
