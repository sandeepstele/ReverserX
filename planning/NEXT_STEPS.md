# What You Can Do Now

Phase 0–2 engineering implementation is complete. The immediate objective is to
finish Phase 1 owner scoring and Phase 2 live-provider/real-fixture acceptance,
not to treat recorded engineering scenarios as proof of product quality.

## Current verified baseline

- The final implementation baseline has 232 passing repository tests with 85%
  measured coverage.
- Ruff formatting/linting and strict MyPy validation pass.
- The controlled production-`ContextService` benchmark records hit@1, hit@3,
  hit@5, and MRR of 1.0.
- The authorized fixture's base APK is 235,169,283 bytes with 20 DEX files.
- Its 7,329,019-byte retained split is resource-only.
- JADX 1.5.6 produced 155,643 source files and 9,809 resource files under
  explicit partial-result acceptance, with 1,095 reported errors.
- Engineering index run **`run_40cce1b79bc74186aa1ab39845920ac4`** completed
  in **905.2 seconds** with chunker **1.1.0** and fingerprint
  **`4070e0d40dc0976ce1e9a3932f9e5c3a5e81483c745ea376d3035cea3d2f6b1e`**.
- All **155,643 sources** were indexed with **0 skipped** and **29 bounded
  oversized fallbacks**, producing **917,131 chunks** and **754,003 summaries**.
- The authoritative index has exactly **594,112 method chunks** and **594,112
  method summaries**. Its published vector metadata records **917,131
  documents**, **384 dimensions**, and **`local-hashing-v1`**.
- Exact and timeout-bounded regex real-fixture searches completed in **32.1**
  and **28.1 seconds**. A bounded known-path hybrid query completed in **1.48
  seconds**, returning **10 chunks** and packing **3,281 of 30,000 tokens**.
- The static report was generated with partial/error/signing/index-warning and
  provenance limitations preserved. Initial diagnostic omissions, summary
  collisions, and readiness issues were fixed before the authoritative run.

The controlled benchmark is not a substitute for scoring retrieval on the
authorized fixture. The signing inventory fingerprints evidence but does not
cryptographically verify signature validity or signer trust.

## Completed engineering acceptance work

The following authorized-fixture gates are complete:

1. The partial JADX output was indexed with complete file accounting,
   collision-free method summaries, and published vector metadata.
2. Deterministic exact and regular-expression searches preserved file, symbol,
   line, and excerpt evidence.
3. A bounded hybrid retrieval with a known-path hint demonstrated operational
   query and token-packing behavior on the large fixture.
4. The static report was generated and checked for partial-result, error,
   signing, index-warning, and provenance disclosure.
5. The diagnostic file omissions, method-summary collisions, and vector
   readiness gap were corrected and revalidated on the authoritative run.

## Remaining owner/product acceptance work

Complete these tasks before declaring product acceptance:

1. **Score owner-labeled retrieval.** Run 20–30 realistic questions through the
   production `ContextService` and calculate hit@1, hit@3, hit@5, and MRR as a
   new dataset, separate from the controlled score of 1.0.
2. **Review the decoded manifest.** Manually confirm exported-state inference,
   Android 12 explicit-export warnings, application permission inheritance, and
   provider read/write guards.
3. **Review obfuscation output.** Check the highest-scoring signals and record
   false positives, accounting for the 100,000-file cap and JADX-deobfuscated
   names.
4. **Review the static report as an owner.** Confirm that candidate evidence is
   useful and appropriately qualified rather than presented as proof.
5. **Record the product decision.** Either accept the partial decompilation for
   the first MVP with documented limits or open a bounded task for another
   decompiler/error-reduction strategy.

## What is needed from the app owner

1. Identify the expected important methods, classes, packages, or behaviors in
   the authorized app without publishing proprietary source.
2. Write 20–30 realistic questions, including the first demonstration goal,
   without putting the expected source filename or method name in every query.
3. Review a sample of exported-component and permission findings against the
   application's intended design.
4. Review a sample of obfuscation findings and label true/false positives.
5. Decide whether 1,095 JADX-reported errors are acceptable for the MVP if the
   target flows are still recoverable.
6. Approve a small redistributable fixture for CI and public examples. Keep the
   authorized private APK and its recovered sources out of Git.

## Remaining Phase 2 live acceptance work

The local route and authorized encryption-location run are complete. Session
`ses_06ca3ead51b84321b6339a444f425d7b` used `gpt-oss:20b` model ID
`17052f91a42e`, completed four tool steps in about 324 seconds, persisted five
candidate findings and a final checkpoint, and created an evidence-linked report
at zero provider cost. The initial plan and one reviewer decision required the
bounded repair paths; both repaired outputs passed local schema validation.

1. Have the app owner review the local plan, five candidate findings, source-line
   evidence, unsupported-claim risk, and generated report.
2. If hosted processing is approved, set the provider key only in the local
   environment and run the same allowed-context scenarios through OpenAI.
3. If a hosted run is approved, score both routes for correctness, evidence,
   usefulness, unsupported claims,
   latency, tokens, and cost; do not select a default from model reputation alone.
4. Deliberately stop one live run and verify the latest persisted checkpoint contains
   plan status, attempts, working memory, and usage needed for later polished
   resume support.
5. Record whether the static MVP is accepted for a small trusted test group or
   which bounded fixes are required first.

## Decisions needed before Phase 2 live acceptance

- Is ReverserX initially a personal local tool or a distributable product?
- Must analysis work completely offline, or may approved source/image context be
  sent to hosted multimodal models?
- Which artifacts and modalities may leave the machine?
- Which initial hosted and local model providers should be supported?
- What are the maximum model cost, token, step, retry, and wall-time limits per
  analysis?
- How long should APKs, recovered source, embeddings, reports, and model
  transcripts be retained?
- What exact Phase 1 and live-provider result is the go/no-go gate for releasing
  the static MVP to trusted testers?

Do not place provider API keys in chat or Git. Configure them locally through
environment variables only for approved Phase 2 live-provider evaluation.

## Useful owner work to finish acceptance

- Maintain an authorized fixture catalog with expected findings and sharing
  restrictions.
- Define a severity and confidence vocabulary for findings.
- Review the generated Markdown report structure and identify missing evidence
  fields before autonomous reporting is introduced.
- Maintain an external-tool compatibility table, including the accepted JADX
  1.5.6 partial-result behavior.
- Define the responsible-use confirmation required before later dynamic or
  network actions.

## Completed milestone checklist

- [x] The CLI installs in an isolated environment.
- [x] Dependency diagnostics report tool availability and versions.
- [x] Projects and sessions persist in SQLite.
- [x] APK/APKM inputs are safely inspected and imported without overwriting raw
  artifacts.
- [x] Base and resource-only split APKs are selected deterministically.
- [x] Static metadata, manifest, search, context, obfuscation, and report tools
  have typed results and automated coverage.
- [x] Controlled `ContextService` retrieval meets the recorded benchmark.
- [x] The authorized base APK reaches an explicit, structured partial JADX
  result rather than being misreported as a clean success.
- [x] The authorized partial source tree is indexed with all 155,643 files
  accounted for and vector metadata published for all 917,131 chunks.
- [x] Exact, regex, and bounded known-path hybrid retrieval run successfully on
  the authorized fixture.
- [x] The evidence-linked static report is generated with limitations intact.
- [ ] Owner-labeled real-fixture queries are scored and reviewed.
- [ ] Real manifest and obfuscation findings are manually sampled.
- [ ] The static report is owner-reviewed and accepted with limitations intact.

## Work to avoid now

- Do not conflate Phase 1 engineering acceptance with owner/product acceptance.
- Do not generalize from the bounded known-path query: the unguided
  natural-language real query was noisy.
- Do not describe `local-hashing-v1` as semantic understanding; it is a lexical
  hashing fallback.
- Do not generalize the file-level, memory-backed controlled benchmark to exact
  method ranking or production Chroma behavior.
- Do not assume a hybrid query exhaustively scans lexical matches; it reranks a
  bounded ANN/known-path candidate set. Use exact/regex search for that purpose.
- Do not treat the capped obfuscation result as exhaustive; it scanned at most
  100,000 files and used JADX-deobfuscated names.
- Do not present report findings as proof; they are candidate evidence requiring
  analyst review.
- Do not hide or discard the 1,095 JADX errors in retrieval or reports.
- Do not describe signing fingerprints as cryptographic verification.
- Do not commit the authorized APK, recovered proprietary source, or private
  indexes.
- Do not release the bounded agent loop to testers before the remaining Phase 1
  and Phase 2 live acceptance gates close.
- Do not start Frida, Ghidra, or broad deobfuscation work before the static
  vertical slice receives owner/product acceptance.
