# Phase 5 — Full Persistence and Evidence Reporting

**Duration:** 4–6 weeks full-time  
**Goal:** Make long-running analyses resumable, auditable, and suitable for
responsible security reporting.

## Deliverables

- Versioned serialized state for plans, steps, working memory, limits, and user
  confirmations.
- Resume validation for missing devices, artifacts, indexes, models, and tools.
- Rebuildable ChromaDB indexes referenced from durable SQLite metadata.
- Evidence graph relating findings to code, hooks, captures, and tool runs.
- Finding lifecycle: candidate, confirmed, rejected, mitigated, and duplicate.
- Markdown report with evidence links and Mermaid flow diagrams.
- Self-contained HTML report with redaction controls.
- Cost, token, tool-version, and audit appendices.
- Export bundle manifest with checksums.
- Database backup, migration, and recovery documentation.

## Work breakdown

1. Define what must resume and what must be re-established externally.
2. Add schema-version checks and migration tests.
3. Implement evidence traversal and broken-reference detection.
4. Build report views from stored data, not directly from model prose.
5. Add configurable secret/PII redaction and report previews.
6. Add diagrams only where graph/state data supports them.
7. Add export integrity verification.
8. Evaluate whether concurrent workers now justify Redis; keep it optional if
   SQLite and in-process state remain sufficient.

## Acceptance criteria

- A process can stop after any completed step and resume without repeating a
  non-idempotent action silently.
- Resume explains which device/proxy state must be recreated.
- A deleted vector index can be rebuilt from durable artifacts.
- Every report claim links to evidence or is explicitly labeled as inference.
- Redacted reports do not contain fixture secrets in text, metadata, or embedded
  raw events.
- Export checksum verification detects modification.
- Old test databases migrate forward without losing findings or evidence links.

## What you can do

- Draft the exact Markdown and HTML report structure you want.
- Review which evidence may appear in reports by default.
- Test resume across process restarts and external-tool upgrades.
- Review every finding for the observed-versus-inferred distinction.
- Give sample reports to trusted security researchers and collect feedback.
