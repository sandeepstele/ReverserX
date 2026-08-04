# Phase 2 — Agent Orchestration and Model Routing

**Original duration:** 5–7 weeks full-time

**Implementation status:** Complete

**Engineering scenario status:** Complete with recorded providers

**Live-provider/owner acceptance status:** Local provider complete; hosted and
owner review pending

**Goal:** Use the reliable static tools through a bounded plan-execute-review
loop with transparent model selection and cost controls.

## Implemented baseline

- Provider-independent text, code, image, and artifact-reference message parts;
  every image carries a digest, media type, artifact ID, locator, and transient
  bytes that are excluded from persistence.
- Capability-first routing across local Ollama and optional hosted OpenAI
  Responses adapters, with explicit modality, structured-output, context, privacy,
  quality, preference, and cost filters.
- Project-persistent `--local-models-only` policy plus per-run `--local-only`.
- Configurable provider pricing and estimates that include image accounting.
- Strict planner and reviewer schemas, one bounded plan-repair attempt,
  registered-tool validation before execution, finite reviewer transitions,
  transient-only provider retries, repeated-call loop detection, and hard limits.
- SQLite persistence for sessions, plan attempts, tool-run linkage, evidence,
  findings, model usage, image counts, request IDs, and recovery checkpoints.
- Read-only `agent estimate`, confirmed `agent run`, `agent sessions`, and
  `agent show` CLI commands.
- Evidence-linked agent Markdown reporting with explicit static-analysis
  limitations.
- Recorded scenario tests for deterministic transitions, plan repair, privacy
  routing, transient retry, cost and step stops, evidence lineage, checkpoints,
  and a complete synthetic evidence-to-report run.

The repository gate is 232 passing tests with 85% measured coverage. Ruff,
strict MyPy, locked dependencies, and package builds are part of the final gate.
This does not establish live-provider output quality on the authorized app.

## Deliverables

- Common provider interface and normalized model responses.
- Typed multimodal message parts for text, code, images, and artifact references.
- Provider capability registry covering modalities, context limits, privacy
  location, structured output, and tool calling.
- Initial hosted reasoning provider plus local/Ollama provider; add further
  providers only through the same contract.
- Prompt templates with explicit structured outputs.
- Task classifier and configurable model-routing policy.
- Pricing configuration, token-usage ledger, pre-run estimate, and actual-cost
  report.
- Planner producing validated plan-step schemas.
- Executor allowing only registered tools and validated arguments.
- Reviewer able to accept, retry, refine, inject, or stop a step.
- Working memory for findings, hypotheses, key locations, and unresolved items.
- Checkpoints sufficient to recover a failed run, even though polished full
  resume is delivered later.
- Global limits for cost, tokens, steps, retries, tool duration, and wall time.
- Human confirmation before expensive or scope-changing actions.

## Work breakdown

1. Define typed text, code, image, and artifact-reference message parts.
2. Implement provider adapters and recorded fake providers for tests.
3. Define task categories, capability requirements, and routing policies
   independently of model names.
4. Record estimates and actual usage for every request, including image inputs.
5. Implement planner validation and repair for invalid structured output.
6. Implement executor state transitions and idempotency rules.
7. Implement reviewer decisions with a finite set of allowed transitions.
8. Add loop and recursion detection.
9. Build scenario tests from fixed text-only and multimodal transcripts.
10. Compare routed output quality and cost against a single-model baseline.

## Acceptance criteria

- The same recorded responses reproduce the same state transitions.
- Invalid plans or tool arguments never reach a tool implementation.
- A user-set cost or step limit always stops the loop.
- Retry policy distinguishes transient failures from invalid requests.
- Every finding identifies its supporting tool evidence and model interpretation.
- The user sees estimated cost before execution and actual cost afterward.
- Hosted providers can be disabled for a project.
- Image-bearing tasks route only to providers that declare image support.
- Hosted multimodal providers never receive an image when project policy is
  local-only, and unsupported modalities produce an explicit routing error.
- Every image input retains an artifact digest, media type, and evidence source.
- A complete fixture run answers the static encryption-location goal and creates
  an evidence-linked Markdown report.

## Acceptance record

- [x] Recorded responses reproduce identical typed state transitions.
- [x] Invalid plans and tool arguments are rejected or repaired before execution.
- [x] Cost, token, step, retry, tool-duration, and wall-time limits are enforced.
- [x] Transient provider errors are retried; invalid requests are not.
- [x] Model findings link to persisted tool evidence.
- [x] Estimates precede explicit CLI confirmation; actual usage is persisted and
  displayed afterward.
- [x] Hosted models can be disabled persistently for a project.
- [x] Image and privacy routing conflicts fail explicitly without dropping parts.
- [x] A complete recorded fixture run creates an evidence-linked Markdown report.
- [x] Run the configured live Ollama model and record model/version, latency,
  structured-output compliance, and cost.
- [ ] Run the approved hosted provider on allowed fixture context and compare its
  correctness, evidence, usefulness, unsupported claims, and cost with Ollama.
- [x] Exercise the authorized APK encryption-location goal end to end and create
  the evidence-linked report.
- [ ] Have the owner review the live plan, findings, evidence links, unsupported
  claims, and report.
- [ ] Deliberately interrupt a live run and confirm the checkpoint contains enough
  state for the planned Phase 5 polished resume workflow.

## Local live-provider record

- Authorized fixture: supplied APKM contents matched the retained private base and
  split artifacts byte-for-byte, so the completed decompile/index lineage was
  reused.
- Provider/model: Ollama 0.30.11, `gpt-oss:20b`, model ID `17052f91a42e`, 20.9B
  parameters, MXFP4, declared 131,072-token context.
- Completed session: `ses_06ca3ead51b84321b6339a444f425d7b` in approximately
  324 seconds with four successful tool steps and checkpoint sequence 6.
- Usage: 45,786 input tokens, 2,178 output tokens, seven recorded model calls,
  and $0 provider cost.
- Structured output: the initial planner response required the single bounded
  plan-repair turn; one reviewer response required the single bounded reviewer
  repair added from live-test feedback. All executed tool names and arguments
  passed the local registry/schema boundary.
- Result: five candidate findings, 50 bounded source references across the three
  analysis evidence records, and a session-scoped Markdown report. The report
  explicitly states that static evidence does not prove runtime behavior.
- Live-test fixes: adaptive Ollama context sizing, goal/scope/tool-schema-preserving
  plan repair, exact argument-key guidance, one bounded reviewer repair, explicit
  final-tool enforcement, line-level evidence rendering, and Ctrl-C pause/checkpoint
  persistence. A follow-up audit added schema-v5 persistence for both rejected and
  accepted planner attempts so future repairs retain their raw/structured outputs
  and validation errors.

## What you can do

- Set the maximum acceptable cost and runtime for a fixture analysis.
- Review generated plans for unnecessary or unsafe steps.
- Score model answers using a simple rubric: correctness, evidence, usefulness,
  unsupported claims, and cost.
- Decide which artifact types are allowed to go to hosted providers.
- Test interruption and resume after deliberately stopping runs.

## Release point

At the end of this phase ReverserX is a useful **static Android analysis MVP**.
Release it to a small trusted test group before adding dynamic integrations.
