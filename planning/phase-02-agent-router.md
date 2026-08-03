# Phase 2 — Agent Orchestration and Model Routing

**Duration:** 5–7 weeks full-time  
**Goal:** Use the reliable static tools through a bounded plan-execute-review
loop with transparent model selection and cost controls.

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
