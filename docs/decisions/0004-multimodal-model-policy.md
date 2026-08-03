# ADR 0004: Capability-first multimodal model policy

- **Status:** Accepted
- **Date:** 2026-08-03

## Decision

Design the Phase 2 provider interface around typed message parts rather than a
single text prompt. Supported part types begin with text, code, image, and
artifact reference. Every provider advertises its supported modalities,
context limits, privacy location, structured-output support, and tool-calling
support.

Routing first satisfies task capability and project privacy requirements, then
optimizes quality and cost. A visual task can use screenshots, rendered Android
resources, runtime UI states, QR codes, or other image evidence. Each image part
retains its media type, digest, source artifact, and evidence locator.

## Consequences

- Text-only code analysis remains the default for Phase 1.
- Multimodal support is implemented in Phase 2 without redesigning prompts or
  persistence around one provider.
- Unsupported modalities cause an explicit routing error; they are never
  silently removed.
- Hosted providers do not receive images or code from a local-only project.
- Text descriptions or OCR derived from an image are new evidence-linked
  artifacts, not invisible replacements for the original input.
- Token and cost estimation must include provider-specific image accounting.
