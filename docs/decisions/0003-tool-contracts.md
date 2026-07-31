# ADR 0003: Typed, registered tool contracts

- **Status:** Accepted
- **Date:** 2026-08-01

## Decision

Every tool declares a unique name, description, version, and strict Pydantic
input model. A central registry is the only execution boundary exposed to the
future agent. Tools return structured results and do not accept arbitrary shell
fragments.

## Consequences

- Invalid or undeclared arguments are rejected before tool execution.
- Tool schemas can be converted into model function-calling definitions.
- Deterministic tool adapters remain testable without an AI provider.
- Tool implementation versions are persisted with runs for reproducibility.
- Adding a tool requires registration, contract tests, and documented external
  dependencies.
