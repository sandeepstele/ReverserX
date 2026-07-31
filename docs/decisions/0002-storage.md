# ADR 0002: SQLite source of truth and content-addressed artifacts

- **Status:** Accepted
- **Date:** 2026-08-01

## Decision

Use SQLite as the durable metadata and session store. Store imported binaries
and generated raw artifacts as immutable, content-addressed files separated by
project. Treat future vector indexes as derived and rebuildable.

## Consequences

- Local setup has no mandatory database service.
- Duplicate content within a project reuses one blob.
- Schema changes require ordered migrations and migration tests.
- Redis remains optional until concurrent workers demonstrate a concrete need.
- Encryption at rest is not provided by this foundation and must be handled by
  the host or a later storage feature.
