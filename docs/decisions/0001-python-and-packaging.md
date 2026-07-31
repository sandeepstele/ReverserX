# ADR 0001: Python baseline and packaging

- **Status:** Accepted
- **Date:** 2026-08-01

## Decision

Support Python 3.11 and newer, use a `src/` package layout, standard
`pyproject.toml` metadata, and `uv` for developer environment and lock-file
management. Build through setuptools so source and wheel installs follow common
Python packaging behavior.

## Consequences

- Code must not require language syntax newer than Python 3.11.
- The initial development hosts are macOS on Apple Silicon and Ubuntu x86_64.
- CI tests Ubuntu with the oldest supported baseline and the current development
  version; macOS is exercised on the primary development machine.
- Optional reverse-engineering integrations must not prevent the base CLI from
  installing.
- Dependency updates are reviewed through the committed `uv.lock` file.
