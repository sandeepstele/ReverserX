# Security Policy

ReverserX is intended for authorized security research. The current codebase is
pre-alpha and should not be treated as a security boundary for hostile,
untrusted multi-user workloads.

## Reporting a vulnerability

Do not open a public issue containing exploitable details, secrets, proprietary
artifacts, or target data. Contact the repository owner privately with:

- affected version or commit;
- reproduction steps using a safe fixture;
- impact and prerequisites;
- suggested mitigation, if known.

## Current security properties

- External commands use argument vectors without an implicit shell.
- Command execution supports timeouts, cancellation, and bounded retained output.
- Imported artifacts are content-addressed, project-separated, and made read-only.
- Tool arguments are validated against explicit Pydantic schemas.
- Configuration output and configured logs redact known provider secrets.
- Local database and artifact paths are excluded from version control.

## Known pre-alpha limitations

- The local user running ReverserX can modify its database and artifact store.
- SQLite and artifacts are not encrypted at rest.
- Artifact parsing isolation and resource quotas are not yet complete.
- Scope confirmation gates for dynamic and network actions arrive in Phase 3.
- Generated instrumentation scripts are not implemented and must eventually be
  treated as untrusted code.

Use a dedicated environment for unknown artifacts and never analyze a target
without explicit authorization.
