# Contributing to ReverserX

ReverserX is pre-alpha. Contributions should preserve evidence provenance,
explicit authorization boundaries, and deterministic behavior before adding AI
interpretation.

## Development setup

Requirements:

- Python 3.11 or newer
- `uv`
- Git
- Java and JADX for Phase 1 static-analysis work

Install the project and development dependencies:

```bash
git clone https://github.com/sandeepstele/ReverserX.git
cd ReverserX
uv sync --locked --extra dev --extra phase1
uv run reverserx --help
```

Run all checks before committing:

```bash
make check
```

Individual commands are also available:

```bash
uv run ruff format .
uv run ruff check .
uv run mypy
uv run pytest
```

## Local runtime data

Keep analysis data outside tracked source files. For repository-local testing:

```bash
uv run reverserx --data-dir .reverserx init
```

`.reverserx/`, `.env`, databases, and generated artifacts are ignored by Git.
Never commit API keys, proprietary APKs, runtime captures, tokens, or reports
containing sensitive target data.

## Change expectations

- Add or update tests for behavior changes.
- Return typed, versioned tool results.
- Use argument vectors; never interpolate untrusted input into shell commands.
- Record source artifact, tool version, and locator for evidence.
- Keep model inference distinct from observed facts.
- Fail clearly when optional dependencies are unavailable.
- Add a migration rather than modifying a released database schema in place.
- Update the relevant phase document when scope or acceptance criteria change.

## Fixtures

Only use fixtures that the project is authorized to analyze and allowed to
redistribute. Prefer small applications built specifically for ReverserX with
known expected findings. Do not add third-party production APKs to the
repository.

## Commit messages

Use concise, action-oriented messages. Conventional prefixes are encouraged:
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, and `chore:`.
