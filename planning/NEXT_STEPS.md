# What You Can Do Now

The Phase 0 software foundation is implemented. The best immediate contribution
is now to prepare the fixtures and product decisions required for Phase 1.

## Foundation decisions completed

- Python 3.11+ is the supported language baseline.
- `uv` manages environments, locking, and developer commands.
- macOS on Apple Silicon is the initial development host; Ubuntu x86_64 is
  validated in CI.
- Runtime data is local by default, with SQLite and content-addressed artifacts.
- Hosted-model credentials are loaded from environment variables and redacted.

## This week

- Run `uv run reverserx doctor` and install a functional Java runtime. JADX is
  present on the initial machine, but its Java dependency must be usable before
  Phase 1 integration tests.
- Install Android Platform Tools before Phase 3; ADB is not required for the
  Phase 1 static pipeline.
- Obtain two legally usable APK fixtures:
  - one small, unobfuscated application;
  - one application you control that contains a known crypto flow.
- Write down the first demonstration goal: for example, “Given the fixture APK,
  locate the encryption implementation and produce cited code evidence.”
- Create API accounts or local endpoints for the initial two model providers.
  Do not commit keys; decide how local environment secrets will be loaded.
- Decide a monthly development/API budget and a maximum cost per analysis run.

## Product decisions you should make

Document short answers to the following before implementation:

1. Is ReverserX initially a personal local tool or a distributable product?
2. Must the first MVP work completely offline, or is a hosted model allowed?
3. Which Android versions and CPU architectures must be supported first?
4. Will the MVP require a rooted emulator/device, or only static analysis?
5. What result proves the MVP is successful?
6. Which artifacts may leave the machine for hosted-model analysis?
7. How long should APKs, captures, and model transcripts be retained?

## Useful non-coding work

- Build an authorized fixture catalog with expected findings.
- Define a severity and confidence vocabulary for findings.
- Draft a sample final report by hand. This reveals which evidence fields the
  storage and tool contracts must preserve.
- Create expected-result files for manifest analysis, source retrieval, and
  encryption discovery.
- Maintain an external-tool compatibility table as versions are tested.
- Define a responsible-use statement and the exact confirmation required before
  dynamic or network actions.

## Work to avoid initially

- Do not begin with a generic autonomous agent loop. First make deterministic
  tools produce dependable structured results.
- Do not install Redis until concurrent workers create a demonstrated need.
- Do not attempt generic deobfuscation before normal APK analysis is reliable.
- Do not start Ghidra/JNI tracing before the Java/Kotlin static pipeline works.
- Do not optimize provider cost without recording actual token use and quality.
- Do not use third-party APKs without clear authorization and licensing.

## First milestone checklist

The software portion of the first milestone is complete:

- [x] The CLI installs in an isolated environment.
- [x] `reverserx doctor` reports dependency availability and versions.
- [x] A project can be created and reopened.
- [x] An artifact can be imported without overwriting the original.
- [x] A dummy tool invocation is recorded in SQLite with logs and status.
- [x] Unit tests and lint/type checks run through one documented command.

Begin Phase 1 implementation after an authorized APK fixture and its expected
static-analysis results are available.
