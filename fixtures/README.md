# Test Fixtures

Only authorized, legally usable fixtures belong in the ReverserX test process.

- `fixtures/private/` is ignored by Git and may contain local APK/APKM fixtures
  that must never be pushed.
- Redistributable synthetic fixtures may be added to a future tracked directory
  with their source and license.
- Every fixture should have a short metadata record describing authorization,
  expected findings, package, version, architecture, and required splits.

Do not commit production APKs, proprietary applications, captures, credentials,
or extracted application source.
