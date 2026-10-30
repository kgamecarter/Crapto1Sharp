# Continuous integration and NuGet releases

## Validation and preview packages

GitHub Actions runs `.github/workflows/ci.yml` for pull requests targeting
`master`, pushes to `master`, and manual workflow dispatches. It calls the shared
`build.yml` workflow, which restores and builds the explicit
`Crapto1Sharp.slnx` solution in Release mode, then runs the test project for both
`net10.0` and `net462`.

The library is built for `netstandard1.1`, `netstandard2.0`, `net462`, and
`net10.0`. The benchmark project is compiled but benchmarks are not executed.
The SDK is selected by `global.json`; third-party actions are pinned to commits.

The project's three-part `<Version>` (currently `2.0.1`) is the source of the
release version. Local builds retain it. Normal CI builds use
`<Version>-ci.<github.run_number>`, for example `2.0.1-ci.4`. Rerunning the same
run keeps its package version; artifact names include the run attempt. These
preview packages are artifacts only and are not pushed to NuGet.org.

CI supplies Version, PackageVersion and InformationalVersion as MSBuild
properties. AssemblyVersion and FileVersion remain numeric (`2.0.1.0`), without
the prerelease suffix. Successful tests allow upload of the exact package as
`nuget-<version>-<attempt>`. TRX reports are uploaded as
`test-results-<run>-<attempt>`, including when tests fail. Retention is 30 days.

## Stable releases

Pushing a version tag such as `v2.0.1` triggers `release.yml`. It calls the same
build and test workflow with release mode enabled. Before building it requires:

- A push event for exactly `v<Version>`; malformed, prerelease, or mismatched
  tags fail validation.
- The tagged commit to be an ancestor of `master`.

The package version is exactly `2.0.1`, without a build number. Only after all
framework builds and both test suites pass does a separate publishing job
download that run's package artifact. It verifies the NuGet package ID and
version against the tag and pushes that tested package without rebuilding.

Publishing uses NuGet Trusted Publishing (OIDC), not a stored API key:

- Repository Actions variable `NUGET_USER`: `kgame` (NuGet profile name).
- GitHub Actions environment: `nuget`.
- NuGet policy owner: `kgame`.
- Repository owner/name: `kgamecarter/Crapto1Sharp`.
- Workflow file: `release.yml` (file name only).
- Environment restriction: `nuget`.
- Scope: push only new versions of package `Crapto1Sharp`; no new package IDs
  or unlist/relist permission.

Only the publishing job has `id-token: write`; CI and build/test jobs have
read-only repository permissions. NuGet credentials are obtained immediately
before pushing. A failed test, tag check, package check, or login prevents push.
An existing package version causes a push failure rather than a silent skip.

To release: update the project version and release notes, merge through a
passing PR, then push the matching tag on the merged commit. Never move a tag
or reuse a version after publication. Re-run a failed publishing job only after
checking whether NuGet already accepted the package. Changing the workflow file,
environment, owner, or repository requires updating the NuGet trust policy.

See [NuGet Trusted Publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing).

## 2.0.1 release notes

- Fix cancellation while submitting candidate batches after validation has
  already determined the result.
- Join validation workers and release queued pooled buffers before propagating
  worker failures.
- Add regression coverage for cancellation, a full queue, and worker cleanup.

## AppVeyor migration audit (2026-10-31)

The authenticated AppVeyor project settings for `kgame/crapto1sharp` were
inspected before migration:

- Version format: `2.0.0.{build}`; next build number: 36.
- Only `master` builds; tag builds disabled; no build schedule.
- Image: Visual Studio 2026; configuration: Release.
- .NET project patching enabled for `**\*.csproj`. Version, VersionPrefix,
  PackageVersion, AssemblyVersion, FileVersion, and InformationalVersion were
  configured as `{version}` (only applicable existing elements are patched).
- Before build: `dotnet restore`; build mode: automatic MSBuild selection.
- Test commands still target obsolete `netcoreapp2.1` and `net461` output paths.
- No deployment providers or deployment scripts configured.
- No custom artifacts configured.
- NuGet project-feed API key: not configured. Project/account feeds are not
  automatically added as build package sources. This feed is distinct from
  NuGet.org publishing.
- Exported YAML contains no environment variables or publishing commands.

The old build failed after restore with an ambiguous project/solution selection
error. Actions uses explicit solution and project paths and the current test
frameworks.

Cutover procedure: verify a successful Actions PR run, merge the workflow, and
verify a successful `master` run before disabling AppVeyor's Push and Pull
request triggers. Keep the AppVeyor project and history available for reference;
do not delete the project or revoke account-wide access used by other projects.
To roll back, re-enable those two triggers and repair the legacy build/test
commands before relying on AppVeyor again.
