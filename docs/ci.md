# Continuous integration

GitHub Actions runs `.github/workflows/ci.yml` for pull requests targeting
`master`, pushes to `master`, and manual workflow dispatches. The Windows job
restores and builds the explicit `Crapto1Sharp.slnx` solution in Release mode,
then runs the test project for both `net10.0` and `net462`.

The library is built for `netstandard1.1`, `netstandard2.0`, `net462`, and
`net10.0`. The benchmark project is compiled but benchmarks are not executed in
CI. The SDK is selected by `global.json`, and third-party action references are
pinned to their release commit IDs.

## Versioning and artifacts

The project file's three-part `<Version>` (currently `2.0.0`) is the source of
the release version. Local builds retain that version. CI appends a build
number: `<Version>.<github.run_number + 35>`. Thus the first Actions run uses
`2.0.0.36`, continuing from AppVeyor build 35. Rerunning the same workflow run
keeps its package version; artifact names include the run attempt.

CI supplies Version, PackageVersion, AssemblyVersion, FileVersion and
InformationalVersion as MSBuild properties instead of modifying source files.
Keep the workflow run counter/offset in mind if replacing this workflow or
changing to a different version format in the future.

Successful builds upload the `.nupkg` under `nuget-<version>-<attempt>`.
TRX test reports are uploaded under `test-results-<run>-<attempt>`, including
when tests fail. Artifacts are retained for 30 days.

This workflow does not publish to NuGet.org or GitHub Packages and requires no
publishing credentials. Downloading a CI artifact does not publish a package.
A future publishing workflow should be configured separately from PR validation.

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
