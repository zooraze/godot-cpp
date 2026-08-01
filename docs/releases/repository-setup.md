# Repository setup

The public repository is `zooraze/godot-cpp`, with default branch `master`, based on upstream commit `ba0edfed90512ec64aba51d4295a3e7e30112f86`. The release tooling is applied in one reviewed feature branch and merged without rewriting upstream history.

Protect `master` before accepting the feature branch. Require a pull request, require the pull-request workflow checks for both supported platforms, require the branch to be current, block force pushes, and block deletion. Permit only the normal merge method selected for the initial release-tooling pull request.

Create an environment named `release`. Restrict it to protected branches, configure the approved human reviewer model, and add no environment secrets. Production candidates build before the environment gate; only the promotion job enters the environment and receives `contents: write`.

Enable repository release immutability before the first production run. GitHub applies immutability only after publication, so the workflow creates a complete draft, round-trips every draft asset, and publishes once. The workflow then requires GitHub to report the release as immutable and dispatches independent verification.

Repository Actions policy permits only the checked-in full-SHA action allowlist. Hosted builds use `ubuntu-22.04` and `windows-2025-vs2026`; caches, schedules, larger or paid runners, self-hosted runners, private build inputs, and cross-repository credentials are prohibited. The personal-account repository disables attestation storage records and does not grant `artifact-metadata: write`.

The hosted images do not define the release ABI by themselves. Every package and independent consumer job runs `prepare-toolchain` first. On Linux this installs the authenticated LLVM 17 package suite after checking the repository signing-key fingerprint. On Windows this adds the reviewed MSVC 14.50 side-by-side component through the existing Visual Studio Installer. The build then selects the exact toolset and SDK through `vcvarsall.bat` and verifies the resolved compiler path and version. Do not replace these steps with the image-default compiler.
