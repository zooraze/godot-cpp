# Release policy

Pull requests run read-only workflows with no secrets, no `pull_request_target`, and no publication capability. Production builds run only through a manually dispatched workflow for an exact reviewed commit reachable from the protected `master` branch.

The production matrix is static. Platform jobs have `contents: read`, `id-token: write`, and `attestations: write`. This personal-account repository disables attestation storage-record creation, so `artifact-metadata: write` is not granted. Only the final promotion job receives `contents: write`, and it runs behind the protected `release` environment.

Promotion first verifies the complete expected matrix, internal manifests, metadata, checksums, offline attestation bundles, and online signer identity. It then creates a draft release, uploads all assets, verifies the remote asset inventory, and publishes once. Repository release immutability must be enabled before the first production publication.

A separate workflow downloads every asset anonymously, verifies release and artifact attestations, checks all checksums again, and compiles and links a minimal consumer on both supported platforms. Publication explicitly dispatches this workflow because events created with the repository workflow token do not reliably start another workflow; the `release: published` trigger remains as a fallback for externally published releases.
