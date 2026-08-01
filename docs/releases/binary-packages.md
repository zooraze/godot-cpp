# Binary package contract

Binary releases are convenience products built from an upstream-aligned `godot-cpp` fork. They do not change Godot's GDExtension compatibility rules.

Each package binds an exact upstream commit, Godot API dump, class-generation profile, platform, architecture, compiler, standard library or CRT, target, optimization mode, precision, threading, exception mode, RTTI mode, and other generation flags. Consumers compare the complete machine-readable contract and fail closed on missing or unknown fields.

Archives contain `METADATA.json`, `MANIFEST.sha256`, exact API inputs, public and generated headers, one static library, license texts, an SPDX SBOM, and build provenance. `MANIFEST.sha256` covers the payload and deliberately excludes itself and `METADATA.json`; the metadata records the manifest digest, while the release-level checksum covers the complete archive.

The canonical compatibility digest is SHA-256 over normalized JSON containing compatibility fields only. Run IDs, timestamps, archive names, and repository-host metadata do not affect it. Source revisions, public patch identities, generated API/profile identities, build switches, and platform ABI fields do.

## Reviewed build toolchains

The current standard runner images do not supply the approved compiler versions as defaults. The workflows provision and verify Clang 17.0.6 on Ubuntu 22.04 and MSVC 19.50.35737 from Build Tools folder 14.50.35717 on `windows-2025-vs2026`. These provisioning inputs are embedded in each package compatibility object and therefore change the compatibility digest if modified.
