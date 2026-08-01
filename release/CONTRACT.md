# Public binary compatibility contract

The versioned compatibility object embedded in every package is the consumer contract. Its canonical digest is SHA-256 over UTF-8 JSON serialized with keys sorted, no insignificant whitespace, no ASCII escaping, and one trailing newline. The implementation is `tools/release_lib/canonical.py`; the schema is `release/schemas/compatibility-contract-v1.schema.json`.

Consumers must compare the complete object or its digest. They must not infer compatibility from filenames. Unknown, missing, or changed fields are incompatible until reviewed. Platform-independent inputs and platform ABI fields are both included, so Windows and Linux packages intentionally have different compatibility digests.

The v1 package layout and metadata are defined by `package-metadata-v1.schema.json`. The release-level atomic matrix and sidecar inventory are defined by `release-manifest-v1.schema.json`. Published schema files are immutable within a schema version; incompatible changes require v2.

Toolchain provisioning is part of the compatibility object. Linux uses the authenticated `llvm-toolchain-jammy-17` repository and rejects any compiler other than Clang 17.0.6. Windows installs the reviewed Visual Studio component `Microsoft.VisualStudio.Component.VC.14.50.18.0.x86.x64`, selects toolset folder `14.50.35717`, SDK `10.0.26100.0`, and rejects any `cl.exe` that does not report compiler version `19.50.35737`. Provisioning failure is a build failure; no runner default is accepted as a fallback.
