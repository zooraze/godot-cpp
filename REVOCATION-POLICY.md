# Binary Release Revocation Policy

Published release assets are immutable and are never replaced in place.

A deprecated package remains available for exact existing pins, but new consumers should select a successor. A revoked package must not be newly installed or accepted. Revocation is published as a new immutable record identifying the affected SHA-256 digest, the reason, the effective date, and a replacement when one exists.

Removal of an immutable release is reserved for legal obligations or severe security emergencies. Removal requires an explicit maintainer decision and a public record explaining the action. Routine defects are handled by publishing a successor build revision.

The machine-readable revocation index is `release/revocations.json`. Consumers must fail closed on a matching digest and may cache the last verified index for offline use.
