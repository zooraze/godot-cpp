# Security policy

Report suspected vulnerabilities privately through GitHub's security advisory interface. Do not include secrets, private source, or customer data in public issues.

Published package assets are immutable. A confirmed package compromise is handled by publishing a revocation record and a successor build. Build workflows use read-only untrusted pull-request permissions, full-SHA-pinned allowlisted actions, exact source and toolchain inputs, GitHub OIDC attestations, and a protected promotion environment.
