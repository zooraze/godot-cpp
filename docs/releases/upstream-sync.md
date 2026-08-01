# Upstream synchronization

The public repository is a fork of `godotengine/godot-cpp` and preserves upstream history. The `upstream` remote points to the canonical repository. Upstream updates enter `master` through a reviewed pull request that records the old and new upstream commits and reruns the full package matrix.

Generally useful source fixes should be proposed upstream. Any temporary source divergence must be public, generally useful, listed in the package contract's patch inventory, and removed when upstream accepts or supersedes it. Release tooling and packaging policy may remain fork-specific.

Private product source, private paths, private compatibility policy, credentials, or private fixtures are prohibited from this repository and its release artifacts.
