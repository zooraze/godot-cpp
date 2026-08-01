from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .canonical import file_hashes, sha256_file


def _verification_code(paths: list[Path]) -> str:
    sha1_values = [hashlib.sha1(path.read_bytes()).hexdigest() for path in paths]
    return hashlib.sha1("".join(sorted(sha1_values)).encode("ascii")).hexdigest()



def package_spdx(package_id: str, contract_sha256: str, root: Path) -> dict[str, Any]:
    hashes = file_hashes(root, {"sbom/package.spdx.json", "METADATA.json", "MANIFEST.sha256"})
    files = []
    relationships = []
    verification_paths = []
    for index, (name, digest) in enumerate(sorted(hashes.items()), start=1):
        spdx_id = f"SPDXRef-File-{index}"
        verification_paths.append(root / name)
        files.append({
            "SPDXID": spdx_id,
            "fileName": f"./{name}",
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })
        relationships.append({"spdxElementId": "SPDXRef-Package", "relationshipType": "CONTAINS", "relatedSpdxElement": spdx_id})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{package_id}-sbom",
        "documentNamespace": f"https://github.com/zooraze/godot-cpp/spdx/{contract_sha256}/{package_id}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: godot-cpp-release-tooling-v1"]},
        "packages": [{
            "SPDXID": "SPDXRef-Package",
            "name": package_id,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
            "packageVerificationCode": {"packageVerificationCodeValue": _verification_code(verification_paths)},
        }],
        "files": files,
        "relationships": relationships,
    }


def release_spdx(tag: str, packages: list[Path]) -> dict[str, Any]:
    entries = []
    relationships = []
    verification_paths = []
    for index, package in enumerate(sorted(packages, key=lambda p: p.name), start=1):
        spdx_id = f"SPDXRef-Artifact-{index}"
        verification_paths.append(package)
        entries.append({
            "SPDXID": spdx_id,
            "fileName": f"./{package.name}",
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_file(package)}],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })
        relationships.append({"spdxElementId": "SPDXRef-Release", "relationshipType": "CONTAINS", "relatedSpdxElement": spdx_id})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"godot-cpp-{tag}-release-sbom",
        "documentNamespace": f"https://github.com/zooraze/godot-cpp/releases/{tag}/sbom",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: godot-cpp-release-tooling-v1"]},
        "packages": [{
            "SPDXID": "SPDXRef-Release",
            "name": tag,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": "NOASSERTION",
            "packageVerificationCode": {"packageVerificationCodeValue": _verification_code(verification_paths)},
        }],
        "files": entries,
        "relationships": relationships,
    }
