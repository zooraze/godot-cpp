from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .archive import read_archive, validate_archive_structure
from .canonical import canonical_bytes, sha256_bytes, sha256_file
from .contracts import compatibility, contract_digest, package_filename, package_id

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")


def _json_member(files: dict[str, bytes], name: str) -> Any:
    try:
        return json.loads(files[name].decode("utf-8"))
    except KeyError as error:
        raise ValueError(f"missing archive member: {name}") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON member: {name}") from error


def _manifest(files: dict[str, bytes]) -> dict[str, str]:
    try:
        text = files["MANIFEST.sha256"].decode("utf-8")
    except KeyError as error:
        raise ValueError("missing MANIFEST.sha256") from error
    result: dict[str, str] = {}
    previous = ""
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            raise ValueError(f"invalid manifest line: {line!r}")
        digest, name = match.groups()
        if name <= previous or name in result:
            raise ValueError("manifest entries must be unique and sorted")
        previous = name
        result[name] = digest
    return result


def _validate_metadata(metadata: dict[str, Any]) -> None:
    required = {
        "schema_version", "package_id", "contract_sha256", "compatibility", "source",
        "build_provenance", "payload_manifest_sha256", "payload", "reproducibility",
    }
    if set(metadata) != required or metadata["schema_version"] != 1:
        raise ValueError("metadata does not conform to schema v1")
    if not _SHA64.fullmatch(metadata["contract_sha256"]):
        raise ValueError("invalid metadata contract digest")
    source = metadata["source"]
    if set(source) != {"upstream_repository", "upstream_commit", "fork_repository", "fork_commit", "public_patches"}:
        raise ValueError("invalid source metadata")
    if not _SHA40.fullmatch(source["upstream_commit"]) or not _SHA40.fullmatch(source["fork_commit"]):
        raise ValueError("invalid source commit")
    if metadata["reproducibility"] not in {"untested", "structurally-reproducible", "byte-reproducible"}:
        raise ValueError("invalid reproducibility value")


def _verify_sbom(files: dict[str, bytes], metadata: dict[str, Any]) -> None:
    sbom = _json_member(files, "sbom/package.spdx.json")
    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("invalid SPDX package document")
    expected: dict[str, str] = {}
    for entry in sbom.get("files", []):
        name = entry.get("fileName", "")
        checksums = entry.get("checksums", [])
        if not name.startswith("./") or len(checksums) != 1 or checksums[0].get("algorithm") != "SHA256":
            raise ValueError("invalid SPDX file entry")
        expected[name[2:]] = checksums[0].get("checksumValue", "")
    actual_names = set(files) - {"sbom/package.spdx.json", "METADATA.json", "MANIFEST.sha256"}
    if set(expected) != actual_names:
        raise ValueError("SPDX file inventory mismatch")
    for name, digest in expected.items():
        if sha256_bytes(files[name]) != digest:
            raise ValueError(f"SPDX checksum mismatch: {name}")
    if sha256_bytes(files["sbom/package.spdx.json"]) != metadata["payload"]["sbom_sha256"]:
        raise ValueError("SPDX digest mismatch")


def verify_package(path: Path, contract: dict[str, Any], matrix_id: str, source_commit: str | None = None) -> dict[str, Any]:
    validate_archive_structure(path)
    files = read_archive(path)
    metadata = _json_member(files, "METADATA.json")
    _validate_metadata(metadata)

    expected_id = package_id(contract, matrix_id)
    if metadata["package_id"] != expected_id:
        raise ValueError("package identity mismatch")
    expected_compatibility = compatibility(contract, matrix_id)
    if metadata["compatibility"] != expected_compatibility:
        raise ValueError("compatibility contract mismatch")
    digest = contract_digest(contract, matrix_id)
    if metadata["contract_sha256"] != digest:
        raise ValueError("compatibility digest mismatch")
    if source_commit and metadata["source"]["fork_commit"] != source_commit:
        raise ValueError("fork commit mismatch")

    manifest = _manifest(files)
    expected_manifest_names = set(files) - {"MANIFEST.sha256", "METADATA.json"}
    if set(manifest) != expected_manifest_names:
        raise ValueError("manifest inventory mismatch")
    for name, expected_digest in manifest.items():
        if sha256_bytes(files[name]) != expected_digest:
            raise ValueError(f"manifest checksum mismatch: {name}")
    if sha256_bytes(files["MANIFEST.sha256"]) != metadata["payload_manifest_sha256"]:
        raise ValueError("manifest digest mismatch")

    payload = metadata["payload"]
    required = {"extension_api_sha256", "profile_sha256", "sbom_sha256", "licenses", "library"}
    if set(payload) != required:
        raise ValueError("invalid payload metadata")
    checks = {
        "api/extension_api.json": contract["godot"]["extension_api_sha256"],
        "profile/build_profile.json": contract["profile"]["sha256"],
        "licenses/GODOT-CPP-LICENSE.md": payload["licenses"]["godot_cpp_sha256"],
        "licenses/GODOT-LICENSE.txt": payload["licenses"]["godot_sha256"],
        payload["library"]["path"]: payload["library"]["sha256"],
    }
    for name, expected_digest in checks.items():
        if name not in files or sha256_bytes(files[name]) != expected_digest:
            raise ValueError(f"payload checksum mismatch: {name}")
    if payload["extension_api_sha256"] != checks["api/extension_api.json"]:
        raise ValueError("API identity mismatch")
    if payload["profile_sha256"] != checks["profile/build_profile.json"]:
        raise ValueError("profile identity mismatch")
    if not any(name.startswith("include/godot_cpp/") for name in files):
        raise ValueError("missing godot-cpp headers")
    if "include/gdextension_interface.h" not in files:
        raise ValueError("missing GDExtension interface header")
    _verify_sbom(files, metadata)
    return metadata


def verify_candidate(descriptor_path: Path, contract: dict[str, Any], require_attestations: bool) -> dict[str, Any]:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    if descriptor.get("schema_version") != 1:
        raise ValueError("invalid candidate descriptor")
    matrix_id = descriptor["matrix_id"]
    if matrix_id not in contract["expected_matrix"]:
        raise ValueError("unexpected candidate matrix")
    if descriptor.get("package_id") != package_id(contract, matrix_id):
        raise ValueError("candidate package identity mismatch")
    if descriptor.get("contract_sha256") != contract_digest(contract, matrix_id):
        raise ValueError("candidate contract digest mismatch")
    if descriptor.get("package", {}).get("filename") != package_filename(contract, matrix_id):
        raise ValueError("candidate package filename mismatch")
    directory = descriptor_path.parent
    package = directory / descriptor["package"]["filename"]
    sbom = directory / descriptor["sbom"]["filename"]
    for path, record in ((package, descriptor["package"]), (sbom, descriptor["sbom"])):
        if not path.is_file() or sha256_file(path) != record["sha256"] or path.stat().st_size != record["size"]:
            raise ValueError(f"candidate sidecar mismatch: {path.name}")
    verify_package(package, contract, matrix_id)
    attestations = descriptor.get("attestations", {})
    if require_attestations and set(attestations) != {"provenance", "sbom"}:
        raise ValueError("candidate lacks complete attestations")
    for record in attestations.values():
        path = directory / record["filename"]
        if not path.is_file() or sha256_file(path) != record["sha256"] or path.stat().st_size != record["size"]:
            raise ValueError(f"attestation bundle mismatch: {path.name}")
    return descriptor
