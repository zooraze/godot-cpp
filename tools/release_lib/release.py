from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from .canonical import sha256_file, write_json
from .sbom import release_spdx
from .verify import verify_candidate, verify_package


def _record(path: Path) -> dict[str, Any]:
    return {"filename": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}


def _find_descriptors(root: Path) -> list[Path]:
    return sorted(root.rglob("*.candidate.json"), key=lambda path: path.as_posix())


def prepare_release(candidates_root: Path, output_dir: Path, contract: dict[str, Any], tag: str, source_commit: str) -> Path:
    if tag != contract["release"]["proposed_tag"] or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag):
        raise ValueError("release tag does not match the reviewed contract")
    descriptors = _find_descriptors(candidates_root)
    if not descriptors:
        raise ValueError("no candidate descriptors found")
    candidates = [verify_candidate(path, contract, require_attestations=True) for path in descriptors]
    by_matrix = {candidate["matrix_id"]: (candidate, path) for candidate, path in zip(candidates, descriptors)}
    if set(by_matrix) != set(contract["expected_matrix"]) or len(by_matrix) != len(candidates):
        raise ValueError("candidate matrix is incomplete or duplicated")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    packages = []
    copied_assets: list[Path] = []
    for matrix_id in contract["expected_matrix"]:
        candidate, descriptor_path = by_matrix[matrix_id]
        source_dir = descriptor_path.parent
        records = [candidate["package"], candidate["sbom"], *candidate["attestations"].values()]
        for record in records:
            source = source_dir / record["filename"]
            target = output_dir / source.name
            if target.exists():
                raise ValueError(f"duplicate release asset: {target.name}")
            shutil.copy2(source, target)
            copied_assets.append(target)
        packages.append({
            "matrix_id": matrix_id,
            "package_id": candidate["package_id"],
            **candidate["package"],
            "sbom": candidate["sbom"]["filename"],
            "provenance_attestation": candidate["attestations"]["provenance"]["filename"],
            "sbom_attestation": candidate["attestations"]["sbom"]["filename"],
        })

    release_sbom = output_dir / "release.spdx.json"
    write_json(release_sbom, release_spdx(tag, [output_dir / item["filename"] for item in packages]))
    copied_assets.append(release_sbom)
    assets = [_record(path) for path in sorted(copied_assets, key=lambda item: item.name)]
    manifest = {
        "schema_version": 1,
        "tag": tag,
        "source_commit": source_commit,
        "expected_matrix": contract["expected_matrix"],
        "packages": packages,
        "assets": assets,
    }
    manifest_path = output_dir / "release-manifest.json"
    write_json(manifest_path, manifest)
    checksum_targets = sorted([*copied_assets, manifest_path], key=lambda item: item.name)
    checksums = "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_targets)
    (output_dir / "SHA256SUMS").write_text(checksums, encoding="utf-8", newline="\n")
    verify_release_dir(output_dir, contract, require_all_assets=True)
    return manifest_path


def _parse_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            raise ValueError("invalid SHA256SUMS")
        digest, name = match.groups()
        if name in entries:
            raise ValueError("invalid SHA256SUMS")
        entries[name] = digest
    return entries


def verify_revocations(manifest: dict[str, Any], path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "revocations"} or document["schema_version"] != 1:
        raise ValueError("invalid revocation index")
    revoked: set[str] = set()
    for record in document["revocations"]:
        required = {"sha256", "reason", "effective_date"}
        if not isinstance(record, dict) or not required <= set(record) or set(record) - (required | {"replacement_sha256"}):
            raise ValueError("invalid revocation record")
        digest = record["sha256"]
        replacement = record.get("replacement_sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or digest in revoked:
            raise ValueError("invalid revocation digest")
        if replacement is not None and not re.fullmatch(r"[0-9a-f]{64}", replacement):
            raise ValueError("invalid replacement digest")
        if not isinstance(record["reason"], str) or not record["reason"].strip():
            raise ValueError("invalid revocation reason")
        if not isinstance(record["effective_date"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", record["effective_date"]):
            raise ValueError("invalid revocation date")
        revoked.add(digest)
    for package in manifest["packages"]:
        if package["sha256"] in revoked:
            raise ValueError(f"revoked package: {package['filename']}")


def verify_release_dir(root: Path, contract: dict[str, Any], require_all_assets: bool) -> dict[str, Any]:
    manifest = json.loads((root / "release-manifest.json").read_text(encoding="utf-8"))
    required = {"schema_version", "tag", "source_commit", "expected_matrix", "packages", "assets"}
    if set(manifest) != required or manifest["schema_version"] != 1:
        raise ValueError("release manifest does not conform to schema v1")
    if manifest["tag"] != contract["release"]["proposed_tag"]:
        raise ValueError("release tag contract mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]):
        raise ValueError("invalid release source commit")
    if manifest["expected_matrix"] != contract["expected_matrix"]:
        raise ValueError("release matrix contract mismatch")
    matrix = [item["matrix_id"] for item in manifest["packages"]]
    if matrix != contract["expected_matrix"] or len(matrix) != len(set(matrix)):
        raise ValueError("release package matrix is incomplete or unordered")
    assets = {item["filename"]: item for item in manifest["assets"]}
    for record in manifest["assets"]:
        path = root / record["filename"]
        if require_all_assets and not path.is_file():
            raise ValueError(f"missing release asset: {path.name}")
        if path.is_file() and (sha256_file(path) != record["sha256"] or path.stat().st_size != record["size"]):
            raise ValueError(f"release asset mismatch: {path.name}")
    for package in manifest["packages"]:
        if package["filename"] not in assets:
            raise ValueError("package missing from asset inventory")
        path = root / package["filename"]
        if path.is_file():
            if sha256_file(path) != package["sha256"] or path.stat().st_size != package["size"]:
                raise ValueError("release package checksum mismatch")
            verify_package(path, contract, package["matrix_id"], manifest["source_commit"])
        for key in ("sbom", "provenance_attestation", "sbom_attestation"):
            if package[key] not in assets:
                raise ValueError(f"package sidecar missing from assets: {package[key]}")
    release_sbom = json.loads((root / "release.spdx.json").read_text(encoding="utf-8"))
    if release_sbom.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("invalid release SPDX document")
    sbom_files = {entry["fileName"][2:]: entry["checksums"][0]["checksumValue"] for entry in release_sbom.get("files", [])}
    expected_sbom = {item["filename"]: item["sha256"] for item in manifest["packages"]}
    if sbom_files != expected_sbom:
        raise ValueError("release SPDX inventory mismatch")
    checksums = _parse_checksums(root / "SHA256SUMS")
    expected_checksum_names = set(assets) | {"release-manifest.json"}
    if set(checksums) != expected_checksum_names:
        raise ValueError("release checksum inventory mismatch")
    if require_all_assets:
        expected_files = expected_checksum_names | {"SHA256SUMS"}
        actual_files = {path.name for path in root.iterdir() if path.is_file()}
        if actual_files != expected_files:
            raise ValueError("release directory contains missing or extra assets")
    for name, digest in checksums.items():
        path = root / name
        if require_all_assets and not path.is_file():
            raise ValueError(f"missing checksummed file: {name}")
        if path.is_file() and sha256_file(path) != digest:
            raise ValueError(f"release checksum mismatch: {name}")
    return manifest
