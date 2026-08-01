from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from .archive import create_archive
from .canonical import file_hashes, hash_listing, sha256_file, write_json
from .contracts import compatibility, contract_digest, package_filename, package_id
from .sbom import package_spdx


def _copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ValueError(f"missing directory: {source}")
    shutil.copytree(source, destination, dirs_exist_ok=True)


def _write_manifest(root: Path) -> str:
    entries = file_hashes(root, {"MANIFEST.sha256", "METADATA.json"})
    lines = "".join(f"{digest}  {name}\n" for name, digest in sorted(entries.items()))
    manifest = root / "MANIFEST.sha256"
    manifest.write_text(lines, encoding="utf-8", newline="\n")
    return sha256_file(manifest)


def _find_library(source_root: Path, contract: dict[str, Any], matrix_id: str) -> Path:
    platform = contract["platforms"][matrix_id]
    suffix = ".lib" if platform["os"] == "windows" else ".a"
    expected = f"libgodot-cpp.{platform['os']}.{contract['build']['target']}.{platform['architecture']}{suffix}"
    library = source_root / "bin" / expected
    if not library.is_file():
        raise ValueError(f"missing expected library: {library}")
    return library


def build_package(
    source_root: Path,
    contract: dict[str, Any],
    matrix_id: str,
    extension_api: Path,
    output_dir: Path,
    source_commit: str,
    provenance: dict[str, Any],
    licenses_dir: Path,
) -> dict[str, Any]:
    package_name = package_filename(contract, matrix_id)
    identifier = package_id(contract, matrix_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / package_name

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / identifier
        root.mkdir()
        _copy_tree(source_root / "include", root / "include")
        _copy_tree(source_root / "gen" / "include", root / "include")

        library = _find_library(source_root, contract, matrix_id)
        library_target = root / "lib" / library.name
        library_target.parent.mkdir(parents=True)
        shutil.copy2(library, library_target)

        api_target = root / "api" / "extension_api.json"
        api_target.parent.mkdir(parents=True)
        shutil.copy2(extension_api, api_target)

        profile_target = root / "profile" / "build_profile.json"
        profile_target.parent.mkdir(parents=True)
        shutil.copy2(source_root / contract["profile"]["path"], profile_target)

        license_target = root / "licenses"
        license_target.mkdir()
        shutil.copy2(licenses_dir / "GODOT-CPP-LICENSE.md", license_target / "GODOT-CPP-LICENSE.md")
        shutil.copy2(licenses_dir / "GODOT-LICENSE.txt", license_target / "GODOT-LICENSE.txt")

        write_json(root / "provenance" / "build-provenance.json", provenance)
        digest = contract_digest(contract, matrix_id)
        sbom = package_spdx(identifier, digest, root)
        sbom_path = root / "sbom" / "package.spdx.json"
        write_json(sbom_path, sbom)
        manifest_digest = _write_manifest(root)

        metadata = {
            "schema_version": 1,
            "package_id": identifier,
            "contract_sha256": digest,
            "compatibility": compatibility(contract, matrix_id),
            "source": {
                "upstream_repository": contract["source"]["upstream_repository"],
                "upstream_commit": contract["source"]["upstream_commit"],
                "fork_repository": contract["repository"]["full_name"],
                "fork_commit": source_commit,
                "public_patches": contract["source"]["public_patches"],
            },
            "build_provenance": provenance,
            "payload_manifest_sha256": manifest_digest,
            "payload": {
                "extension_api_sha256": sha256_file(api_target),
                "profile_sha256": sha256_file(profile_target),
                "sbom_sha256": sha256_file(sbom_path),
                "licenses": {
                    "godot_cpp_sha256": sha256_file(license_target / "GODOT-CPP-LICENSE.md"),
                    "godot_sha256": sha256_file(license_target / "GODOT-LICENSE.txt"),
                },
                "library": {"path": f"lib/{library.name}", "sha256": sha256_file(library_target)},
            },
            "reproducibility": "structurally-reproducible",
        }
        write_json(root / "METADATA.json", metadata)
        create_archive(root, archive_path, contract["platforms"][matrix_id]["archive_format"])

        sidecar_sbom = output_dir / f"{identifier}.spdx.json"
        shutil.copy2(sbom_path, sidecar_sbom)

    descriptor = {
        "schema_version": 1,
        "matrix_id": matrix_id,
        "package_id": identifier,
        "contract_sha256": contract_digest(contract, matrix_id),
        "package": {"filename": archive_path.name, "sha256": sha256_file(archive_path), "size": archive_path.stat().st_size},
        "sbom": {"filename": sidecar_sbom.name, "sha256": sha256_file(sidecar_sbom), "size": sidecar_sbom.stat().st_size},
        "attestations": {},
    }
    descriptor_path = output_dir / f"{identifier}.candidate.json"
    write_json(descriptor_path, descriptor)
    return {"archive": archive_path, "sbom": sidecar_sbom, "descriptor": descriptor_path, "metadata": metadata}


def attach_attestations(descriptor_path: Path, provenance_bundle: Path, sbom_bundle: Path) -> None:
    from .canonical import load_json

    descriptor = load_json(descriptor_path)
    destination = descriptor_path.parent
    records = {}
    for name, source in (("provenance", provenance_bundle), ("sbom", sbom_bundle)):
        target = destination / f"{descriptor['package_id']}.{name}.attestation.json"
        if source.resolve() != target.resolve():
            shutil.copy2(source, target)
        records[name] = {"filename": target.name, "sha256": sha256_file(target), "size": target.stat().st_size}
    descriptor["attestations"] = records
    write_json(descriptor_path, descriptor)
