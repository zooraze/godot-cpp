from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, load_json, sha256_bytes

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")


def load_contract(path: Path) -> dict[str, Any]:
    contract = load_json(path)
    validate_contract(contract)
    return contract


def validate_contract(contract: dict[str, Any]) -> None:
    required = {"schema_version", "repository", "release", "source", "godot", "profile", "build", "platforms", "expected_matrix", "attestation"}
    missing = required - set(contract)
    if missing:
        raise ValueError(f"contract missing fields: {sorted(missing)}")
    if contract["schema_version"] != 1:
        raise ValueError("unsupported contract schema")
    if contract["repository"]["full_name"] != "zooraze/godot-cpp":
        raise ValueError("unexpected repository identity")
    if contract["repository"]["default_branch"] != "master":
        raise ValueError("default branch must remain master")
    if not _SHA40.fullmatch(contract["source"]["upstream_commit"]):
        raise ValueError("invalid upstream commit")
    if not _SHA64.fullmatch(contract["godot"]["extension_api_sha256"]):
        raise ValueError("invalid extension API digest")
    if not _SHA64.fullmatch(contract["profile"]["sha256"]):
        raise ValueError("invalid profile digest")
    if contract["build"].get("python", {}).get("version") != "3.12.10":
        raise ValueError("unexpected Python toolchain version")
    matrix = contract["expected_matrix"]
    if sorted(matrix) != sorted(contract["platforms"]):
        raise ValueError("expected matrix must exactly match platform definitions")
    if contract["attestation"].get("create_storage_record") is not False:
        raise ValueError("personal-account releases must disable storage records")
    if "artifact-metadata:write" not in contract["attestation"].get("forbidden_permissions", []):
        raise ValueError("artifact-metadata:write must be forbidden")
    windows = contract["platforms"]["windows-x86_64"]
    compiler = windows["compiler"]
    expected = ("windows-2025-vs2026", "19.50.35737", "14.50", "v145", "10.0.26100.0", "/MT")
    actual = (
        windows["runner_label"], compiler["version"], compiler["build_tools"],
        compiler["msbuild_platform_toolset"], windows["sdk"]["windows"],
        windows["standard_library"]["crt_linkage"],
    )
    if actual != expected:
        raise ValueError(f"unexpected Windows contract: {actual}")
    linux_provisioning = contract["platforms"]["linux-x86_64"].get("provisioning")
    expected_linux_provisioning = {
        "provider": "apt.llvm.org",
        "repository": "https://apt.llvm.org/jammy/",
        "suite": "llvm-toolchain-jammy-17",
        "signing_key_url": "https://apt.llvm.org/llvm-snapshot.gpg.key",
        "signing_key_fingerprint": "6084F3CF814B57C1CF12EFD515CF4D18AF4F7421",
        "keyring_path": "/usr/share/keyrings/apt.llvm.org.asc",
        "sources_path": "/etc/apt/sources.list.d/apt.llvm.org.list",
        "packages": ["clang-17"],
        "package_version_prefix": "1:17.0.6",
    }
    if linux_provisioning != expected_linux_provisioning:
        raise ValueError("unexpected Linux toolchain provisioning contract")
    windows_provisioning = windows.get("provisioning")
    expected_windows_provisioning = {
        "provider": "visual-studio-installer",
        "component_id": "Microsoft.VisualStudio.Component.VC.14.50.18.0.x86.x64",
        "toolset_version": "14.50.35717",
        "configuration_file": "release/toolchains/windows-msvc-14.50.vsconfig",
    }
    if windows_provisioning != expected_windows_provisioning:
        raise ValueError("unexpected Windows toolchain provisioning contract")


def compatibility(contract: dict[str, Any], matrix_id: str) -> dict[str, Any]:
    platform = copy.deepcopy(contract["platforms"][matrix_id])
    return {
        "schema_version": contract["schema_version"],
        "dependency": "godot-cpp",
        "package_revision": contract["release"]["package_revision"],
        "source": {
            "upstream_repository": contract["source"]["upstream_repository"],
            "upstream_commit": contract["source"]["upstream_commit"],
            "public_patches": contract["source"]["public_patches"],
        },
        "godot": {
            "version": contract["godot"]["version"],
            "build_identity": contract["godot"]["build_identity"],
            "extension_api_sha256": contract["godot"]["extension_api_sha256"],
        },
        "profile_sha256": contract["profile"]["sha256"],
        "build": copy.deepcopy(contract["build"]),
        "matrix_id": matrix_id,
        "platform": platform,
    }


def contract_digest(contract: dict[str, Any], matrix_id: str) -> str:
    return sha256_bytes(canonical_bytes(compatibility(contract, matrix_id)))


def toolchain_slug(contract: dict[str, Any], matrix_id: str) -> str:
    compiler = contract["platforms"][matrix_id]["compiler"]
    if compiler["family"] == "msvc":
        return compiler["msbuild_platform_toolset"].replace("v", "msvc")
    return f"clang{compiler['version'].split('.')[0]}"


def package_id(contract: dict[str, Any], matrix_id: str) -> str:
    platform = contract["platforms"][matrix_id]
    build = contract["build"]
    abi12 = contract_digest(contract, matrix_id)[:12]
    return (
        f"godot-cpp-{contract['godot']['version']}-b{contract['release']['package_revision']}-"
        f"{platform['os']}-{platform['architecture']}-{toolchain_slug(contract, matrix_id)}-"
        f"{build['target']}-{build['configuration']}-{abi12}"
    )


def package_filename(contract: dict[str, Any], matrix_id: str) -> str:
    suffix = ".zip" if contract["platforms"][matrix_id]["archive_format"] == "zip" else ".tar.zst"
    return package_id(contract, matrix_id) + suffix
