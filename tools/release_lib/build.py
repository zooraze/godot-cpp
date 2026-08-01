from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from .archive import extract_archive
from .canonical import sha256_file
from .package import build_package
from .toolchains import linux_compilers, validate_windows_output, windows_command_prefix


def _download(url: str, output: Path, expected_sha256: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.exists() or sha256_file(output) != expected_sha256:
        request = urllib.request.Request(url, headers={"User-Agent": "godot-cpp-release-tooling/1"})
        with urllib.request.urlopen(request, timeout=120) as response, output.open("wb") as stream:
            shutil.copyfileobj(response, stream)
    if sha256_file(output) != expected_sha256:
        raise ValueError(f"download checksum mismatch: {output.name}")


def _extract_zip(path: Path, destination: Path) -> None:
    extract_archive(path, destination)


def _godot_api(source_root: Path, contract: dict[str, Any], matrix_id: str, work: Path) -> tuple[Path, str]:
    archive_spec = contract["godot"]["archives"][matrix_id]
    archive = work / Path(archive_spec["url"]).name
    _download(archive_spec["url"], archive, archive_spec["sha256"])
    extracted = work / "godot"
    _extract_zip(archive, extracted)
    binary = extracted / archive_spec["binary"]
    if not binary.is_file():
        matches = list(extracted.rglob(archive_spec["binary"]))
        if len(matches) != 1:
            raise ValueError("Godot binary not found in verified archive")
        binary = matches[0]
    if os.name != "nt":
        binary.chmod(0o755)
    version = subprocess.run([str(binary), "--version"], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    if version != contract["godot"]["build_identity"]:
        raise ValueError(f"unexpected Godot build identity: {version}")
    api_dir = work / "api"
    api_dir.mkdir()
    subprocess.run([str(binary), "--headless", "--dump-extension-api"], cwd=api_dir, check=True)
    api = api_dir / "extension_api.json"
    if sha256_file(api) != contract["godot"]["extension_api_sha256"]:
        raise ValueError("Godot extension API digest mismatch")
    return api, version


def _scons_arguments(contract: dict[str, Any], matrix_id: str, api: Path) -> list[str]:
    build = contract["build"]
    platform = contract["platforms"][matrix_id]
    arguments = [
        f"platform={platform['os']}",
        f"target={build['target']}",
        f"arch={platform['architecture']}",
        f"custom_api_file={api}",
        f"build_profile={contract['profile']['path']}",
        f"optimize={build['optimization']}",
        f"precision={build['precision']}",
        f"threads={'yes' if build['threads'] else 'no'}",
        f"disable_exceptions={'no' if build['exceptions'] else 'yes'}",
        f"symbols_visibility={build['symbols_visibility_option']}",
        f"lto={build['lto']}",
        f"debug_symbols={'yes' if build['debug_symbols'] else 'no'}",
        f"use_hot_reload={'yes' if build['use_hot_reload'] else 'no'}",
        f"generate_bindings={'yes' if build['generate_bindings'] else 'no'}",
        f"build_library={'yes' if build['build_library'] else 'no'}",
    ]
    if platform["os"] == "linux":
        arguments.extend(["use_llvm=yes", "use_static_cpp=yes"])
    else:
        arguments.extend(["use_mingw=no", "use_llvm=no", "use_static_cpp=yes"])
    return arguments


def _linux_build(source_root: Path, contract: dict[str, Any], matrix_id: str, api: Path) -> tuple[list[str], dict[str, Any]]:
    cc, cxx, version_text = linux_compilers(contract, matrix_id)
    args = [sys.executable, "-m", "SCons", *_scons_arguments(contract, matrix_id, api)]
    environment = dict(os.environ, CC=cc, CXX=cxx, SOURCE_DATE_EPOCH=str(contract["build"]["source_date_epoch"]))
    subprocess.run(args, cwd=source_root, env=environment, check=True)
    glibc = subprocess.run(["ldd", "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True).stdout.splitlines()[0]
    if contract["platforms"][matrix_id]["minimum_runtime"]["glibc"] not in glibc:
        raise ValueError(f"unexpected glibc baseline: {glibc}")
    package_version = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", "clang-17"],
        check=True, text=True, stdout=subprocess.PIPE,
    ).stdout.strip()
    return args, {"compiler": version_text, "package": "clang-17", "package_version": package_version, "cc": cc, "cxx": cxx, "glibc": glibc}


def _windows_build(source_root: Path, contract: dict[str, Any], matrix_id: str, api: Path) -> tuple[list[str], dict[str, Any]]:
    scons = [sys.executable, "-m", "SCons", *_scons_arguments(contract, matrix_id, api)]
    quoted = subprocess.list2cmdline(scons)
    command = (
        windows_command_prefix(contract, matrix_id)
        + " && echo VCToolsVersion=%VCToolsVersion%"
        + " && echo WindowsSdkVersion=%WindowsSdkVersion%"
        + " && for %I in (cl.exe) do @echo CLPath=%~$PATH:I"
        + " && (cl 2>&1 || ver >nul) && "
        + quoted
    )
    result = subprocess.run(
        ["cmd.exe", "/d", "/s", "/c", command],
        cwd=source_root,
        env=dict(os.environ, SOURCE_DATE_EPOCH=str(contract["build"]["source_date_epoch"])),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout)
    return scons, validate_windows_output(result.stdout, contract, matrix_id)


def run_build(source_root: Path, contract: dict[str, Any], matrix_id: str, output_dir: Path, source_commit: str) -> dict[str, Any]:
    expected_python = contract["build"]["python"]["version"]
    if sys.version.split()[0] != expected_python:
        raise ValueError(f"unexpected Python version: {sys.version.split()[0]} (expected {expected_python})")
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        api, godot_version = _godot_api(source_root, contract, matrix_id, work)
        if os.name == "nt":
            command, toolchain = _windows_build(source_root, contract, matrix_id, api)
        else:
            command, toolchain = _linux_build(source_root, contract, matrix_id, api)
        provenance = {
            "schema_version": 1,
            "workflow": os.environ.get("GITHUB_WORKFLOW", "local"),
            "workflow_commit": source_commit,
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "runner": {"name": os.environ.get("RUNNER_NAME", "local"), "os": os.environ.get("RUNNER_OS", os.name), "label": contract["platforms"][matrix_id]["runner_label"]},
            "toolchain": toolchain,
            "godot_build_identity": godot_version,
            "command": command,
            "environment": {"source_date_epoch": str(contract["build"]["source_date_epoch"]), "python": sys.version.split()[0]},
        }
        return build_package(source_root, contract, matrix_id, api, output_dir, source_commit, provenance, source_root / "release/licenses")
