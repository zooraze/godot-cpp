from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .archive import extract_archive
from .canonical import sha256_file
from .release import verify_release_dir, verify_revocations
from .toolchains import _run_windows_command, linux_compilers, validate_windows_output, windows_command_prefix


def consumer_runtime_flags(platform: dict[str, Any]) -> list[str]:
    if platform["os"] == "windows":
        return [platform["standard_library"]["crt_linkage"]]
    linkage = platform["standard_library"]["consumer_runtime_linkage"]
    if linkage != "static-libstdc++-and-libgcc":
        raise ValueError(f"unsupported consumer runtime linkage: {linkage}")
    return ["-static-libstdc++", "-static-libgcc"]


def _anonymous_download(url: str, output: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "godot-cpp-release-verifier/1"})
    with urllib.request.urlopen(request, timeout=120) as response, output.open("wb") as stream:
        shutil.copyfileobj(response, stream)


def download_release(repository: str, tag: str, output_dir: Path, contract: dict[str, Any], revocations: Path) -> dict[str, Any]:
    if repository.lower() != contract["repository"]["full_name"].lower():
        raise ValueError(f"unexpected release repository: {repository}")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    base = f"https://github.com/{repository}/releases/download/{urllib.parse.quote(tag, safe='')}/"
    for name in ("release-manifest.json", "SHA256SUMS"):
        _anonymous_download(base + name, output_dir / name)
    manifest = json.loads((output_dir / "release-manifest.json").read_text(encoding="utf-8"))
    for record in manifest.get("assets", []):
        name = record["filename"]
        _anonymous_download(base + urllib.parse.quote(name, safe=""), output_dir / name)
    verify_release_dir(output_dir, contract, require_all_assets=True)
    verify_revocations(manifest, revocations)
    return manifest


def _package_for_matrix(manifest: dict[str, Any], matrix_id: str) -> dict[str, Any]:
    matches = [item for item in manifest["packages"] if item["matrix_id"] == matrix_id]
    if len(matches) != 1:
        raise ValueError(f"release lacks one package for {matrix_id}")
    return matches[0]


def smoke_test(package: Path, matrix_id: str, smoke_source: Path, contract: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "package"
        extract_archive(package, root)
        libraries = list((root / "lib").iterdir())
        if len(libraries) != 1:
            raise ValueError("package must contain exactly one library")
        output = Path(temporary) / ("smoke.dll" if os.name == "nt" else "smoke.so")
        platform = contract["platforms"][matrix_id]
        if os.name == "nt":
            command = [
                "cl", "/nologo", "/std:c++17", *consumer_runtime_flags(platform), "/LD", str(smoke_source),
                f"/I{root / 'include'}", str(libraries[0]), "/link", f"/OUT:{output}",
            ]
            body = subprocess.list2cmdline(command)
            sdk = platform["sdk"]["windows"]
            shell = (
                windows_command_prefix(contract, matrix_id)
                + " && echo VCToolsVersion=%VCToolsVersion%"
                + " && echo WindowsSdkVersion=%WindowsSdkVersion%"
                + " && for %I in (cl.exe) do @echo CLPath=%~$PATH:I"
                + " && (cl 2>&1 || ver >nul) && "
                + body
            )
            result = _run_windows_command(shell)
            if result.returncode:
                raise subprocess.CalledProcessError(result.returncode, shell, output=result.stdout)
            validate_windows_output(result.stdout, contract, matrix_id)
        else:
            _, compiler, _ = linux_compilers(contract, matrix_id)
            command = [
                compiler, "-std=c++17", "-shared", "-fPIC", str(smoke_source),
                f"-I{root / 'include'}", str(libraries[0]), "-pthread", "-ldl",
                *consumer_runtime_flags(platform), "-Wl,--no-undefined", "-o", str(output),
            ]
            subprocess.run(command, check=True)
        if not output.is_file() or output.stat().st_size == 0:
            raise ValueError("consumer compile/link output missing")
