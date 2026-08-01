from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


def _first_line(command: list[str]) -> str:
    return subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ).stdout.splitlines()[0]


def linux_compilers(contract: dict[str, Any], matrix_id: str) -> tuple[str, str, str]:
    expected = contract["platforms"][matrix_id]["compiler"]["version"]
    cc = shutil.which("clang-17")
    cxx = shutil.which("clang++-17")
    if not cc or not cxx:
        raise ValueError("reviewed Clang 17 toolchain not found")
    version = _first_line([cxx, "--version"])
    if not re.search(rf"\b{re.escape(expected)}\b", version):
        raise ValueError(f"unexpected Clang version: {version}")
    return cc, cxx, version


def _verify_key(key: Path, expected_fingerprint: str) -> None:
    result = subprocess.run(
        ["gpg", "--show-keys", "--with-colons", str(key)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    fingerprints = {
        fields[9].replace(" ", "").upper()
        for line in result.stdout.splitlines()
        if (fields := line.split(":"))[0] == "fpr" and len(fields) > 9
    }
    if expected_fingerprint.replace(" ", "").upper() not in fingerprints:
        raise ValueError("LLVM repository signing-key fingerprint mismatch")


def _prepare_linux(contract: dict[str, Any], matrix_id: str) -> None:
    try:
        linux_compilers(contract, matrix_id)
        return
    except ValueError:
        pass
    platform = contract["platforms"][matrix_id]
    provision = platform["provisioning"]
    if os.name == "nt" or provision["provider"] != "apt.llvm.org":
        raise ValueError("Linux toolchain provisioning requested on an incompatible host")
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    if 'VERSION_ID="22.04"' not in os_release:
        raise ValueError("reviewed Clang provisioning requires Ubuntu 22.04")
    with tempfile.TemporaryDirectory() as temporary:
        key = Path(temporary) / "apt.llvm.org.asc"
        request = urllib.request.Request(
            provision["signing_key_url"], headers={"User-Agent": "godot-cpp-release-tooling/1"}
        )
        with urllib.request.urlopen(request, timeout=120) as response, key.open("wb") as stream:
            shutil.copyfileobj(response, stream)
        _verify_key(key, provision["signing_key_fingerprint"])
        subprocess.run(
            ["sudo", "install", "-m", "0644", str(key), provision["keyring_path"]], check=True
        )
    source = (
        f"deb [signed-by={provision['keyring_path']}] {provision['repository']} "
        f"{provision['suite']} main\n"
    )
    subprocess.run(
        ["sudo", "tee", provision["sources_path"]],
        input=source,
        text=True,
        stdout=subprocess.DEVNULL,
        check=True,
    )
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    subprocess.run(["sudo", "apt-get", "update"], env=environment, check=True)
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "--no-install-recommends", *provision["packages"]],
        env=environment,
        check=True,
    )
    package_version = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", "clang-17"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if not package_version.startswith(provision["package_version_prefix"]):
        raise ValueError(f"unexpected clang-17 package version: {package_version}")
    linux_compilers(contract, matrix_id)


def _vswhere() -> Path:
    candidates = [
        Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))
        / "Microsoft Visual Studio/Installer/vswhere.exe",
        Path("C:/Program Files/Microsoft Visual Studio/Installer/vswhere.exe"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which("vswhere")
    if found:
        return Path(found)
    raise ValueError("vswhere.exe not found")


def visual_studio_installation() -> Path:
    installation = subprocess.run(
        [
            str(_vswhere()),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    root = Path(installation)
    if not root.is_dir():
        raise ValueError("Visual Studio installation not found")
    return root


def windows_command_prefix(contract: dict[str, Any], matrix_id: str) -> str:
    platform = contract["platforms"][matrix_id]
    toolset = platform["provisioning"]["toolset_version"]
    vcvars = visual_studio_installation() / "VC/Auxiliary/Build/vcvarsall.bat"
    if not vcvars.is_file():
        raise ValueError("vcvarsall.bat not found")
    return (
        f'call "{vcvars}" amd64 {platform["sdk"]["windows"]} '
        f"-vcvars_ver={toolset}"
    )


def validate_windows_output(
    output: str, contract: dict[str, Any], matrix_id: str
) -> dict[str, str]:
    platform = contract["platforms"][matrix_id]
    compiler = platform["compiler"]
    provision = platform["provisioning"]
    if f"Version {compiler['version']}" not in output:
        raise ValueError("MSVC compiler version mismatch")
    vc_match = re.search(r"VCToolsVersion=([^\r\n]+)", output)
    sdk_match = re.search(r"WindowsSdkVersion=([^\r\n]+)", output)
    path_match = re.search(r"(?im)^CLPath=(.+cl\.exe)\s*$", output)
    if not vc_match or vc_match.group(1).strip() != provision["toolset_version"]:
        raise ValueError("MSVC Build Tools version mismatch")
    if not sdk_match or platform["sdk"]["windows"] not in sdk_match.group(1):
        raise ValueError("Windows SDK version mismatch")
    if not path_match or provision["toolset_version"] not in path_match.group(1):
        raise ValueError("cl.exe was not resolved from the reviewed MSVC toolset")
    return {
        "compiler": compiler["version"],
        "build_tools": vc_match.group(1).strip(),
        "platform_toolset": compiler["msbuild_platform_toolset"],
        "sdk": sdk_match.group(1).strip(),
        "compiler_path": path_match.group(1).strip(),
    }


def windows_probe(contract: dict[str, Any], matrix_id: str) -> dict[str, str]:
    command = (
        windows_command_prefix(contract, matrix_id)
        + " && echo VCToolsVersion=%VCToolsVersion%"
        + " && echo WindowsSdkVersion=%WindowsSdkVersion%"
        + " && for %I in (cl.exe) do @echo CLPath=%~$PATH:I"
        + " && (cl 2>&1 || ver >nul)"
    )
    result = subprocess.run(
        ["cmd.exe", "/d", "/s", "/c", command],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(result.stdout, end="")
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout)
    return validate_windows_output(result.stdout, contract, matrix_id)


def _windows_installer_arguments(setup: Path, installation: Path, config: Path) -> list[str]:
    return [
        str(setup),
        "modify",
        "--installPath",
        str(installation),
        "--config",
        str(config),
        "--quiet",
        "--norestart",
    ]


def _prepare_windows(root: Path, contract: dict[str, Any], matrix_id: str) -> None:
    if os.name != "nt":
        raise ValueError("Windows toolchain provisioning requested on a non-Windows host")
    platform = contract["platforms"][matrix_id]
    provision = platform["provisioning"]
    installation = visual_studio_installation()
    toolset = installation / "VC/Tools/MSVC" / provision["toolset_version"]
    if not toolset.is_dir():
        setup = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/setup.exe"
        config = root / provision["configuration_file"]
        if not setup.is_file() or not config.is_file():
            raise ValueError("reviewed Visual Studio installer inputs are missing")
        result = subprocess.run(_windows_installer_arguments(setup, installation, config))
        print(f"Visual Studio installer exit code: {result.returncode}")
        if result.returncode not in (0, 3010):
            raise subprocess.CalledProcessError(result.returncode, result.args)
    if not toolset.is_dir():
        raise ValueError(f"reviewed MSVC toolset was not installed: {toolset}")
    windows_probe(contract, matrix_id)


def prepare_toolchain(root: Path, contract: dict[str, Any], matrix_id: str) -> None:
    platform = contract["platforms"].get(matrix_id)
    if not platform:
        raise ValueError(f"unknown matrix id: {matrix_id}")
    if platform["os"] == "linux":
        _prepare_linux(contract, matrix_id)
    elif platform["os"] == "windows":
        _prepare_windows(root, contract, matrix_id)
    else:
        raise ValueError(f"unsupported toolchain platform: {platform['os']}")
