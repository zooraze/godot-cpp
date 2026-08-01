from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "tools"))

from release_lib.archive import create_archive, extract_archive
from release_lib.build import _windows_build
from release_lib.consumer import consumer_runtime_flags, download_release
from release_lib.canonical import sha256_file
from release_lib.contracts import load_contract
from release_lib.package import attach_attestations, build_package
from release_lib.release import _parse_checksums, prepare_release, verify_release_dir, verify_revocations
from release_lib.verify import verify_package
from release_lib.toolchains import (
    _run_windows_command, _windows_installer_arguments, validate_windows_output, windows_environment_prefix,
)
from release_lib.workflow_policy import check_workflows

SOURCE_COMMIT = "1" * 40


class ReleaseToolingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / "include/godot_cpp").mkdir(parents=True)
        (self.source / "include/godot_cpp/godot.hpp").write_text("#pragma once\n", encoding="utf-8")
        (self.source / "gen/include/godot_cpp").mkdir(parents=True)
        (self.source / "gen/include/godot_cpp/generated.hpp").write_text("#pragma once\n", encoding="utf-8")
        (self.source / "gen/include/gdextension_interface.h").write_text("#pragma once\n", encoding="utf-8")
        (self.source / "bin").mkdir()
        (self.source / "release/profiles").mkdir(parents=True)
        self.profile = self.source / "release/profiles/test.json"
        self.profile.write_text('{"enabled_classes":["Node"]}\n', encoding="utf-8")
        self.api = self.root / "extension_api.json"
        self.api.write_text('{"header":{"version_major":4}}\n', encoding="utf-8")
        self.contract = copy.deepcopy(load_contract(ROOT / "release/contracts/godot-4.7.1-build.1.json"))
        self.contract["profile"]["path"] = "release/profiles/test.json"
        self.contract["profile"]["sha256"] = sha256_file(self.profile)
        self.contract["godot"]["extension_api_sha256"] = sha256_file(self.api)
        self.provenance = {
            "schema_version": 1, "workflow": "test", "workflow_commit": SOURCE_COMMIT, "run_id": "1",
            "runner": {"name": "test", "os": "test", "label": "test"}, "toolchain": {"compiler": "test"},
            "godot_build_identity": self.contract["godot"]["build_identity"], "command": ["test"],
            "environment": {"source_date_epoch": "0", "python": "test"},
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _candidate(self, matrix_id: str, destination: Path) -> Path:
        platform = self.contract["platforms"][matrix_id]
        suffix = ".lib" if platform["os"] == "windows" else ".a"
        library = self.source / "bin" / f"libgodot-cpp.{platform['os']}.editor.x86_64{suffix}"
        library.write_bytes((matrix_id + "-library").encode())
        result = build_package(
            self.source, self.contract, matrix_id, self.api, destination, SOURCE_COMMIT,
            self.provenance, ROOT / "release/licenses",
        )
        provenance = self.root / f"{matrix_id}-provenance.json"
        sbom = self.root / f"{matrix_id}-sbom.json"
        provenance.write_text('{"bundle":"provenance"}\n', encoding="utf-8")
        sbom.write_text('{"bundle":"sbom"}\n', encoding="utf-8")
        attach_attestations(result["descriptor"], provenance, sbom)
        return result["descriptor"]

    def test_contract_contains_approved_windows_identity(self) -> None:
        windows = self.contract["platforms"]["windows-x86_64"]
        self.assertEqual(windows["runner_label"], "windows-2025-vs2026")
        self.assertEqual(windows["compiler"], {"family": "msvc", "version": "19.50.35737", "build_tools": "14.50", "msbuild_platform_toolset": "v145"})
        self.assertEqual(windows["sdk"]["windows"], "10.0.26100.0")
        self.assertEqual(windows["standard_library"]["crt_linkage"], "/MT")
        self.assertEqual(windows["provisioning"]["toolset_version"], "14.50.35717")
        self.assertEqual(
            windows["provisioning"]["component_id"],
            "Microsoft.VisualStudio.Component.VC.14.50.18.0.x86.x64",
        )
        linux = self.contract["platforms"]["linux-x86_64"]
        self.assertEqual(linux["provisioning"]["suite"], "llvm-toolchain-jammy-17")
        self.assertEqual(linux["provisioning"]["package_version_prefix"], "1:17.0.6")
        self.assertFalse(self.contract["attestation"]["create_storage_record"])

    def test_windows_probe_is_fail_closed(self) -> None:
        output = (
            "VCToolsVersion=14.50.35717\n"
            "WindowsSdkVersion=10.0.26100.0\\\n"
            "CLPath=C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Tools\\MSVC\\14.50.35717\\bin\\Hostx64\\x64\\cl.exe\n"
            "Microsoft (R) C/C++ Optimizing Compiler Version 19.50.35737 for x64\n"
        )
        metadata = validate_windows_output(output, self.contract, "windows-x86_64")
        self.assertEqual(metadata["build_tools"], "14.50.35717")
        with self.assertRaisesRegex(ValueError, "compiler version mismatch"):
            validate_windows_output(output.replace("19.50.35737", "19.51.36231"), self.contract, "windows-x86_64")

    def test_consumer_runtime_linkage_comes_from_contract(self) -> None:
        windows = self.contract["platforms"]["windows-x86_64"]
        linux = self.contract["platforms"]["linux-x86_64"]
        self.assertEqual(consumer_runtime_flags(windows), ["/MT"])
        self.assertEqual(consumer_runtime_flags(linux), ["-static-libstdc++", "-static-libgcc"])

    def test_release_download_rejects_wrong_repository(self) -> None:
        with self.assertRaisesRegex(ValueError, "unexpected release repository"):
            download_release("example/wrong", "tag", self.root / "download", self.contract, self.root / "revocations.json")

    def test_windows_build_propagates_source_date_epoch(self) -> None:
        output = (
            "VCToolsVersion=14.50.35717\n"
            "WindowsSdkVersion=10.0.26100.0\\\n"
            "CLPath=C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise\\VC\\Tools\\MSVC\\14.50.35717\\bin\\Hostx64\\x64\\cl.exe\n"
            "Microsoft (R) C/C++ Optimizing Compiler Version 19.50.35737 for x64\n"
        )
        completed = mock.Mock(returncode=0, stdout=output)
        with mock.patch("release_lib.build.windows_environment_prefix", return_value="call vcvars"), mock.patch(
            "release_lib.build.subprocess.run", return_value=completed
        ) as run:
            _windows_build(self.source, self.contract, "windows-x86_64", self.api)
        self.assertEqual(run.call_args.kwargs["env"]["SOURCE_DATE_EPOCH"], "0")

    def test_windows_installer_uses_supported_arguments(self) -> None:
        command = _windows_installer_arguments(
            Path("setup.exe"), Path("Visual Studio/18/Enterprise"), Path("toolchain.vsconfig")
        )
        self.assertEqual(command[1], "modify")
        self.assertIn("--config", command)
        self.assertNotIn("--wait", command)

    def test_windows_batch_command_uses_shell_string(self) -> None:
        completed = mock.Mock(returncode=0, stdout="")
        with mock.patch("release_lib.toolchains.subprocess.run", return_value=completed) as run:
            _run_windows_command('call "C:\\Program Files\\probe.bat"')
        self.assertEqual(run.call_args.args[0], 'call "C:\\Program Files\\probe.bat"')
        self.assertTrue(run.call_args.kwargs["shell"])

    def test_windows_environment_is_read_after_vcvars(self) -> None:
        with mock.patch("release_lib.toolchains.windows_command_prefix", return_value="call vcvars"):
            command = windows_environment_prefix(self.contract, "windows-x86_64")
        self.assertIn("&& set VCToolsVersion", command)
        self.assertIn("&& set WindowsSdkVersion", command)
        self.assertNotIn("%VCToolsVersion%", command)

    def test_workflow_policy(self) -> None:
        check_workflows(ROOT)

    def test_linux_package_is_byte_reproducible_and_valid(self) -> None:
        first = self._candidate("linux-x86_64", self.root / "first")
        second = self._candidate("linux-x86_64", self.root / "second")
        first_package = first.parent / json.loads(first.read_text())["package"]["filename"]
        second_package = second.parent / json.loads(second.read_text())["package"]["filename"]
        self.assertEqual(sha256_file(first_package), sha256_file(second_package))
        metadata = verify_package(first_package, self.contract, "linux-x86_64", SOURCE_COMMIT)
        self.assertEqual(metadata["source"]["fork_commit"], SOURCE_COMMIT)

    def test_windows_package_is_byte_reproducible_and_valid(self) -> None:
        first = self._candidate("windows-x86_64", self.root / "first")
        second = self._candidate("windows-x86_64", self.root / "second")
        first_package = first.parent / json.loads(first.read_text())["package"]["filename"]
        second_package = second.parent / json.loads(second.read_text())["package"]["filename"]
        self.assertEqual(sha256_file(first_package), sha256_file(second_package))
        verify_package(first_package, self.contract, "windows-x86_64", SOURCE_COMMIT)

    def test_tampered_package_is_rejected(self) -> None:
        descriptor = self._candidate("windows-x86_64", self.root / "candidate")
        package = descriptor.parent / json.loads(descriptor.read_text())["package"]["filename"]
        extracted = self.root / "tampered"
        extract_archive(package, extracted)
        library = next((extracted / "lib").iterdir())
        library.write_bytes(b"tampered")
        replacement = self.root / "tampered.zip"
        create_archive(extracted, replacement, "zip")
        with self.assertRaisesRegex(ValueError, "manifest checksum mismatch"):
            verify_package(replacement, self.contract, "windows-x86_64", SOURCE_COMMIT)

    def test_incomplete_release_matrix_is_rejected(self) -> None:
        self._candidate("linux-x86_64", self.root / "candidates/linux")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            prepare_release(self.root / "candidates", self.root / "release", self.contract, self.contract["release"]["proposed_tag"], SOURCE_COMMIT)

    def test_complete_release_matrix_is_verified(self) -> None:
        self._candidate("linux-x86_64", self.root / "candidates/linux")
        self._candidate("windows-x86_64", self.root / "candidates/windows")
        release = self.root / "release"
        prepare_release(self.root / "candidates", release, self.contract, self.contract["release"]["proposed_tag"], SOURCE_COMMIT)
        manifest = verify_release_dir(release, self.contract, True)
        self.assertEqual([item["matrix_id"] for item in manifest["packages"]], self.contract["expected_matrix"])

    def test_schema_files_are_valid_json(self) -> None:
        for path in (ROOT / "release/schemas").glob("*.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_invalid_release_checksum_is_rejected(self) -> None:
        checksums = self.root / "SHA256SUMS"
        checksums.write_text(f"{'x' * 64}  package.zip\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid SHA256SUMS"):
            _parse_checksums(checksums)

    def test_revoked_package_is_rejected(self) -> None:
        digest = "a" * 64
        revocations = self.root / "revocations.json"
        revocations.write_text(json.dumps({
            "schema_version": 1,
            "revocations": [{"sha256": digest, "reason": "test", "effective_date": "2026-08-01"}],
        }), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "revoked package"):
            verify_revocations({"packages": [{"filename": "package.zip", "sha256": digest}]}, revocations)

    def test_zip_symlink_and_traversal_are_rejected(self) -> None:
        for name, mode in (("link", 0o120777), ("../escape", 0o100644)):
            archive = self.root / f"{mode}.zip"
            with zipfile.ZipFile(archive, "w") as output:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                output.writestr(info, b"target")
            with self.assertRaises(ValueError):
                extract_archive(archive, self.root / "extracted")

    def test_public_tree_contains_no_local_environment_markers(self) -> None:
        forbidden = (
            "BEGIN " + "PRIVATE KEY", "BEGIN OPENSSH " + "PRIVATE KEY",
            "D:" + "\\Workspace\\", "/" + "Users/", "/" + "home/",
        )
        for path in ROOT.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".py", ".md", ".json", ".yml", ".txt"}:
                text = path.read_text(encoding="utf-8")
                for token in forbidden:
                    self.assertNotIn(token, text, f"{token} leaked into {path}")


if __name__ == "__main__":
    unittest.main()
