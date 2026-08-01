#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

from release_lib.build import run_build
from release_lib.consumer import download_release, smoke_test
from release_lib.contracts import contract_digest, load_contract, package_filename, package_id
from release_lib.package import attach_attestations
from release_lib.release import prepare_release, verify_release_dir
from release_lib.toolchains import prepare_toolchain
from release_lib.verify import verify_candidate, verify_package
from release_lib.workflow_policy import check_workflows


def _path(value: str) -> Path:
    return Path(value).resolve()


def _contract(arguments: argparse.Namespace) -> dict:
    return load_contract(_path(arguments.contract))


def _sha40(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError(f"expected full lowercase Git SHA: {value}")
    return value


def _cmd_build(args: argparse.Namespace) -> None:
    run_build(_path(args.source), _contract(args), args.matrix, _path(args.output), _sha40(args.source_commit))


def _cmd_names(args: argparse.Namespace) -> None:
    contract = _contract(args)
    identifier = package_id(contract, args.matrix)
    values = {
        "package_id": identifier,
        "package": package_filename(contract, args.matrix),
        "descriptor": f"{identifier}.candidate.json",
        "sbom": f"{identifier}.spdx.json",
        "contract_sha256": contract_digest(contract, args.matrix),
    }
    if args.github_output:
        output = Path(os.environ["GITHUB_OUTPUT"])
        with output.open("a", encoding="utf-8", newline="\n") as stream:
            for key, value in values.items():
                stream.write(f"{key}={value}\n")
    else:
        print(json.dumps(values, sort_keys=True))


def _cmd_verify_source(args: argparse.Namespace) -> None:
    commit = _sha40(args.commit)
    contract = _contract(args)
    expected_remote = f"https://github.com/{contract['repository']['full_name']}.git"
    remote = subprocess.run(
        ["git", "remote", "get-url", "origin"], check=True, text=True, stdout=subprocess.PIPE
    ).stdout.strip()
    if remote.removesuffix(".git") != expected_remote.removesuffix(".git"):
        raise ValueError(f"unexpected origin remote: {remote}")
    subprocess.run(["git", "fetch", "origin", args.branch, "--no-tags"], check=True)
    head = subprocess.run(["git", "rev-parse", f"origin/{args.branch}"], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    current = subprocess.run(["git", "rev-parse", "HEAD"], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    reachable = subprocess.run(["git", "merge-base", "--is-ancestor", commit, head]).returncode == 0
    if current != commit or not reachable:
        raise ValueError(f"production source must be the requested protected-branch commit: requested={commit} checked_out={current} branch={head}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic godot-cpp binary release tooling")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--contract", required=True)
    build.add_argument("--matrix", required=True)
    build.add_argument("--source", default=".")
    build.add_argument("--output", required=True)
    build.add_argument("--source-commit", required=True)
    build.set_defaults(func=_cmd_build)

    toolchain = sub.add_parser("prepare-toolchain")
    toolchain.add_argument("--contract", required=True)
    toolchain.add_argument("--matrix", required=True)
    toolchain.add_argument("--root", default=".")
    toolchain.set_defaults(func=lambda a: prepare_toolchain(_path(a.root), _contract(a), a.matrix))

    names = sub.add_parser("names")
    names.add_argument("--contract", required=True)
    names.add_argument("--matrix", required=True)
    names.add_argument("--github-output", action="store_true")
    names.set_defaults(func=_cmd_names)

    package = sub.add_parser("verify-package")
    package.add_argument("--contract", required=True)
    package.add_argument("--matrix", required=True)
    package.add_argument("--package", required=True)
    package.add_argument("--source-commit")
    package.set_defaults(func=lambda a: verify_package(_path(a.package), _contract(a), a.matrix, _sha40(a.source_commit) if a.source_commit else None))

    candidate = sub.add_parser("verify-candidate")
    candidate.add_argument("--contract", required=True)
    candidate.add_argument("--descriptor", required=True)
    candidate.add_argument("--require-attestations", action="store_true")
    candidate.set_defaults(func=lambda a: verify_candidate(_path(a.descriptor), _contract(a), a.require_attestations))

    attach = sub.add_parser("attach-attestations")
    attach.add_argument("--descriptor", required=True)
    attach.add_argument("--provenance", required=True)
    attach.add_argument("--sbom", required=True)
    attach.set_defaults(func=lambda a: attach_attestations(_path(a.descriptor), _path(a.provenance), _path(a.sbom)))

    release = sub.add_parser("prepare-release")
    release.add_argument("--contract", required=True)
    release.add_argument("--candidates", required=True)
    release.add_argument("--output", required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--source-commit", required=True)
    release.set_defaults(func=lambda a: prepare_release(_path(a.candidates), _path(a.output), _contract(a), a.tag, _sha40(a.source_commit)))

    release_verify = sub.add_parser("verify-release-dir")
    release_verify.add_argument("--contract", required=True)
    release_verify.add_argument("--directory", required=True)
    release_verify.set_defaults(func=lambda a: verify_release_dir(_path(a.directory), _contract(a), True))

    remote = sub.add_parser("verify-release-url")
    remote.add_argument("--contract", required=True)
    remote.add_argument("--repository", required=True)
    remote.add_argument("--tag", required=True)
    remote.add_argument("--matrix", required=True)
    remote.add_argument("--output", required=True)
    remote.add_argument("--smoke-source", required=True)
    remote.add_argument("--revocations", default="release/revocations.json")
    def verify_remote(a: argparse.Namespace) -> None:
        contract = _contract(a)
        manifest = download_release(a.repository, a.tag, _path(a.output), contract, _path(a.revocations))
        item = next(package for package in manifest["packages"] if package["matrix_id"] == a.matrix)
        smoke_test(_path(a.output) / item["filename"], a.matrix, _path(a.smoke_source), contract)
    remote.set_defaults(func=verify_remote)


    github_verify = sub.add_parser("verify-github-release")
    github_verify.add_argument("--repository", required=True)
    github_verify.add_argument("--tag", required=True)
    github_verify.add_argument("--directory", required=True)
    def verify_github(a: argparse.Namespace) -> None:
        directory = _path(a.directory)
        manifest = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
        subprocess.run(["gh", "release", "verify", a.tag, "--repo", a.repository], check=True)
        remote_json = subprocess.run(
            ["gh", "release", "view", a.tag, "--repo", a.repository, "--json", "assets"],
            check=True, text=True, stdout=subprocess.PIPE,
        ).stdout
        remote_names = {item["name"] for item in json.loads(remote_json)["assets"]}
        files = sorted(path for path in directory.iterdir() if path.is_file())
        if remote_names != {path.name for path in files}:
            raise ValueError("remote release asset inventory mismatch")
        for path in files:
            subprocess.run(["gh", "release", "verify-asset", a.tag, str(path), "--repo", a.repository], check=True)
        for package in manifest["packages"]:
            subprocess.run([
                "gh", "attestation", "verify", str(directory / package["filename"]),
                "--repo", a.repository,
                "--signer-workflow", f"{a.repository}/.github/workflows/release.yml",
                "--source-digest", manifest["source_commit"],
                "--deny-self-hosted-runners",
            ], check=True)
    github_verify.set_defaults(func=verify_github)

    source = sub.add_parser("verify-source")
    source.add_argument("--contract", required=True)
    source.add_argument("--commit", required=True)
    source.add_argument("--branch", required=True)
    source.set_defaults(func=_cmd_verify_source)

    policy = sub.add_parser("check-workflows")
    policy.add_argument("--root", default=".")
    policy.set_defaults(func=lambda a: check_workflows(_path(a.root)))

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
