from __future__ import annotations

import json
import re
from pathlib import Path


def _job_block(text: str, job: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text)
    if not match:
        raise ValueError(f"missing workflow job: {job}")
    return match.group(1)


def _validate_action_pins(root: Path, allowlist: dict[str, str]) -> None:
    for workflow in sorted((root / ".github/workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for action, reference in re.findall(r"(?m)^\s*-\s+uses:\s+([^@\s]+)@([^\s#]+)", text):
            expected = allowlist.get(action)
            if not expected or reference != expected or not re.fullmatch(r"[0-9a-f]{40}", reference):
                raise ValueError(f"unapproved action reference in {workflow.name}: {action}@{reference}")


def check_workflows(root: Path) -> None:
    workflow_dir = root / ".github/workflows"
    expected = {"pull-request.yml", "release.yml", "verify-release.yml"}
    actual = {path.name for path in workflow_dir.glob("*.yml")}
    if actual != expected:
        raise ValueError(f"unexpected workflow set: {sorted(actual)}")
    texts = {name: (workflow_dir / name).read_text(encoding="utf-8") for name in expected}
    for name, text in texts.items():
        forbidden = ["pull_request_target", "schedule:", "windows-latest", "actions/cache@", "artifact-metadata: write", "secrets."]
        for token in forbidden:
            if token in text:
                raise ValueError(f"forbidden workflow token in {name}: {token}")
        if re.search(r"(?mi)^\s*runs-on:.*self-hosted", text):
            raise ValueError(f"self-hosted runner is forbidden in {name}")
        if re.search(r"(?m)^\s*runs-on:\s*windows-2025\s*$", text):
            raise ValueError(f"ambiguous Windows runner label in {name}")
    allowlist = json.loads((root / "release/actions-allowlist.json").read_text(encoding="utf-8"))
    _validate_action_pins(root, allowlist)
    for name, text in texts.items():
        setup_count = text.count("uses: actions/setup-python@")
        if setup_count == 0 or setup_count != text.count("python-version: '3.12.11'"):
            raise ValueError(f"every job must use the reviewed Python version in {name}")
        if text.count("check-latest: false") != setup_count:
            raise ValueError(f"setup-python must not resolve a moving version in {name}")
    if sum(text.count("contents: write") for text in texts.values()) != 1:
        raise ValueError("only the promotion job may receive contents write")

    pull = texts["pull-request.yml"]
    if "pull_request:" not in pull or "workflow_dispatch:" in pull:
        raise ValueError("pull-request workflow must run only on pull requests")
    if not re.search(r"(?ms)^permissions:\n\s+contents:\s+read\s*$", pull):
        raise ValueError("pull-request workflow must be contents-read only")
    for token in ("id-token: write", "attestations: write", "contents: write", "gh release", "actions/attest"):
        if token in pull:
            raise ValueError(f"pull-request workflow exceeds read-only policy: {token}")
    if "ubuntu-22.04" not in pull or "windows-2025-vs2026" not in pull:
        raise ValueError("pull-request workflow matrix is incomplete")
    if pull.count("prepare-toolchain --contract") != 1:
        raise ValueError("pull-request matrix must provision the reviewed toolchain")

    production = texts["release.yml"]
    if "workflow_dispatch:" not in production or "pull_request:" in production:
        raise ValueError("production workflow must be manually dispatched")
    if "ubuntu-22.04" not in production or "windows-2025-vs2026" not in production:
        raise ValueError("production workflow matrix is incomplete")
    if production.count("prepare-toolchain --contract") != 1:
        raise ValueError("production matrix must provision the reviewed toolchain")
    build = _job_block(production, "build")
    if "contents: read" not in build or "id-token: write" not in build or "attestations: write" not in build:
        raise ValueError("production build permissions are incomplete")
    if "contents: write" in build or "create-storage-record: false" not in build:
        raise ValueError("production build permissions or storage-record policy invalid")
    promote = _job_block(production, "promote")
    if "environment: release" not in promote or "contents: write" not in promote:
        raise ValueError("promotion must use the protected release environment with contents write")
    if "id-token: write" in promote or "attestations: write" in promote:
        raise ValueError("promotion must not mint new build attestations")

    verify = texts["verify-release.yml"]
    if "release:" not in verify or "types: [published]" not in verify:
        raise ValueError("independent verification must run on publication")
    if "contents: write" in verify or "id-token: write" in verify or "attestations: write" in verify:
        raise ValueError("independent verification workflow must be read-only")
    if "ubuntu-22.04" not in verify or "windows-2025-vs2026" not in verify:
        raise ValueError("independent verification matrix is incomplete")
    if verify.count("prepare-toolchain --contract") != 1:
        raise ValueError("independent verification matrix must provision the reviewed toolchain")
