from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def normalized_relative(path: str) -> str:
    pure = PurePosixPath(path.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ValueError(f"unsafe archive path: {path!r}")
    normalized = pure.as_posix()
    if normalized.startswith("./") or normalized.endswith("/"):
        raise ValueError(f"non-canonical archive path: {path!r}")
    return normalized


def iter_files(root: Path) -> Iterable[Path]:
    return sorted((path for path in root.rglob("*") if path.is_file()), key=lambda p: p.relative_to(root).as_posix())


def file_hashes(root: Path, excluded: set[str] | None = None) -> dict[str, str]:
    excluded = excluded or set()
    result: dict[str, str] = {}
    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        if relative not in excluded:
            result[relative] = sha256_file(path)
    return result


def hash_listing(entries: dict[str, str]) -> str:
    lines = "".join(f"{digest}  {path}\n" for path, digest in sorted(entries.items()))
    return sha256_bytes(lines.encode("utf-8"))
