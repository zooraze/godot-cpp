from __future__ import annotations

import io
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

from .canonical import iter_files, normalized_relative

_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def create_zip(source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
        for path in iter_files(source):
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, _FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 << 16)
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def create_tar_zst(source: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp_dir:
        tar_path = Path(temp_dir) / "archive.tar"
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for path in iter_files(source):
                relative = path.relative_to(source).as_posix()
                info = tarfile.TarInfo(relative)
                data = path.read_bytes()
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
        subprocess.run(
            ["zstd", "-19", "--threads=1", "--no-progress", "--force", str(tar_path), "-o", str(output)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


def create_archive(source: Path, output: Path, archive_format: str) -> None:
    if archive_format == "zip":
        create_zip(source, output)
    elif archive_format == "tar.zst":
        create_tar_zst(source, output)
    else:
        raise ValueError(f"unsupported archive format: {archive_format}")


def read_archive(path: Path) -> dict[str, bytes]:
    if path.name.endswith(".zip"):
        return _read_zip(path)
    if path.name.endswith(".tar.zst"):
        return _read_tar_zst(path)
    raise ValueError(f"unsupported archive: {path}")


def _read_zip(path: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = normalized_relative(info.filename)
            if name in files:
                raise ValueError(f"duplicate archive member: {name}")
            mode = info.external_attr >> 16
            if mode and stat.S_IFMT(mode) != stat.S_IFREG:
                raise ValueError(f"non-regular ZIP member: {name}")
            files[name] = archive.read(info)
    return files


def _read_tar_zst(path: Path) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory() as temp_dir:
        tar_path = Path(temp_dir) / "archive.tar"
        with tar_path.open("wb") as stream:
            subprocess.run(["zstd", "--decompress", "--stdout", str(path)], check=True, stdout=stream, stderr=subprocess.PIPE)
        files: dict[str, bytes] = {}
        with tarfile.open(tar_path, "r:") as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                name = normalized_relative(member.name)
                if not member.isfile():
                    raise ValueError(f"non-regular TAR member: {name}")
                if name in files:
                    raise ValueError(f"duplicate archive member: {name}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"failed to read TAR member: {name}")
                files[name] = extracted.read()
        return files


def extract_archive(path: Path, destination: Path) -> None:
    files = read_archive(path)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for relative, data in files.items():
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)


def validate_archive_structure(path: Path) -> None:
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            names = [info.filename for info in archive.infolist() if not info.is_dir()]
            if names != sorted(names) or len(names) != len(set(names)):
                raise ValueError("ZIP members must be unique and sorted")
            for info in archive.infolist():
                if info.is_dir():
                    continue
                normalized_relative(info.filename)
                if info.date_time != _FIXED_ZIP_TIME:
                    raise ValueError(f"non-deterministic ZIP timestamp: {info.filename}")
                if (info.external_attr >> 16) != 0o100644:
                    raise ValueError(f"non-canonical ZIP mode: {info.filename}")
        return
    if path.name.endswith(".tar.zst"):
        with tempfile.TemporaryDirectory() as temp_dir:
            tar_path = Path(temp_dir) / "archive.tar"
            with tar_path.open("wb") as stream:
                subprocess.run(["zstd", "--decompress", "--stdout", str(path)], check=True, stdout=stream, stderr=subprocess.PIPE)
            with tarfile.open(tar_path, "r:") as archive:
                members = [member for member in archive.getmembers() if not member.isdir()]
                names = [member.name for member in members]
                if names != sorted(names) or len(names) != len(set(names)):
                    raise ValueError("TAR members must be unique and sorted")
                for member in members:
                    normalized_relative(member.name)
                    if not member.isfile() or member.mtime != 0 or member.uid != 0 or member.gid != 0 or member.mode != 0o644:
                        raise ValueError(f"non-canonical TAR metadata: {member.name}")
        return
    raise ValueError(f"unsupported archive: {path}")
