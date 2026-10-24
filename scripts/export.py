#!/usr/bin/env python3
"""Export reviewed source files to a generated public checkout; never traverse private data."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

spec = importlib.util.spec_from_file_location("gitreposted_package", Path(__file__).with_name("build.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def previous_files(destination: Path) -> dict[str, str]:
    marker = destination / package.EXPORT_MARKER
    if not marker.exists():
        if any(path.name != ".git" for path in destination.iterdir()):
            raise package.PackageError("Destination is not empty and has no generated-checkout marker")
        return {}
    if package.linked(marker) or not marker.is_file() or marker.stat().st_size > 1024 * 1024:
        raise package.PackageError("Generated-checkout marker is invalid")
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
        if set(value) != {"format", "project", "files"} or value["format"] != 1 or value["project"] != "GitRePosted":
            raise ValueError()
        files = value["files"]
        if not isinstance(files, dict) or not files:
            raise ValueError()
        for name, checksum in files.items():
            if not package.allowed_file(name) or not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum):
                raise ValueError()
        return files
    except (ValueError, TypeError, KeyError) as error:
        raise package.PackageError("Generated-checkout marker is invalid") from error


def validate_destination(destination: Path, previous: dict[str, str]) -> None:
    """Only previously generated, unedited files can be overwritten or removed."""
    for current, directories, filenames in os.walk(destination, followlinks=False):
        current = Path(current)
        if current == destination and ".git" in directories:
            if package.linked(destination / ".git"):
                raise package.PackageError("Linked Git metadata is forbidden")
            directories.remove(".git")  # No credentials or Git internals are read.
        for child in directories + filenames:
            path = current / child
            name = path.relative_to(destination).as_posix()
            package.safe_relative(name)
            if package.linked(path):
                raise package.PackageError("Linked checkout entry is forbidden: " + name)
            if current == destination and name in {".git", "install.sh", package.EXPORT_MARKER}:
                if not path.is_file():
                    raise package.PackageError("Checkout metadata is not an ordinary file")
                continue
            if path.is_dir():
                if name not in package.PUBLIC_DIRECTORIES:
                    raise package.PackageError("Foreign directory in generated checkout: " + name)
            elif name not in previous:
                raise package.PackageError("Foreign file in generated checkout: " + name)
            elif digest(package.read_public_file(destination, name)) != previous[name]:
                raise package.PackageError("Generated file was edited; refusing overwrite: " + name)


def atomic_file(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    package.ordinary_directory(path.parent)
    if path.exists() and (package.linked(path) or not path.is_file()):
        raise package.PackageError("Export target is not an ordinary file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".gitreposted-export-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def export(installer: Path, runtime_source: Path, destination: Path) -> dict[str, object]:
    installer, runtime_source = package.ordinary_directory(installer), package.ordinary_directory(runtime_source)
    destination = destination.absolute()
    for source in (installer, runtime_source):
        if destination == source or source in destination.parents or destination in source.parents:
            raise package.PackageError("Export destination must be separate from both source trees")
    # Collect/scan everything before writing any checkout content.
    files = package.collect_sources(installer, runtime_source)
    if destination.exists():
        package.ordinary_directory(destination)
    else:
        package.ordinary_directory(destination.parent)
        destination.mkdir()
    previous = previous_files(destination)
    validate_destination(destination, previous)
    for name, value in files.items():
        path = destination / name
        if name in previous and path.exists():
            if digest(package.read_public_file(destination, name)) != previous[name]:
                raise package.PackageError("Concurrent edit to generated file: " + name)
        if not path.exists() or digest(path.read_bytes()) != digest(value):
            atomic_file(path, value)
    # Remove only exact, unedited files owned by the prior generated inventory.
    for name in sorted(previous.keys() - files.keys()):
        path = destination / name
        if path.exists():
            if digest(package.read_public_file(destination, name)) != previous[name]:
                raise package.PackageError("Concurrent edit to stale generated file: " + name)
            path.unlink()
    marker = {"format": 1, "project": "GitRePosted", "files": {name: digest(value) for name, value in files.items()}}
    atomic_file(destination / package.EXPORT_MARKER, (json.dumps(marker, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    package.collect(destination)
    return {"destination": str(destination), "file_count": len(files)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = export(Path(__file__).absolute().parents[1], args.runtime_source, args.destination)
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=True))
        return 0
    except (OSError, ValueError, UnicodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
