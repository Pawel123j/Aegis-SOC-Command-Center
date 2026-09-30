"""Prepare hash-verified CPython 3.12 Linux x86_64 wheels for offline Docker builds."""

from __future__ import annotations

import hashlib
import re
import runpy
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from pip._vendor.packaging.tags import compatible_tags, cpython_tags
from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]
LOCKFILES = (ROOT / "backend/requirements.lock", ROOT / "backend/requirements-dev.lock")
WHEELHOUSE = ROOT / "backend/.wheelhouse"
LEGACY_CACHE = ROOT / "backend/.local/wheelhouse"
PLATFORMS = [f"manylinux_2_{minor}_x86_64" for minor in range(36, 4, -1)] + [
    "manylinux2014_x86_64",
    "manylinux2010_x86_64",
    "manylinux1_x86_64",
]
SUPPORTED_TAGS = set(cpython_tags((3, 12), ["cp312"], PLATFORMS)) | set(
    compatible_tags((3, 12), "cp312", PLATFORMS)
)


@dataclass
class LockedPackage:
    version: str
    hashes: set[str] = field(default_factory=set)


def read_locks(paths: tuple[Path, ...]) -> dict[str, LockedPackage]:
    packages: dict[str, LockedPackage] = {}
    for path in paths:
        current: LockedPackage | None = None
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip().removesuffix("\\").strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.!+_-]+)", line)
            if match:
                name, version = match.groups()
                name = canonicalize_name(name)
                if name in packages and packages[name].version != version:
                    raise ValueError(f"Conflicting versions for {name} in the lockfiles")
                current = packages.setdefault(name, LockedPackage(version))
                continue
            match = re.fullmatch(r"--hash=sha256:([a-f0-9]{64})", line)
            if current is None or match is None:
                raise ValueError(f"Unsupported lockfile entry at {path.name}:{number}")
            current.hashes.add(match.group(1))
    if not packages or any(not package.hashes for package in packages.values()):
        raise ValueError("Every locked package must have a SHA-256 hash")
    return packages


def verify_wheel(path: Path, packages: dict[str, LockedPackage]) -> str | None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Wheel must be a regular file: {path.name}")
    name, version, _, tags = parse_wheel_filename(path.name)
    package = packages.get(name)
    if package is None or str(version) != package.version:
        raise ValueError(f"Wheel is not pinned in the current lockfiles: {path.name}")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest not in package.hashes:
        raise ValueError(f"Wheel SHA-256 does not match the lockfiles: {path.name}")
    return name if tags & SUPPORTED_TAGS else None


def verified_packages(directory: Path, packages: dict[str, LockedPackage]) -> set[str]:
    if directory.is_symlink():
        raise ValueError("Wheelhouse must be a regular directory")
    found = set()
    for path in sorted(directory.glob("*.whl")):
        name = verify_wheel(path, packages)
        if name is not None:
            found.add(name)
    return found


def copy_legacy_cache(packages: dict[str, LockedPackage]) -> None:
    if not LEGACY_CACHE.is_dir() or LEGACY_CACHE.is_symlink():
        return
    for source in sorted(LEGACY_CACHE.glob("*.whl")):
        name, version, _, _ = parse_wheel_filename(source.name)
        package = packages.get(name)
        if package is None or str(version) != package.version:
            continue
        if verify_wheel(source, packages) is not None:
            destination = WHEELHOUSE / source.name
            if not destination.exists():
                shutil.copyfile(source, destination)


def download_wheels() -> int:
    if sys.platform == "win32":
        from pip._vendor import truststore

        truststore.inject_into_ssl()
    arguments = [
        "pip",
        "download",
        "--require-hashes",
        "--no-deps",
        "--only-binary=:all:",
        "--implementation=cp",
        "--python-version=3.12",
        "--abi=cp312",
        "--dest",
        str(WHEELHOUSE),
        "--find-links",
        str(WHEELHOUSE),
    ]
    for platform in PLATFORMS:
        arguments.extend(("--platform", platform))
    for path in LOCKFILES:
        arguments.extend(("--requirement", str(path)))
    previous_arguments = sys.argv
    sys.argv = arguments
    try:
        runpy.run_module("pip", run_name="__main__")
    except SystemExit as result:
        return int(result.code or 0)
    finally:
        sys.argv = previous_arguments
    return 0


def main() -> int:
    try:
        packages = read_locks(LOCKFILES)
        if WHEELHOUSE.is_symlink():
            raise ValueError("Wheelhouse must be a regular directory")
        WHEELHOUSE.mkdir(parents=True, exist_ok=True)
        verified_packages(WHEELHOUSE, packages)
        copy_legacy_cache(packages)
        found = verified_packages(WHEELHOUSE, packages)
        missing = packages.keys() - found
        if missing:
            print(f"Downloading {len(missing)} missing locked Linux wheel(s).")
            result = download_wheels()
            if result:
                return result
            found = verified_packages(WHEELHOUSE, packages)
            missing = packages.keys() - found
        if missing:
            raise ValueError(f"Missing compatible wheels: {', '.join(sorted(missing))}")
        print(
            f"Wheelhouse ready: {len(found)} locked packages, hashes verified; "
            "Linux x86_64/CPython 3.12."
        )
        return 0
    except (OSError, ValueError, ImportError) as error:
        print(f"Wheelhouse preparation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
