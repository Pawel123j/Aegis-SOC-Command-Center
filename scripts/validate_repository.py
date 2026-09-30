"""Read-only repository checks; not an application test or security scanner."""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SKIP = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".local",
    "dist",
    "coverage",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".codex",
    ".agents",
    ".wheelhouse",
}
TEXT_SUFFIXES = {
    ".md",
    ".py",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".sh",
    ".conf",
    ".lock",
    ".ps1",
    ".cmd",
}
TEXT_NAMES = {
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    ".env.example",
    ".dockerignore",
    "Dockerfile",
}
LINK = re.compile(r"!?\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)")


def text_files() -> list[Path]:
    """Visit source documents while pruning generated and runtime directories."""
    result = []
    for parent, directories, names in os.walk(ROOT, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name not in SKIP and not (Path(parent) / name).is_symlink()
        )
        for name in sorted(names):
            path = Path(parent) / name
            if path.suffix in TEXT_SUFFIXES or name in TEXT_NAMES:
                result.append(path)
    return result


def markdown_errors(path: Path, content: str) -> list[str]:
    """Check closed fences and local link paths outside code fences."""
    errors = []
    fence = ""
    for number, line in enumerate(content.splitlines(), 1):
        match = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
        if match:
            marker, remainder = match.groups()
            if not fence:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                if not remainder.strip():
                    fence = ""
            continue
        if fence:
            continue
        for match in LINK.finditer(line):
            target = match.group(1).strip("<>")
            parts = urlsplit(target)
            if parts.scheme or parts.netloc or not parts.path:
                continue
            resolved = (path.parent / unquote(parts.path)).resolve()
            if not resolved.is_relative_to(ROOT) or not resolved.exists():
                errors.append(f"line {number}: missing/outside local link: {target}")
    if fence:
        errors.append("unclosed Markdown fence")
    return errors


def file_errors(path: Path) -> tuple[list[str], str]:
    errors = []
    raw = path.read_bytes()
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ["not UTF-8"], ""
    if raw.startswith(b"\xef\xbb\xbf"):
        errors.append("UTF-8 BOM")
    if b"\r" in raw:
        errors.append("expected LF line endings")
    if raw and not raw.endswith(b"\n"):
        errors.append("missing final newline")
    for number, line in enumerate(content.splitlines(), 1):
        if line.rstrip() != line:
            errors.append(f"line {number}: trailing whitespace")
        if "\t" in line:
            errors.append(f"line {number}: tab indentation/content")
    if path.suffix == ".md":
        errors.extend(markdown_errors(path, content))
    try:
        if path.suffix == ".py":
            ast.parse(content, filename=str(path), feature_version=(3, 11))
        elif path.suffix == ".json":
            json.loads(content)
    except (SyntaxError, ValueError) as error:
        errors.append(f"syntax: {error}")
    return errors, content


def main() -> int:
    manifest_path = ROOT / "scripts/repository_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        required_files = manifest["required_files"]
        required_directories = manifest["required_directories"]
    except (OSError, ValueError, KeyError) as error:
        print(f"FAIL manifest: {error}")
        return 1

    errors = []
    for kind, entries in (("file", required_files), ("directory", required_directories)):
        for entry in entries:
            path = (ROOT / entry).resolve()
            exists = path.is_file() if kind == "file" else path.is_dir()
            if not path.is_relative_to(ROOT) or not exists:
                errors.append(f"missing/outside {kind}: {entry}")

    documents = {}
    files = text_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        findings, content = file_errors(path)
        errors.extend(f"{relative}: {finding}" for finding in findings)
        documents[relative] = content

    plan = documents.get("docs/implementation-plan.md", "")
    phases = [int(item) for item in re.findall(r"^## PHASE (\d+)\b", plan, re.M)]
    if phases != list(range(21)):
        errors.append("plan must contain PHASE 0..20 exactly once in order")
    matrix = documents.get("docs/requirements-traceability.md", "")
    requirements = [int(item) for item in re.findall(r"^\| (\d+) \|", matrix, re.M)]
    if requirements != list(range(1, 38)):
        errors.append("traceability must contain requirements 1..37 exactly once")
    if len(list((ROOT / "docs/adr").glob("[0-9][0-9][0-9][0-9]-*.md"))) != 6:
        errors.append("Phase 0 requires six ADR records")

    if errors:
        for error in errors:
            print(f"FAIL {error}")
        print(f"FAILED: {len(errors)} finding(s)")
        return 1
    print(
        f"PASS: {len(files)} text files, {len(required_directories)} required directories, "
        "21 phases, 37 requirements, 6 ADRs; local links, text format, Python/JSON syntax."
    )
    print("Scope: repository structure, text and syntax only; no runtime or hosted CI tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
