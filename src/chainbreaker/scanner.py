"""Walks a directory, classifies files and runs the rules over them."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set

from .models import FileContext, Finding
from .rules import run_rules

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".idea", ".vscode",
    "coverage", ".next", ".terraform", "vendor",
}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}
MAX_FILE_BYTES = 1_000_000

EXTENSIONS = {
    ".py": "python", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".jsx": "js", ".tsx": "js",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "config", ".ini": "config", ".cfg": "config",
    ".conf": "config", ".properties": "config", ".sh": "shell", ".bash": "shell", ".tf": "terraform",
    ".pem": "key", ".key": "key", ".env": "env",
}


def classify(name: str) -> Optional[str]:
    lower = name.lower()
    if lower in (n.lower() for n in SKIP_FILES) or lower.endswith((".min.js", ".map")):
        return None
    if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
        return "docker"
    if lower.startswith(("docker-compose", "compose")) and lower.endswith((".yml", ".yaml")):
        return "compose"
    if lower == ".env" or lower.startswith(".env."):
        if lower.endswith((".example", ".sample", ".template", ".dist", ".defaults")):
            return None
        return "env"
    if lower.startswith("requirements") and lower.endswith(".txt"):
        return "requirements"
    if lower == "package.json":
        return "package_json"
    return EXTENSIONS.get(os.path.splitext(lower)[1])


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)


def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None  # binary
    return raw.decode("utf-8", errors="replace")


def iter_files(root: str, excludes: Set[str]) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excludes)
        for name in sorted(filenames):
            if name in excludes:
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            if rel in excludes or any(rel.startswith(e.rstrip("/") + "/") for e in excludes if "/" in e):
                continue
            yield os.path.join(dirpath, name)


def scan(root: str, exclude: Iterable[str] = ()) -> ScanResult:
    root = os.path.abspath(root)
    if not os.path.exists(root):
        raise FileNotFoundError(root)
    excludes = set(DEFAULT_EXCLUDES) | {e.strip().strip("/").replace("\\", "/") for e in exclude if e.strip()}
    base = os.path.dirname(root) if os.path.isfile(root) else root
    result = ScanResult(root=root)
    seen = set()
    for path in iter_files(root, excludes):
        kind = classify(os.path.basename(path))
        if kind is None:
            continue
        text = _read(path)
        if text is None:
            continue
        result.files_scanned += 1
        rel = os.path.relpath(path, base).replace(os.sep, "/")
        ctx = FileContext(path=rel, abspath=path, text=text, kind=kind)
        for finding in run_rules(ctx):
            if finding.id not in seen:
                seen.add(finding.id)
                result.findings.append(finding)
    return result
