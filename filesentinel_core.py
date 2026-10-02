"""File integrity snapshots and recovery helpers for HashHarbor."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
from typing import Iterable


@dataclass(frozen=True)
class FileRecord:
    size: int
    sha256: str


@dataclass(frozen=True)
class FileEvent:
    kind: str
    path: str
    timestamp: float


class ActivityLog:
    """Append and load local HashHarbor audit events in JSON Lines format."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> list[dict[str, str]]:
        if not self.path.exists():
            return []

        records: list[dict[str, str]] = []
        with self.path.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict) and all(
                    isinstance(item.get(key), str) for key in ("timestamp", "event", "path", "details")
                ):
                    records.append(item)
        return records

    def record(self, event: str, path: str = "", details: str = "") -> dict[str, str]:
        item = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "event": event,
            "path": path,
            "details": details,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(item, ensure_ascii=True) + "\n")
        return item


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def scan_directory(root: Path) -> dict[str, FileRecord]:
    """Return SHA-256 and size for regular files below root, excluding symlinks."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)

    records: dict[str, FileRecord] = {}

    def raise_walk_error(error: OSError) -> None:
        raise error

    for directory, directories, filenames in os.walk(root, followlinks=False, onerror=raise_walk_error):
        base = Path(directory)
        directories[:] = [name for name in directories if not (base / name).is_symlink()]
        for filename in filenames:
            path = base / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            records[relative] = FileRecord(path.stat().st_size, _digest(path))
    return records


def _ensure_separate_paths(root: Path, vault: Path) -> tuple[Path, Path]:
    root = root.resolve(strict=True)
    vault = vault.expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    if root == vault or root in vault.parents or vault in root.parents:
        raise ValueError("The recovery vault and monitored folder must not contain each other.")
    return root, vault


def create_baseline(root: Path, vault: Path) -> Path:
    """Copy a consistent baseline into a separate vault and return its path."""
    root, vault = _ensure_separate_paths(root, vault)
    vault.mkdir(parents=True, exist_ok=True)
    folder_key = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    baseline = vault / f"hashharbor-{folder_key}"
    staging = vault / f".hashharbor-{folder_key}.staging"
    if baseline.exists() or staging.exists():
        raise FileExistsError("A baseline already exists in this vault. Choose an empty vault folder.")

    original_records = scan_directory(root)
    staging.mkdir()
    try:
        for relative, record in original_records.items():
            source = root / Path(relative)
            destination = staging / Path(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            if _digest(destination) != record.sha256:
                raise RuntimeError(f"File changed while its baseline was being copied: {relative}")

        manifest = {
            "version": 1,
            "root": str(root),
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "files": {
                relative: {"size": record.size, "sha256": record.sha256}
                for relative, record in original_records.items()
            },
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        staging.rename(baseline)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return baseline


def restore_baseline(root: Path, baseline: Path) -> int:
    """Restore baseline files after verifying the manifest and each backup hash."""
    root = root.resolve(strict=True)
    baseline = baseline.resolve(strict=True)
    manifest_path = baseline / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("version") != 1 or Path(manifest.get("root", "")).resolve() != root:
        raise ValueError("This baseline does not belong to the selected monitored folder.")

    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("The baseline manifest is invalid.")

    for relative, expected in files.items():
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("The baseline contains an unsafe file path.")
        source = baseline / relative_path
        destination = root / relative_path
        if source.is_symlink() or _digest(source) != expected.get("sha256"):
            raise ValueError(f"A recovery copy failed its integrity check: {relative}")
        if any(parent.is_symlink() for parent in (destination, *destination.parents) if parent != root.parent):
            raise ValueError(f"A destination path contains a symbolic link: {relative}")

    restored = 0
    for relative in files:
        source = baseline / Path(relative)
        destination = root / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        restored += 1
    return restored


def changed_files(previous: dict[str, FileRecord], current: dict[str, FileRecord]) -> list[tuple[str, str]]:
    """Return (event kind, relative path) pairs for changes between scans."""
    changes: list[tuple[str, str]] = []
    for relative in previous.keys() - current.keys():
        changes.append(("DELETED", relative))
    for relative in current.keys() - previous.keys():
        changes.append(("NEW", relative))
    for relative in previous.keys() & current.keys():
        if previous[relative].sha256 != current[relative].sha256:
            changes.append(("CHANGED", relative))
    return sorted(changes)


class RansomwareDetector:
    """Flag unusually large bursts of file changes; this is a heuristic only."""

    def __init__(self, threshold: int = 12, window_seconds: float = 30.0) -> None:
        if threshold < 1 or window_seconds <= 0:
            raise ValueError("Threshold and window must be positive.")
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.events: list[FileEvent] = []

    def add(self, changes: Iterable[tuple[str, str]], now: float | None = None) -> bool:
        timestamp = time.monotonic() if now is None else now
        self.events.extend(FileEvent(kind, path, timestamp) for kind, path in changes)
        cutoff = timestamp - self.window_seconds
        self.events = [event for event in self.events if event.timestamp >= cutoff]
        return len(self.events) >= self.threshold