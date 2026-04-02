"""
storage.py – Append-only persistence layer (Layer 5).

Storage layout under a configurable base directory:
  <base>/
    logs/
      entries.jsonl          – one JSON object per line (append-only)
    checkpoints/
      checkpoints.jsonl      – checkpoint records (append-only)
    keys/
      private_key.pem
      public_key.pem
    reports/
      report_<timestamp>.json

Design decisions:
  - JSONL is human-readable, easy to demonstrate, and naturally append-only.
  - After writing, the entries file is set to read-only (simulated immutability).
  - A verification mode opens files read-only and never mutates them.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Dict, List, Any, Optional

from .log_entry import LogEntry


class AppendOnlyStorage:
    """Handles all file I/O for the tamper-evident log system."""

    def __init__(self, base_dir: str | Path):
        self.base = Path(base_dir)
        self.logs_dir = self.base / "logs"
        self.checkpoints_dir = self.base / "checkpoints"
        self.keys_dir = self.base / "keys"
        self.reports_dir = self.base / "reports"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        for d in (self.logs_dir, self.checkpoints_dir, self.keys_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Log entries
    # ------------------------------------------------------------------ #
    @property
    def entries_path(self) -> Path:
        return self.logs_dir / "entries.jsonl"

    def append_entry(self, entry: LogEntry) -> None:
        """Append a single log entry as a JSON line.  Never overwrites."""
        with open(self.entries_path, "a", encoding="utf-8") as fh:
            fh.write(entry.to_json() + "\n")

    def read_entries(self) -> List[LogEntry]:
        """Read all log entries from disk (read-only operation)."""
        if not self.entries_path.exists():
            return []
        entries: List[LogEntry] = []
        with open(self.entries_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(LogEntry.from_json(line))
        return entries

    def lock_entries_file(self) -> None:
        """Set the entries file to read-only (simulate immutable storage)."""
        if self.entries_path.exists():
            self.entries_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    def unlock_entries_file(self) -> None:
        """Restore write permission (for demonstration / tamper simulation only)."""
        if self.entries_path.exists():
            self.entries_path.chmod(
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            )

    # ------------------------------------------------------------------ #
    # Checkpoints
    # ------------------------------------------------------------------ #
    @property
    def checkpoints_path(self) -> Path:
        return self.checkpoints_dir / "checkpoints.jsonl"

    def append_checkpoint(self, checkpoint: Dict[str, Any]) -> None:
        with open(self.checkpoints_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(checkpoint, sort_keys=True, separators=(",", ":")) + "\n")

    def read_checkpoints(self) -> List[Dict[str, Any]]:
        if not self.checkpoints_path.exists():
            return []
        items: List[Dict[str, Any]] = []
        with open(self.checkpoints_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    items.append(json.loads(line))
        return items

    # ------------------------------------------------------------------ #
    # Reports
    # ------------------------------------------------------------------ #
    def save_report(self, report: Dict[str, Any], filename: str) -> Path:
        path = self.reports_dir / filename
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
        return path

    # ------------------------------------------------------------------ #
    # Raw file manipulation (for tamper simulation)
    # ------------------------------------------------------------------ #
    def read_raw_lines(self) -> List[str]:
        if not self.entries_path.exists():
            return []
        return self.entries_path.read_text(encoding="utf-8").splitlines()

    def write_raw_lines(self, lines: List[str]) -> None:
        """Overwrite the entries file wholesale – used ONLY for tamper simulation."""
        self.unlock_entries_file()
        with open(self.entries_path, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
