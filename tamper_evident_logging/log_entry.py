"""
log_entry.py – LogEntry data structure and canonical hashing.

Each log entry contains:
  - seq            : monotonic sequence number (1-based)
  - timestamp      : ISO-8601 UTC timestamp
  - event_type     : category of the event (e.g. LOGIN, TRANSACTION)
  - description    : human-readable event description
  - actor          : user / service that triggered the event
  - prev_hash      : hash of the immediately preceding entry ("0"*64 for genesis)
  - entry_hash     : SHA-256 over the canonical serialisation of all fields + prev_hash
  - metadata       : optional dict of extra key-value pairs
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


GENESIS_HASH = "0" * 64  # sentinel for the first entry


@dataclass
class LogEntry:
    seq: int
    timestamp: str
    event_type: str
    description: str
    actor: str
    prev_hash: str
    entry_hash: str = ""          # computed after construction
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Canonical serialisation & hashing
    # ------------------------------------------------------------------ #
    def _canonical_payload(self) -> str:
        """Return a deterministic JSON string of the fields that feed the hash.

        We use sorted keys and compact separators so the same logical
        entry always produces the same byte sequence on any platform.
        """
        payload = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "actor": self.actor,
            "prev_hash": self.prev_hash,
            "metadata": self.metadata,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        """SHA-256 hex digest of the canonical payload."""
        return hashlib.sha256(self._canonical_payload().encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    # Factory helpers
    # ------------------------------------------------------------------ #
    @classmethod
    def create(
        cls,
        seq: int,
        event_type: str,
        description: str,
        actor: str,
        prev_hash: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "LogEntry":
        """Build a new LogEntry with auto-generated timestamp and hash."""
        entry = cls(
            seq=seq,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            description=description,
            actor=actor,
            prev_hash=prev_hash,
            metadata=metadata or {},
        )
        entry.entry_hash = entry.compute_hash()
        return entry

    # ------------------------------------------------------------------ #
    # Serialisation / deserialisation
    # ------------------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LogEntry":
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "LogEntry":
        return cls.from_dict(json.loads(s))
