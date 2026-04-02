"""
log_writer.py – Append-only log writer with Merkle checkpointing (Layers 1-4).

Responsibilities:
  - Accept new events and create LogEntry objects
  - Maintain hash chain continuity
  - Group entries into fixed-size batches
  - Compute Merkle root for each completed batch
  - Sign checkpoint roots with Ed25519
  - Request simulated trusted timestamps
  - Persist everything via the storage layer
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Dict, List, Optional

from .log_entry import LogEntry, GENESIS_HASH
from .merkle_tree import get_merkle_root
from .crypto_signer import CryptoSigner
from .timestamp_authority import request_timestamp
from .storage import AppendOnlyStorage


# Default number of entries per Merkle batch
DEFAULT_BATCH_SIZE = 5


class LogWriter:
    """High-level writer for the tamper-evident logging system."""

    def __init__(
        self,
        storage: AppendOnlyStorage,
        signer: CryptoSigner,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ):
        self.storage = storage
        self.signer = signer
        self.batch_size = batch_size

        # Recover state from existing data
        self._entries: List[LogEntry] = self.storage.read_entries()
        self._checkpoints: List[Dict[str, Any]] = self.storage.read_checkpoints()
        self._pending_batch: List[LogEntry] = []

        # Determine how many entries are already checkpointed
        checkpointed = len(self._checkpoints) * self.batch_size
        if checkpointed < len(self._entries):
            self._pending_batch = self._entries[checkpointed:]

        # Save keys on first run
        if not (self.storage.keys_dir / "private_key.pem").exists():
            self.signer.save_keys(self.storage.keys_dir)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def add_event(
        self,
        event_type: str,
        description: str,
        actor: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LogEntry:
        """Record a new event. Returns the created LogEntry."""
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        seq = len(self._entries) + 1

        entry = LogEntry.create(
            seq=seq,
            event_type=event_type,
            description=description,
            actor=actor,
            prev_hash=prev_hash,
            metadata=metadata,
        )

        # Persist immediately
        self.storage.append_entry(entry)
        self._entries.append(entry)
        self._pending_batch.append(entry)

        # Check if batch is complete
        if len(self._pending_batch) >= self.batch_size:
            self._create_checkpoint()

        return entry

    def flush_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Force a checkpoint for the current (possibly incomplete) batch.

        Useful at shutdown or before verification.
        """
        if self._pending_batch:
            return self._create_checkpoint()
        return None

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _create_checkpoint(self) -> Dict[str, Any]:
        batch_hashes = [e.entry_hash for e in self._pending_batch]
        merkle_root = get_merkle_root(batch_hashes)

        # Sign the Merkle root
        signature = self.signer.sign(merkle_root.encode("utf-8"))

        # Trusted timestamp
        ts_token = request_timestamp(merkle_root)

        checkpoint_seq = len(self._checkpoints) + 1
        first_entry_seq = self._pending_batch[0].seq
        last_entry_seq = self._pending_batch[-1].seq

        checkpoint: Dict[str, Any] = {
            "checkpoint_seq": checkpoint_seq,
            "first_entry_seq": first_entry_seq,
            "last_entry_seq": last_entry_seq,
            "batch_size": len(self._pending_batch),
            "merkle_root": merkle_root,
            "signature": base64.b64encode(signature).decode("ascii"),
            "public_key_hex": self.signer.public_key_hex(),
            "timestamp_token": ts_token.to_dict(),
        }

        self.storage.append_checkpoint(checkpoint)
        self._checkpoints.append(checkpoint)
        self._pending_batch = []
        return checkpoint

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #
    @property
    def entries(self) -> List[LogEntry]:
        return list(self._entries)

    @property
    def checkpoints(self) -> List[Dict[str, Any]]:
        return list(self._checkpoints)

    @property
    def entry_count(self) -> int:
        return len(self._entries)
