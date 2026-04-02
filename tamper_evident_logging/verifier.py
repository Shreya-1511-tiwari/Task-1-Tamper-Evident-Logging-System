"""
verifier.py – Read-only integrity verifier and tamper report generator (Layers 1-4).

Checks performed:
  1. Hash chain continuity  (Layer 1)
  2. Sequence number continuity & ordering
  3. Timestamp monotonic ordering
  4. Merkle root consistency for each batch (Layer 2)
  5. Digital signature validity on checkpoints (Layer 3)
  6. Trusted timestamp validity (Layer 4)

Outputs:
  - VerificationResult with overall status
  - List of TamperFinding objects describing each anomaly
  - Forensic report as a structured dict
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .log_entry import LogEntry, GENESIS_HASH
from .merkle_tree import get_merkle_root
from .crypto_signer import CryptoSigner
from .timestamp_authority import TimestampToken, verify_timestamp
from .storage import AppendOnlyStorage

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class TamperType(str, Enum):
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    REORDERED = "REORDERED"
    FORGED_CHECKPOINT = "FORGED_CHECKPOINT"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    TIMESTAMP_NOT_MONOTONIC = "TIMESTAMP_NOT_MONOTONIC"
    SEQUENCE_GAP = "SEQUENCE_GAP"


@dataclass
class TamperFinding:
    """Describes a single detected anomaly."""
    tamper_type: TamperType
    entry_seq: Optional[int] = None
    checkpoint_seq: Optional[int] = None
    expected: str = ""
    actual: str = ""
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tamper_type"] = self.tamper_type.value
        return d


@dataclass
class VerificationResult:
    """Overall result of log verification."""
    is_valid: bool
    entries_checked: int = 0
    checkpoints_checked: int = 0
    findings: List[TamperFinding] = field(default_factory=list)
    first_tamper_seq: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "is_valid": self.is_valid,
            "entries_checked": self.entries_checked,
            "checkpoints_checked": self.checkpoints_checked,
            "first_tamper_seq": self.first_tamper_seq,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        return d


class IntegrityVerifier:
    """Read-only verifier for the tamper-evident log."""

    def __init__(self, storage: AppendOnlyStorage, batch_size: int = 5):
        self.storage = storage
        self.batch_size = batch_size

    def verify(self) -> VerificationResult:
        """Run a full verification pass and return the result."""
        entries = self.storage.read_entries()
        checkpoints = self.storage.read_checkpoints()

        findings: List[TamperFinding] = []

        # ---- Layer 1: Hash chain & sequence checks ----
        findings.extend(self._verify_chain(entries))

        # ---- Layer 2: Merkle root consistency ----
        findings.extend(self._verify_merkle_roots(entries, checkpoints))

        # ---- Layer 3: Digital signatures ----
        findings.extend(self._verify_signatures(checkpoints))

        # ---- Layer 4: Trusted timestamps ----
        findings.extend(self._verify_timestamps(checkpoints))

        # ---- Timestamp monotonicity on entries ----
        findings.extend(self._verify_timestamp_ordering(entries))

        is_valid = len(findings) == 0
        first_tamper = None
        if not is_valid:
            seq_numbers = [f.entry_seq for f in findings if f.entry_seq is not None]
            first_tamper = min(seq_numbers) if seq_numbers else None

        return VerificationResult(
            is_valid=is_valid,
            entries_checked=len(entries),
            checkpoints_checked=len(checkpoints),
            findings=findings,
            first_tamper_seq=first_tamper,
        )

    # ------------------------------------------------------------------ #
    # Layer 1: Hash chain continuity
    # ------------------------------------------------------------------ #
    def _verify_chain(self, entries: List[LogEntry]) -> List[TamperFinding]:
        findings: List[TamperFinding] = []
        for i, entry in enumerate(entries):
            expected_seq = i + 1

            # Sequence number check
            if entry.seq != expected_seq:
                if entry.seq > expected_seq:
                    findings.append(TamperFinding(
                        tamper_type=TamperType.DELETED,
                        entry_seq=expected_seq,
                        expected=str(expected_seq),
                        actual=str(entry.seq),
                        explanation=(
                            f"Expected sequence #{expected_seq} but found #{entry.seq}. "
                            f"Entries appear to have been deleted between "
                            f"#{expected_seq} and #{entry.seq}."
                        ),
                    ))
                else:
                    findings.append(TamperFinding(
                        tamper_type=TamperType.REORDERED,
                        entry_seq=entry.seq,
                        expected=str(expected_seq),
                        actual=str(entry.seq),
                        explanation=(
                            f"Entry at position {i+1} has sequence #{entry.seq} "
                            f"instead of #{expected_seq}. Entries may have been reordered."
                        ),
                    ))

            # Previous hash linkage
            if i == 0:
                expected_prev = GENESIS_HASH
            else:
                expected_prev = entries[i - 1].entry_hash

            if entry.prev_hash != expected_prev:
                findings.append(TamperFinding(
                    tamper_type=TamperType.MODIFIED,
                    entry_seq=entry.seq,
                    expected=expected_prev,
                    actual=entry.prev_hash,
                    explanation=(
                        f"Entry #{entry.seq} prev_hash does not match the hash of "
                        f"entry #{entry.seq - 1}. The preceding entry was likely modified."
                    ),
                ))

            # Self-hash integrity
            recomputed = entry.compute_hash()
            if entry.entry_hash != recomputed:
                findings.append(TamperFinding(
                    tamper_type=TamperType.MODIFIED,
                    entry_seq=entry.seq,
                    expected=recomputed,
                    actual=entry.entry_hash,
                    explanation=(
                        f"Entry #{entry.seq} stored hash does not match the "
                        f"recomputed hash from its fields. The entry content "
                        f"was modified after logging."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Layer 2: Merkle-root consistency
    # ------------------------------------------------------------------ #
    def _verify_merkle_roots(
        self, entries: List[LogEntry], checkpoints: List[Dict[str, Any]]
    ) -> List[TamperFinding]:
        findings: List[TamperFinding] = []

        for cp in checkpoints:
            cp_seq = cp["checkpoint_seq"]
            first_seq = cp["first_entry_seq"]
            last_seq = cp["last_entry_seq"]
            stored_root = cp["merkle_root"]

            # Gather batch entries by sequence number
            batch_entries = [e for e in entries if first_seq <= e.seq <= last_seq]
            batch_hashes = [e.entry_hash for e in batch_entries]

            if len(batch_entries) != cp["batch_size"]:
                findings.append(TamperFinding(
                    tamper_type=TamperType.DELETED,
                    checkpoint_seq=cp_seq,
                    expected=str(cp["batch_size"]),
                    actual=str(len(batch_entries)),
                    explanation=(
                        f"Checkpoint #{cp_seq} expected {cp['batch_size']} entries "
                        f"(seq {first_seq}..{last_seq}) but found {len(batch_entries)}. "
                        f"Entries may have been deleted."
                    ),
                ))
                continue

            recomputed_root = get_merkle_root(batch_hashes)
            if recomputed_root != stored_root:
                findings.append(TamperFinding(
                    tamper_type=TamperType.FORGED_CHECKPOINT,
                    checkpoint_seq=cp_seq,
                    expected=stored_root,
                    actual=recomputed_root,
                    explanation=(
                        f"Merkle root mismatch for checkpoint #{cp_seq} "
                        f"(entries {first_seq}..{last_seq}). "
                        f"One or more entries in this batch were tampered with."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Layer 3: Digital signatures
    # ------------------------------------------------------------------ #
    def _verify_signatures(
        self, checkpoints: List[Dict[str, Any]]
    ) -> List[TamperFinding]:
        findings: List[TamperFinding] = []

        # Try to load the public key from storage
        pub_key_path = self.storage.keys_dir / "public_key.pem"
        if not pub_key_path.exists():
            findings.append(TamperFinding(
                tamper_type=TamperType.INVALID_SIGNATURE,
                explanation="Public key file not found. Cannot verify signatures.",
            ))
            return findings

        public_key = CryptoSigner.load_public_key(pub_key_path)

        for cp in checkpoints:
            cp_seq = cp["checkpoint_seq"]
            sig_bytes = base64.b64decode(cp["signature"])
            root_bytes = cp["merkle_root"].encode("utf-8")

            if not CryptoSigner.verify_with_public_key(public_key, sig_bytes, root_bytes):
                findings.append(TamperFinding(
                    tamper_type=TamperType.INVALID_SIGNATURE,
                    checkpoint_seq=cp_seq,
                    explanation=(
                        f"Ed25519 signature verification failed for checkpoint "
                        f"#{cp_seq}. The checkpoint data or signature may have "
                        f"been tampered with."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Layer 4: Trusted timestamps
    # ------------------------------------------------------------------ #
    def _verify_timestamps(
        self, checkpoints: List[Dict[str, Any]]
    ) -> List[TamperFinding]:
        findings: List[TamperFinding] = []

        for cp in checkpoints:
            cp_seq = cp["checkpoint_seq"]
            ts_dict = cp.get("timestamp_token")
            if ts_dict is None:
                continue

            ts = TimestampToken.from_dict(ts_dict)
            if not verify_timestamp(ts):
                findings.append(TamperFinding(
                    tamper_type=TamperType.INVALID_TIMESTAMP,
                    checkpoint_seq=cp_seq,
                    explanation=(
                        f"Trusted timestamp token verification failed for "
                        f"checkpoint #{cp_seq}. The checkpoint hash or "
                        f"timestamp may have been modified."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------ #
    # Entry timestamp ordering
    # ------------------------------------------------------------------ #
    def _verify_timestamp_ordering(
        self, entries: List[LogEntry]
    ) -> List[TamperFinding]:
        findings: List[TamperFinding] = []

        for i in range(1, len(entries)):
            try:
                prev_time = datetime.fromisoformat(entries[i - 1].timestamp)
                curr_time = datetime.fromisoformat(entries[i].timestamp)
                if curr_time < prev_time:
                    findings.append(TamperFinding(
                        tamper_type=TamperType.TIMESTAMP_NOT_MONOTONIC,
                        entry_seq=entries[i].seq,
                        expected=f">= {entries[i-1].timestamp}",
                        actual=entries[i].timestamp,
                        explanation=(
                            f"Entry #{entries[i].seq} timestamp "
                            f"({entries[i].timestamp}) is earlier than "
                            f"entry #{entries[i-1].seq} "
                            f"({entries[i-1].timestamp}). "
                            f"Entries may have been reordered."
                        ),
                    ))
            except (ValueError, TypeError):
                pass  # malformed timestamp already caught by hash mismatch

        return findings


# -------------------------------------------------------------------- #
# Tamper Report Generator
# -------------------------------------------------------------------- #

def generate_tamper_report(result: VerificationResult) -> Dict[str, Any]:
    """Create a structured forensic report from a verification result."""
    report: Dict[str, Any] = {
        "report_title": "Tamper-Evident Log – Integrity Verification Report",
        "overall_status": "PASS ✅" if result.is_valid else "FAIL ❌",
        "entries_checked": result.entries_checked,
        "checkpoints_checked": result.checkpoints_checked,
        "first_tamper_point": result.first_tamper_seq,
        "total_anomalies": len(result.findings),
        "anomalies": [],
    }

    for i, f in enumerate(result.findings, 1):
        anomaly = {
            "anomaly_number": i,
            "type": f.tamper_type.value,
            "entry_seq": f.entry_seq,
            "checkpoint_seq": f.checkpoint_seq,
            "expected": f.expected,
            "actual": f.actual,
            "explanation": f.explanation,
        }
        report["anomalies"].append(anomaly)

    if result.is_valid:
        report["summary"] = (
            "All integrity checks passed. The log chain is intact, "
            "Merkle roots are consistent, digital signatures are valid, "
            "and timestamps are properly ordered."
        )
    else:
        types = set(f.tamper_type.value for f in result.findings)
        report["summary"] = (
            f"TAMPERING DETECTED. {len(result.findings)} anomalies found. "
            f"Tamper types: {', '.join(sorted(types))}. "
            f"First affected entry: #{result.first_tamper_seq}."
        )

    return report


def print_report(report: Dict[str, Any]) -> None:
    """Pretty-print a forensic report to stdout."""
    border = "=" * 72
    print(f"\n{border}")
    print(f"  {report['report_title']}")
    print(f"{border}")
    print(f"  Status            : {report['overall_status']}")
    print(f"  Entries checked   : {report['entries_checked']}")
    print(f"  Checkpoints       : {report['checkpoints_checked']}")
    print(f"  First tamper point: {report['first_tamper_point'] or 'N/A'}")
    print(f"  Total anomalies   : {report['total_anomalies']}")
    print(f"{'-' * 72}")
    print(f"  Summary: {report['summary']}")

    if report["anomalies"]:
        print(f"\n{'─' * 72}")
        print("  DETAILED FINDINGS")
        print(f"{'─' * 72}")
        for a in report["anomalies"]:
            print(f"\n  [{a['anomaly_number']}] Type: {a['type']}")
            if a['entry_seq']:
                print(f"      Entry #     : {a['entry_seq']}")
            if a['checkpoint_seq']:
                print(f"      Checkpoint #: {a['checkpoint_seq']}")
            if a['expected']:
                print(f"      Expected    : {a['expected'][:64]}...")
            if a['actual']:
                print(f"      Actual      : {a['actual'][:64]}...")
            print(f"      Explanation : {a['explanation']}")

    print(f"\n{border}\n")
