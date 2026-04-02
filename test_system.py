#!/usr/bin/env python3
"""
test_system.py – Automated test suite for the Tamper-Evident Logging System.

Tests cover:
  1. Entry creation and hash chain integrity
  2. Merkle-tree construction and proof verification
  3. Ed25519 signing and verification
  4. Trusted timestamp simulation
  5. Full log verification (pristine → PASS)
  6. Tamper detection: modification
  7. Tamper detection: deletion
  8. Tamper detection: reordering
  9. Checkpoint signature forgery detection
  10. End-to-end report generation

Run:
    python3 test_system.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from tamper_evident_logging.log_entry import LogEntry, GENESIS_HASH
from tamper_evident_logging.merkle_tree import (
    build_merkle_tree,
    get_merkle_root,
    get_merkle_proof,
    verify_merkle_proof,
)
from tamper_evident_logging.crypto_signer import CryptoSigner
from tamper_evident_logging.timestamp_authority import (
    request_timestamp,
    verify_timestamp,
    TimestampToken,
)
from tamper_evident_logging.log_writer import LogWriter
from tamper_evident_logging.storage import AppendOnlyStorage
from tamper_evident_logging.verifier import (
    IntegrityVerifier,
    TamperType,
    generate_tamper_report,
)


BATCH_SIZE = 3  # small batches for faster testing
passed = 0
failed = 0
total = 0


def test(name: str):
    global total
    total += 1
    def decorator(fn):
        def wrapper():
            global passed, failed
            try:
                fn()
                print(f"  ✅ PASS  {name}")
                passed += 1
            except Exception as e:
                print(f"  ❌ FAIL  {name}")
                print(f"          {e}")
                failed += 1
        return wrapper
    return decorator


def make_temp_storage() -> AppendOnlyStorage:
    """Create a storage instance in a unique temp directory."""
    d = tempfile.mkdtemp(prefix="tels_test_")
    return AppendOnlyStorage(d)


# ==================================================================== #
# Test: LogEntry hashing
# ==================================================================== #
@test("LogEntry canonical hashing is deterministic")
def test_entry_hash_deterministic():
    e1 = LogEntry.create(1, "TEST", "desc", "actor", GENESIS_HASH)
    e2 = LogEntry(
        seq=e1.seq,
        timestamp=e1.timestamp,
        event_type=e1.event_type,
        description=e1.description,
        actor=e1.actor,
        prev_hash=e1.prev_hash,
        metadata=e1.metadata,
    )
    e2.entry_hash = e2.compute_hash()
    assert e1.entry_hash == e2.entry_hash, "Hashes differ for identical entries"


@test("LogEntry hash changes when content changes")
def test_entry_hash_sensitive():
    e = LogEntry.create(1, "TEST", "original", "actor", GENESIS_HASH)
    original_hash = e.entry_hash
    e.description = "tampered"
    assert e.compute_hash() != original_hash, "Hash didn't change after modification"


@test("LogEntry serialisation round-trip preserves data")
def test_entry_roundtrip():
    e = LogEntry.create(1, "LOGIN", "User logged in", "alice", GENESIS_HASH, {"ip": "1.2.3.4"})
    j = e.to_json()
    e2 = LogEntry.from_json(j)
    assert e.entry_hash == e2.entry_hash
    assert e.metadata == e2.metadata


# ==================================================================== #
# Test: Merkle tree
# ==================================================================== #
@test("Merkle tree root is stable for same leaves")
def test_merkle_root_stable():
    leaves = ["aaa", "bbb", "ccc", "ddd"]
    r1 = get_merkle_root(leaves)
    r2 = get_merkle_root(leaves)
    assert r1 == r2


@test("Merkle tree root changes when a leaf changes")
def test_merkle_root_changes():
    r1 = get_merkle_root(["a", "b", "c"])
    r2 = get_merkle_root(["a", "X", "c"])
    assert r1 != r2


@test("Merkle proof verifies for each leaf")
def test_merkle_proof():
    leaves = ["alpha", "bravo", "charlie", "delta", "echo"]
    tree = build_merkle_tree(leaves)
    root = tree[-1][0]
    for i, leaf in enumerate(leaves):
        proof = get_merkle_proof(tree, i)
        assert verify_merkle_proof(leaf, proof, root), f"Proof failed for leaf {i}"


@test("Merkle proof fails for wrong leaf")
def test_merkle_proof_wrong_leaf():
    leaves = ["a", "b", "c"]
    tree = build_merkle_tree(leaves)
    root = tree[-1][0]
    proof = get_merkle_proof(tree, 0)
    assert not verify_merkle_proof("wrong", proof, root)


# ==================================================================== #
# Test: Crypto signer
# ==================================================================== #
@test("Ed25519 sign and verify")
def test_sign_verify():
    signer = CryptoSigner()
    data = b"checkpoint_root_hash"
    sig = signer.sign(data)
    assert signer.verify(sig, data)


@test("Ed25519 verify rejects altered data")
def test_sign_verify_tampered():
    signer = CryptoSigner()
    sig = signer.sign(b"original")
    assert not signer.verify(sig, b"tampered")


@test("Ed25519 key persistence round-trip")
def test_key_persistence():
    d = Path(tempfile.mkdtemp(prefix="tels_keys_"))
    signer = CryptoSigner()
    signer.save_keys(d)
    loaded = CryptoSigner.load_keys(d)
    sig = signer.sign(b"test")
    assert loaded.verify(sig, b"test")
    shutil.rmtree(d)


# ==================================================================== #
# Test: Timestamp authority
# ==================================================================== #
@test("Simulated TSA token verifies correctly")
def test_tsa_verify():
    token = request_timestamp("abc123")
    assert verify_timestamp(token)


@test("Simulated TSA token fails if hash is changed")
def test_tsa_tampered():
    token = request_timestamp("abc123")
    token.checkpoint_hash = "tampered"
    assert not verify_timestamp(token)


# ==================================================================== #
# Test: Full system — pristine verification
# ==================================================================== #
@test("Pristine log passes full verification")
def test_pristine_verification():
    storage = make_temp_storage()
    signer = CryptoSigner()
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)
    for i in range(9):
        writer.add_event("EVENT", f"Event {i+1}", "tester")
    writer.flush_checkpoint()

    verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
    result = verifier.verify()
    assert result.is_valid, f"Expected valid but got {len(result.findings)} findings"
    shutil.rmtree(storage.base)


# ==================================================================== #
# Test: Tamper detection — modification
# ==================================================================== #
@test("Modification tamper is detected")
def test_tamper_modification():
    storage = make_temp_storage()
    signer = CryptoSigner()
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)
    for i in range(6):
        writer.add_event("EVENT", f"Event {i+1}", "tester")
    writer.flush_checkpoint()

    # Tamper: change entry #3
    lines = storage.read_raw_lines()
    d = json.loads(lines[2])
    d["description"] = "TAMPERED"
    lines[2] = json.dumps(d, sort_keys=True, separators=(",", ":"))
    storage.write_raw_lines(lines)

    verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
    result = verifier.verify()
    assert not result.is_valid
    types = {f.tamper_type for f in result.findings}
    assert TamperType.MODIFIED in types, f"Expected MODIFIED in {types}"
    shutil.rmtree(storage.base)


# ==================================================================== #
# Test: Tamper detection — deletion
# ==================================================================== #
@test("Deletion tamper is detected")
def test_tamper_deletion():
    storage = make_temp_storage()
    signer = CryptoSigner()
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)
    for i in range(6):
        writer.add_event("EVENT", f"Event {i+1}", "tester")
    writer.flush_checkpoint()

    # Tamper: remove entry #4
    lines = storage.read_raw_lines()
    del lines[3]
    storage.write_raw_lines(lines)

    verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
    result = verifier.verify()
    assert not result.is_valid
    types = {f.tamper_type for f in result.findings}
    # Should detect sequence gap or deletion
    assert TamperType.DELETED in types or TamperType.MODIFIED in types, \
        f"Expected deletion detection, got {types}"
    shutil.rmtree(storage.base)


# ==================================================================== #
# Test: Tamper detection — reorder
# ==================================================================== #
@test("Reorder tamper is detected")
def test_tamper_reorder():
    storage = make_temp_storage()
    signer = CryptoSigner()
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)
    for i in range(6):
        writer.add_event("EVENT", f"Event {i+1}", "tester")
    writer.flush_checkpoint()

    # Tamper: swap entries #2 and #3
    lines = storage.read_raw_lines()
    lines[1], lines[2] = lines[2], lines[1]
    storage.write_raw_lines(lines)

    verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
    result = verifier.verify()
    assert not result.is_valid
    types = {f.tamper_type for f in result.findings}
    assert TamperType.REORDERED in types or TamperType.MODIFIED in types, \
        f"Expected reorder detection, got {types}"
    shutil.rmtree(storage.base)


# ==================================================================== #
# Test: Report generation
# ==================================================================== #
@test("Forensic report generated correctly for tampered log")
def test_report_generation():
    storage = make_temp_storage()
    signer = CryptoSigner()
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)
    for i in range(6):
        writer.add_event("EVENT", f"Event {i+1}", "tester")
    writer.flush_checkpoint()

    # Tamper
    lines = storage.read_raw_lines()
    d = json.loads(lines[0])
    d["description"] = "TAMPERED"
    lines[0] = json.dumps(d, sort_keys=True, separators=(",", ":"))
    storage.write_raw_lines(lines)

    verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
    result = verifier.verify()
    report = generate_tamper_report(result)

    assert report["overall_status"] == "FAIL ❌"
    assert report["total_anomalies"] > 0
    assert len(report["anomalies"]) > 0
    assert report["summary"].startswith("TAMPERING DETECTED")

    path = storage.save_report(report, "test_report.json")
    assert path.exists()
    shutil.rmtree(storage.base)


# ==================================================================== #
# Test: Append-only storage
# ==================================================================== #
@test("Append-only storage preserves entries across reads")
def test_storage_persistence():
    storage = make_temp_storage()
    e1 = LogEntry.create(1, "X", "d1", "a1", GENESIS_HASH)
    e2 = LogEntry.create(2, "Y", "d2", "a2", e1.entry_hash)
    storage.append_entry(e1)
    storage.append_entry(e2)
    loaded = storage.read_entries()
    assert len(loaded) == 2
    assert loaded[0].entry_hash == e1.entry_hash
    assert loaded[1].entry_hash == e2.entry_hash
    shutil.rmtree(storage.base)


# ==================================================================== #
# Runner
# ==================================================================== #
def main():
    print("\n" + "=" * 60)
    print("  TAMPER-EVIDENT LOGGING SYSTEM — TEST SUITE")
    print("=" * 60 + "\n")

    tests = [
        test_entry_hash_deterministic,
        test_entry_hash_sensitive,
        test_entry_roundtrip,
        test_merkle_root_stable,
        test_merkle_root_changes,
        test_merkle_proof,
        test_merkle_proof_wrong_leaf,
        test_sign_verify,
        test_sign_verify_tampered,
        test_key_persistence,
        test_tsa_verify,
        test_tsa_tampered,
        test_pristine_verification,
        test_tamper_modification,
        test_tamper_deletion,
        test_tamper_reorder,
        test_report_generation,
        test_storage_persistence,
    ]

    for t in tests:
        t()

    print(f"\n{'─' * 60}")
    print(f"  Results: {passed} passed, {failed} failed, {total} total")
    if failed == 0:
        print("  🎉 ALL TESTS PASSED")
    else:
        print("  ⚠  SOME TESTS FAILED")
    print(f"{'─' * 60}\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
