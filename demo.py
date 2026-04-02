#!/usr/bin/env python3
"""
demo.py – Interactive demonstration of the Tamper-Evident Logging System.

This script:
  1. Creates sample log entries (login attempts, user actions, transactions)
  2. Verifies the pristine log → PASS
  3. Simulates three tamper scenarios:
     a) Modify an existing entry
     b) Delete an entry
     c) Reorder entries
  4. Re-verifies after each tamper → FAIL with forensic report
  5. Saves all reports to the reports/ directory

Run:
    python3 demo.py
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import time
from pathlib import Path

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from tamper_evident_logging.log_entry import LogEntry
from tamper_evident_logging.log_writer import LogWriter
from tamper_evident_logging.storage import AppendOnlyStorage
from tamper_evident_logging.crypto_signer import CryptoSigner
from tamper_evident_logging.verifier import (
    IntegrityVerifier,
    generate_tamper_report,
    print_report,
)

DATA_DIR = PROJECT_ROOT / "data"
BATCH_SIZE = 5


# -------------------------------------------------------------------- #
# Sample events                                                         #
# -------------------------------------------------------------------- #
SAMPLE_EVENTS = [
    # (event_type, description, actor, metadata)
    ("LOGIN_ATTEMPT", "User login from 192.168.1.10", "user_alice",
     {"ip": "192.168.1.10", "status": "success", "method": "password"}),
    ("LOGIN_ATTEMPT", "User login from 10.0.0.5", "user_bob",
     {"ip": "10.0.0.5", "status": "success", "method": "ssh_key"}),
    ("FILE_ACCESS", "Accessed /etc/shadow", "user_alice",
     {"path": "/etc/shadow", "action": "read", "result": "permitted"}),
    ("PRIVILEGE_ESCALATION", "sudo to root", "user_bob",
     {"target_user": "root", "command": "apt update"}),
    ("TRANSACTION", "Wire transfer $5,000 to account 9876", "user_alice",
     {"amount": 5000, "currency": "USD", "dest_account": "9876"}),
    ("CONFIG_CHANGE", "Firewall rule added: allow TCP/443", "admin_carol",
     {"service": "firewall", "rule": "allow TCP/443 from 0.0.0.0/0"}),
    ("LOGIN_ATTEMPT", "Failed login from 203.0.113.42", "unknown",
     {"ip": "203.0.113.42", "status": "failed", "method": "password"}),
    ("LOGOUT", "User session ended", "user_alice",
     {"session_duration_sec": 3600}),
    ("FILE_DELETE", "Deleted /tmp/staging/report.csv", "user_bob",
     {"path": "/tmp/staging/report.csv"}),
    ("TRANSACTION", "Payment received $1,200 from client_xyz", "system",
     {"amount": 1200, "currency": "USD", "source": "client_xyz"}),
    ("LOGIN_ATTEMPT", "User login from 172.16.0.3", "admin_carol",
     {"ip": "172.16.0.3", "status": "success", "method": "2fa_totp"}),
    ("AUDIT_REVIEW", "Quarterly security audit completed", "admin_carol",
     {"scope": "full", "findings": 0}),
]


def banner(text: str) -> None:
    width = 72
    print("\n" + "█" * width)
    print(f"█  {text:^{width - 4}}  █")
    print("█" * width + "\n")


def section(text: str) -> None:
    print(f"\n{'─' * 72}")
    print(f"  ▸ {text}")
    print(f"{'─' * 72}")


def fresh_data_dir() -> Path:
    """Remove and recreate the data directory for a clean demo."""
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir(parents=True)
    return DATA_DIR


# -------------------------------------------------------------------- #
# Phase 1: Create log entries
# -------------------------------------------------------------------- #
def phase_create_log(storage: AppendOnlyStorage, signer: CryptoSigner) -> LogWriter:
    banner("PHASE 1 — CREATING SAMPLE LOG ENTRIES")
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)

    for evt_type, desc, actor, meta in SAMPLE_EVENTS:
        entry = writer.add_event(evt_type, desc, actor, metadata=meta)
        print(f"  ✓ Logged #{entry.seq:>2}  [{entry.event_type:<22}]  "
              f"actor={entry.actor:<14}  hash={entry.entry_hash[:16]}…")
        time.sleep(0.05)   # small delay so timestamps differ visibly

    # Flush any remaining partial batch
    cp = writer.flush_checkpoint()
    if cp:
        print(f"\n  ✓ Final checkpoint #{cp['checkpoint_seq']} flushed "
              f"(entries {cp['first_entry_seq']}..{cp['last_entry_seq']})")

    print(f"\n  Total entries    : {writer.entry_count}")
    print(f"  Total checkpoints: {len(writer.checkpoints)}")
    return writer


# -------------------------------------------------------------------- #
# Phase 2: Verify pristine log
# -------------------------------------------------------------------- #
def phase_verify(storage: AppendOnlyStorage, label: str, report_name: str) -> bool:
    section(f"VERIFICATION — {label}")
    verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
    result = verifier.verify()
    report = generate_tamper_report(result)
    print_report(report)

    # Save report to disk
    path = storage.save_report(report, report_name)
    print(f"  📄 Report saved → {path.relative_to(PROJECT_ROOT)}")
    return result.is_valid


# -------------------------------------------------------------------- #
# Phase 3a: Tamper scenario — Modify an entry
# -------------------------------------------------------------------- #
def tamper_modify(storage: AppendOnlyStorage) -> None:
    banner("TAMPER SCENARIO A — MODIFY AN EXISTING ENTRY")
    print("  Simulating: An attacker changes the description of entry #3\n"
          "  (FILE_ACCESS → 'Accessed /etc/passwd' instead of '/etc/shadow')\n")

    lines = storage.read_raw_lines()
    entry_data = json.loads(lines[2])  # 0-indexed → entry #3
    print(f"  Original description : {entry_data['description']}")
    entry_data["description"] = "Accessed /etc/passwd (TAMPERED)"
    print(f"  Tampered description : {entry_data['description']}")
    lines[2] = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
    storage.write_raw_lines(lines)
    print("  ⚠  Entry #3 has been tampered with on disk.\n")


# -------------------------------------------------------------------- #
# Phase 3b: Tamper scenario — Delete an entry
# -------------------------------------------------------------------- #
def tamper_delete(storage: AppendOnlyStorage) -> None:
    banner("TAMPER SCENARIO B — DELETE AN ENTRY")
    print("  Simulating: An attacker removes entry #7 (failed login)\n")

    lines = storage.read_raw_lines()
    removed = json.loads(lines[6])
    print(f"  Removing entry #{removed['seq']} : {removed['description']}")
    del lines[6]
    storage.write_raw_lines(lines)
    print("  ⚠  Entry #7 has been deleted from the log.\n")


# -------------------------------------------------------------------- #
# Phase 3c: Tamper scenario — Reorder entries
# -------------------------------------------------------------------- #
def tamper_reorder(storage: AppendOnlyStorage) -> None:
    banner("TAMPER SCENARIO C — REORDER ENTRIES")
    print("  Simulating: An attacker swaps entries #4 and #5\n")

    lines = storage.read_raw_lines()
    e4 = json.loads(lines[3])
    e5 = json.loads(lines[4])
    print(f"  Before swap  position 4: #{e4['seq']} {e4['event_type']}")
    print(f"  Before swap  position 5: #{e5['seq']} {e5['event_type']}")
    lines[3], lines[4] = lines[4], lines[3]
    storage.write_raw_lines(lines)
    print("  ⚠  Entries #4 and #5 have been swapped on disk.\n")


# ==================================================================== #
# Main
# ==================================================================== #
def main() -> None:
    banner("TAMPER-EVIDENT LOGGING SYSTEM — FULL DEMONSTRATION")
    print("  This demo creates a secure audit log, verifies its integrity,")
    print("  then simulates three tamper scenarios to show detection.\n")

    # ---- Setup ----
    base = fresh_data_dir()
    storage = AppendOnlyStorage(base)
    signer = CryptoSigner()

    # ---- Phase 1: Build log ----
    writer = phase_create_log(storage, signer)

    # ---- Phase 2: Pristine verification ----
    ok = phase_verify(storage, "PRISTINE LOG (should PASS)", "01_pristine_verification.json")
    assert ok, "Pristine log verification unexpectedly failed!"

    # ---- Phase 3a: Modify tamper ----
    # We re-create storage from the same dir so each tamper starts from
    # the tampered state of the previous scenario.  For independent demos,
    # you would reset in between.
    tamper_modify(storage)
    phase_verify(storage, "AFTER MODIFICATION TAMPER (should FAIL)", "02_tamper_modify.json")

    # Restore pristine state for next scenario
    base = fresh_data_dir()
    storage = AppendOnlyStorage(base)
    signer_same = CryptoSigner.load_keys(base / "keys") if (base / "keys" / "private_key.pem").exists() else signer
    writer = phase_create_log(storage, signer)

    # ---- Phase 3b: Delete tamper ----
    tamper_delete(storage)
    phase_verify(storage, "AFTER DELETION TAMPER (should FAIL)", "03_tamper_delete.json")

    # Restore pristine state for next scenario
    base = fresh_data_dir()
    storage = AppendOnlyStorage(base)
    writer = phase_create_log(storage, signer)

    # ---- Phase 3c: Reorder tamper ----
    tamper_reorder(storage)
    phase_verify(storage, "AFTER REORDER TAMPER (should FAIL)", "04_tamper_reorder.json")

    # ---- Done ----
    banner("DEMONSTRATION COMPLETE")
    print("  All scenarios executed. Check the following outputs:")
    print(f"    📁 Log entries     : data/logs/entries.jsonl")
    print(f"    📁 Checkpoints     : data/checkpoints/checkpoints.jsonl")
    print(f"    📁 Keys            : data/keys/")
    print(f"    📁 Reports         : data/reports/\n")


if __name__ == "__main__":
    main()
