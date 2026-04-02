#!/usr/bin/env python3
"""
cli.py – Interactive CLI for the Tamper-Evident Logging System.

Provides a menu-driven interface for:
  • Adding log entries manually
  • Viewing log entries
  • Verifying log integrity
  • Simulating tamper scenarios
  • Generating forensic reports

Run:
    python3 cli.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

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

DATA_DIR = PROJECT_ROOT / "data_interactive"
BATCH_SIZE = 5


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def pause():
    input("\n  Press Enter to continue…")


def show_menu():
    print("\n" + "=" * 56)
    print("  TAMPER-EVIDENT LOGGING SYSTEM — Interactive CLI")
    print("=" * 56)
    print("  1. Add a new log entry")
    print("  2. View all log entries")
    print("  3. View checkpoints")
    print("  4. Verify log integrity")
    print("  5. Tamper: Modify an entry")
    print("  6. Tamper: Delete an entry")
    print("  7. Tamper: Reorder two entries")
    print("  8. Reset log (start fresh)")
    print("  9. Exit")
    print("-" * 56)


def init_system():
    storage = AppendOnlyStorage(DATA_DIR)
    keys_exist = (storage.keys_dir / "private_key.pem").exists()
    if keys_exist:
        signer = CryptoSigner.load_keys(storage.keys_dir)
    else:
        signer = CryptoSigner()
    writer = LogWriter(storage, signer, batch_size=BATCH_SIZE)
    return storage, signer, writer


def add_entry(writer: LogWriter):
    print("\n  — Add New Log Entry —")
    event_type = input("  Event type (e.g. LOGIN, TRANSACTION): ").strip().upper() or "GENERIC"
    description = input("  Description: ").strip() or "No description"
    actor = input("  Actor/User: ").strip() or "unknown"
    meta_raw = input("  Metadata (JSON or blank): ").strip()
    metadata = {}
    if meta_raw:
        try:
            metadata = json.loads(meta_raw)
        except json.JSONDecodeError:
            print("  ⚠  Invalid JSON; ignoring metadata.")
    entry = writer.add_event(event_type, description, actor, metadata=metadata)
    print(f"\n  ✓ Entry #{entry.seq} logged  hash={entry.entry_hash[:32]}…")


def view_entries(storage: AppendOnlyStorage):
    entries = storage.read_entries()
    if not entries:
        print("\n  (no entries yet)")
        return
    print(f"\n  {'#':>4}  {'Type':<22}  {'Actor':<14}  {'Timestamp':<28}  Hash (first 16)")
    print("  " + "-" * 100)
    for e in entries:
        print(f"  {e.seq:>4}  {e.event_type:<22}  {e.actor:<14}  {e.timestamp:<28}  {e.entry_hash[:16]}…")


def view_checkpoints(storage: AppendOnlyStorage):
    checkpoints = storage.read_checkpoints()
    if not checkpoints:
        print("\n  (no checkpoints yet)")
        return
    for cp in checkpoints:
        print(f"\n  Checkpoint #{cp['checkpoint_seq']}  "
              f"entries {cp['first_entry_seq']}..{cp['last_entry_seq']}  "
              f"root={cp['merkle_root'][:24]}…  "
              f"sig={cp['signature'][:20]}…")


def verify(storage: AppendOnlyStorage):
    verifier = IntegrityVerifier(storage, batch_size=BATCH_SIZE)
    result = verifier.verify()
    report = generate_tamper_report(result)
    print_report(report)
    fname = "interactive_report.json"
    path = storage.save_report(report, fname)
    print(f"  📄 Report saved → {path}")


def tamper_modify(storage: AppendOnlyStorage):
    entries = storage.read_entries()
    if not entries:
        print("  No entries to tamper with."); return
    view_entries(storage)
    try:
        seq = int(input("\n  Which entry # to modify? "))
    except ValueError:
        print("  Invalid input."); return
    idx = seq - 1
    lines = storage.read_raw_lines()
    if idx < 0 or idx >= len(lines):
        print("  Entry not found."); return
    new_desc = input("  New description: ").strip()
    entry_data = json.loads(lines[idx])
    print(f"  Old: {entry_data['description']}")
    entry_data["description"] = new_desc
    lines[idx] = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
    storage.write_raw_lines(lines)
    print(f"  ⚠  Entry #{seq} modified on disk.")


def tamper_delete(storage: AppendOnlyStorage):
    entries = storage.read_entries()
    if not entries:
        print("  No entries to delete."); return
    view_entries(storage)
    try:
        seq = int(input("\n  Which entry # to delete? "))
    except ValueError:
        print("  Invalid input."); return
    idx = seq - 1
    lines = storage.read_raw_lines()
    if idx < 0 or idx >= len(lines):
        print("  Entry not found."); return
    del lines[idx]
    storage.write_raw_lines(lines)
    print(f"  ⚠  Entry #{seq} deleted from disk.")


def tamper_reorder(storage: AppendOnlyStorage):
    entries = storage.read_entries()
    if len(entries) < 2:
        print("  Need at least 2 entries."); return
    view_entries(storage)
    try:
        a = int(input("\n  First entry # to swap: "))
        b = int(input("  Second entry # to swap: "))
    except ValueError:
        print("  Invalid input."); return
    lines = storage.read_raw_lines()
    ia, ib = a - 1, b - 1
    if ia < 0 or ib < 0 or ia >= len(lines) or ib >= len(lines):
        print("  Entry not found."); return
    lines[ia], lines[ib] = lines[ib], lines[ia]
    storage.write_raw_lines(lines)
    print(f"  ⚠  Entries #{a} and #{b} swapped on disk.")


def reset():
    import shutil
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    print("  ✓ Log data reset. Starting fresh on next action.")


def main():
    while True:
        storage, signer, writer = init_system()
        show_menu()
        choice = input("  Choice [1-9]: ").strip()
        if choice == "1":
            add_entry(writer)
        elif choice == "2":
            view_entries(storage)
        elif choice == "3":
            view_checkpoints(storage)
        elif choice == "4":
            verify(storage)
        elif choice == "5":
            tamper_modify(storage)
        elif choice == "6":
            tamper_delete(storage)
        elif choice == "7":
            tamper_reorder(storage)
        elif choice == "8":
            reset()
        elif choice == "9":
            print("\n  Goodbye!\n")
            break
        else:
            print("  Invalid choice.")
        pause()


if __name__ == "__main__":
    main()
