"""
Tamper-Evident Logging System
=============================
A secure audit-log prototype with cryptographic integrity guarantees.

Layers:
  1. Entry-level hash chain integrity
  2. Merkle-tree checkpointing
  3. Digital signatures (Ed25519) on checkpoints
  4. Trusted timestamping (RFC 3161-style simulation)
  5. Immutable append-only storage

Author : Shreya
Course : Cybersecurity & Network Security Internship
Task   : Task 1 – Tamper-Evident Logging System
"""

__version__ = "1.0.0"
