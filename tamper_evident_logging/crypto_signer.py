"""
crypto_signer.py – Ed25519 digital signature management (Layer 3).

Responsibilities:
  - Generate or load an Ed25519 key pair
  - Sign arbitrary byte payloads (checkpoint roots)
  - Verify signatures given a public key
  - Serialise keys to PEM for persistence
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class CryptoSigner:
    """Manages an Ed25519 key pair for signing / verifying checkpoint roots."""

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        if private_key is None:
            private_key = Ed25519PrivateKey.generate()
        self._private_key = private_key
        self._public_key = private_key.public_key()

    # ------------------------------------------------------------------ #
    # Signing & verification
    # ------------------------------------------------------------------ #
    def sign(self, data: bytes) -> bytes:
        """Sign *data* with the private key and return the raw signature."""
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Return True if *signature* is valid for *data* under our public key."""
        try:
            self._public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def verify_with_public_key(
        public_key: Ed25519PublicKey, signature: bytes, data: bytes
    ) -> bool:
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    # ------------------------------------------------------------------ #
    # Key persistence
    # ------------------------------------------------------------------ #
    def save_keys(self, directory: Path) -> None:
        """Write private and public keys as PEM files."""
        directory.mkdir(parents=True, exist_ok=True)

        priv_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        (directory / "private_key.pem").write_bytes(priv_pem)

        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        (directory / "public_key.pem").write_bytes(pub_pem)

    @classmethod
    def load_keys(cls, directory: Path) -> "CryptoSigner":
        priv_pem = (directory / "private_key.pem").read_bytes()
        private_key = serialization.load_pem_private_key(priv_pem, password=None)
        assert isinstance(private_key, Ed25519PrivateKey)
        return cls(private_key)

    @classmethod
    def load_public_key(cls, path: Path) -> Ed25519PublicKey:
        pub_pem = path.read_bytes()
        pub_key = serialization.load_pem_public_key(pub_pem)
        assert isinstance(pub_key, Ed25519PublicKey)
        return pub_key

    # ------------------------------------------------------------------ #
    # Convenience accessors
    # ------------------------------------------------------------------ #
    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def public_key_hex(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()
