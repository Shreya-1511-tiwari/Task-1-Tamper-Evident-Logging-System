"""
merkle_tree.py – Merkle-tree construction and proof utilities.

Provides:
  - build_merkle_tree(leaves)   → full tree as list of layers
  - get_merkle_root(leaves)     → root hash
  - get_merkle_proof(tree, idx) → inclusion proof for a leaf
  - verify_merkle_proof(leaf, proof, root) → bool
"""

from __future__ import annotations

import hashlib
from typing import List, Tuple


def _hash_pair(left: str, right: str) -> str:
    """Compute SHA-256 of the concatenation of two hex-digest strings."""
    combined = (left + right).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def _hash_leaf(data: str) -> str:
    """Hash a single leaf (entry hash) with a 0x00 prefix for domain separation."""
    return hashlib.sha256(b"\x00" + data.encode("utf-8")).hexdigest()


def build_merkle_tree(leaves: List[str]) -> List[List[str]]:
    """Build a full Merkle tree from a list of leaf hashes.

    Returns a list of layers (bottom → top).  layers[0] are the hashed
    leaves, layers[-1] contains the single root.

    If the number of nodes at a layer is odd, the last node is duplicated
    (standard Merkle tree padding).
    """
    if not leaves:
        return [[hashlib.sha256(b"empty").hexdigest()]]

    # Layer 0: hash each leaf with domain separation
    current_layer: List[str] = [_hash_leaf(leaf) for leaf in leaves]
    tree: List[List[str]] = [current_layer[:]]

    while len(current_layer) > 1:
        next_layer: List[str] = []
        # If odd, duplicate the last element
        if len(current_layer) % 2 == 1:
            current_layer.append(current_layer[-1])
        for i in range(0, len(current_layer), 2):
            next_layer.append(_hash_pair(current_layer[i], current_layer[i + 1]))
        tree.append(next_layer[:])
        current_layer = next_layer

    return tree


def get_merkle_root(leaves: List[str]) -> str:
    """Return the Merkle root for a list of leaf hashes."""
    tree = build_merkle_tree(leaves)
    return tree[-1][0]


def get_merkle_proof(tree: List[List[str]], index: int) -> List[Tuple[str, str]]:
    """Return the Merkle inclusion proof for the leaf at *index*.

    Each proof element is a tuple (hash, side) where side ∈ {"L", "R"}
    indicating whether the sibling is to the left or right.
    """
    proof: List[Tuple[str, str]] = []
    idx = index
    for layer in tree[:-1]:  # walk bottom-up, skip root layer
        # Ensure even length (padding)
        working = layer[:]
        if len(working) % 2 == 1:
            working.append(working[-1])

        if idx % 2 == 0:
            sibling = working[idx + 1]
            proof.append((sibling, "R"))
        else:
            sibling = working[idx - 1]
            proof.append((sibling, "L"))
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    """Verify a Merkle inclusion proof against a known root."""
    current = _hash_leaf(leaf_hash)
    for sibling, side in proof:
        if side == "R":
            current = _hash_pair(current, sibling)
        else:
            current = _hash_pair(sibling, current)
    return current == root
