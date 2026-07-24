"""Merkle tree — SHA-256 binary hash tree for workspace integrity.

Builds a Merkle tree over a set of items (files, capsules, arbitrary
chunks). Provides inclusion proofs that can be verified without
having the full tree.

Innovation: workspace integrity is verified by checking that a
specific item is included in the tree without downloading the
entire workspace. Only the root hash and the proof path are needed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


def _sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Hash two hex strings together (sorted for determinism)."""
    combined = bytes.fromhex(left) + bytes.fromhex(right)
    return _sha256(combined)


@dataclass
class MerkleProof:
    """A Merkle inclusion proof.

    Attributes:
        leaf_hash: Hash of the leaf being proven.
        leaf_index: Index of the leaf in the tree.
        path: List of (sibling_hash, is_right) tuples from leaf to root.
        root_hash: The Merkle root hash.
    """

    leaf_hash: str
    leaf_index: int
    path: List[Tuple[str, bool]] = field(default_factory=list)
    root_hash: str = ""

    def verify(self, leaf_data: bytes) -> bool:
        """Verify that leaf_data is included in the tree.

        Args:
            leaf_data: Raw bytes of the leaf to verify.

        Returns:
            True if the proof is valid and the leaf is included.
        """
        computed = _sha256(leaf_data)
        if computed != self.leaf_hash:
            return False

        current = computed
        for sibling_hash, is_right in self.path:
            if is_right:
                current = _hash_pair(current, sibling_hash)
            else:
                current = _hash_pair(sibling_hash, current)

        return current == self.root_hash

    def to_dict(self) -> dict:
        """Serialize proof to dict."""
        return {
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "path": [[h, r] for h, r in self.path],
            "root_hash": self.root_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> MerkleProof:
        """Deserialize proof from dict."""
        return cls(
            leaf_hash=d["leaf_hash"],
            leaf_index=d["leaf_index"],
            path=[(h, r) for h, r in d["path"]],
            root_hash=d["root_hash"],
        )


class MerkleTree:
    """SHA-256 Merkle tree over arbitrary byte chunks.

    Usage:
        tree = MerkleTree([b"file1", b"file2", b"file3"])
        root = tree.root_hash
        proof = tree.proof(1)  # proof for "file2"
        assert proof.verify(b"file2")
    """

    def __init__(self, leaves: List[bytes]) -> None:
        if not leaves:
            self._leaves: List[bytes] = []
            self._leaf_hashes: List[str] = []
            self._levels: List[List[str]] = [[]]
            self.root_hash: str = ""
            return

        self._leaves = list(leaves)
        self._leaf_hashes = [_sha256(leaf) for leaf in leaves]
        self._levels = self._build_levels(self._leaf_hashes)
        self.root_hash = self._levels[-1][0] if self._levels[-1] else ""

    @staticmethod
    def _build_levels(leaf_hashes: List[str]) -> List[List[str]]:
        """Build all levels of the tree from leaves to root."""
        if not leaf_hashes:
            return [[]]

        levels: List[List[str]] = [list(leaf_hashes)]

        while len(levels[-1]) > 1:
            current = levels[-1]
            next_level: List[str] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                next_level.append(_hash_pair(left, right))
            levels.append(next_level)

        return levels

    def proof(self, leaf_index: int) -> MerkleProof:
        """Generate an inclusion proof for the leaf at leaf_index.

        Args:
            leaf_index: Index of the leaf to prove.

        Returns:
            MerkleProof containing the sibling path from leaf to root.
        """
        if leaf_index < 0 or leaf_index >= len(self._leaf_hashes):
            raise IndexError(f"Leaf index {leaf_index} out of range")

        path: List[Tuple[str, bool]] = []
        idx = leaf_index

        for level in range(len(self._levels) - 1):
            current_level = self._levels[level]
            if idx % 2 == 0:
                sibling_idx = idx + 1
                if sibling_idx < len(current_level):
                    path.append((current_level[sibling_idx], True))
                else:
                    path.append((current_level[idx], True))
            else:
                sibling_idx = idx - 1
                path.append((current_level[sibling_idx], False))

            idx //= 2

        return MerkleProof(
            leaf_hash=self._leaf_hashes[leaf_index],
            leaf_index=leaf_index,
            path=path,
            root_hash=self.root_hash,
        )

    @property
    def leaf_count(self) -> int:
        """Number of leaves in the tree."""
        return len(self._leaves)

    @property
    def leaf_hashes(self) -> List[str]:
        """SHA-256 hashes of all leaves."""
        return list(self._leaf_hashes)

    def get_leaf(self, index: int) -> bytes:
        """Get raw leaf data by index."""
        return self._leaves[index]

    def verify_root(self, leaves: List[bytes]) -> bool:
        """Verify that a set of leaves produces this tree's root."""
        temp = MerkleTree(leaves)
        return temp.root_hash == self.root_hash

    def to_dict(self) -> dict:
        """Serialize tree metadata to dict (without leaf data)."""
        return {
            "root_hash": self.root_hash,
            "leaf_count": self.leaf_count,
            "leaf_hashes": self._leaf_hashes,
            "levels": self._levels,
        }
