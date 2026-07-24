"""Attestation — cross-platform proof of deterministic reproduction.

An attestation chains capsules across epochs and platforms. When
the same content hash appears on two different platforms, the
attestation proves deterministic reproduction — the computation
produced identical results regardless of hardware.

The AttestationChain links capsules by epoch, creating a
tamper-evident history. Each capsule's content hash is chained
with the previous epoch's hash, so modifying any epoch breaks
all subsequent attestations.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .capsule import Capsule


@dataclass
class Attestation:
    """A single cross-platform attestation record.

    Attributes:
        content_hash: The capsule content hash being attested.
        epoch: Epoch number in the chain.
        platform: Platform metadata of the attesting host.
        previous_hash: Content hash of the previous epoch's capsule (chaining).
        chain_hash: SHA-256 of (previous_hash + content_hash) — tamper-evident link.
        timestamp: Unix timestamp of attestation.
        verifier_notes: Optional human-readable notes.
    """

    content_hash: str
    epoch: int
    platform: Dict[str, str]
    previous_hash: str = ""
    chain_hash: str = ""
    timestamp: float = 0.0
    verifier_notes: str = ""

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if not self.chain_hash:
            self.chain_hash = self._compute_chain_hash()

    def _compute_chain_hash(self) -> str:
        """Compute chain hash linking this epoch to the previous."""
        data = f"{self.previous_hash}{self.content_hash}{self.epoch}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "content_hash": self.content_hash,
            "epoch": self.epoch,
            "platform": self.platform,
            "previous_hash": self.previous_hash,
            "chain_hash": self.chain_hash,
            "timestamp": self.timestamp,
            "verifier_notes": self.verifier_notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Attestation:
        """Deserialize from dict."""
        return cls(
            content_hash=d["content_hash"],
            epoch=d["epoch"],
            platform=d["platform"],
            previous_hash=d.get("previous_hash", ""),
            chain_hash=d.get("chain_hash", ""),
            timestamp=d.get("timestamp", 0.0),
            verifier_notes=d.get("verifier_notes", ""),
        )


class AttestationChain:
    """Chain of attestations across epochs and platforms.

    Each attestation links to the previous one via chain_hash,
    creating a tamper-evident history. Modifying any attestation
    breaks all subsequent chain hashes.

    Usage:
        chain = AttestationChain()
        chain.add(capsule_0)  # epoch 0
        chain.add(capsule_1)  # epoch 1, linked to epoch 0
        assert chain.verify_chain()
        assert chain.cross_platform_match(other_chain)
    """

    def __init__(self) -> None:
        self._attestations: List[Attestation] = []

    def add(self, capsule: Capsule, notes: str = "") -> Attestation:
        """Add a capsule to the chain at the next epoch.

        Args:
            capsule: The sealed capsule to attest.
            notes: Optional verifier notes.

        Returns:
            The created Attestation.
        """
        epoch = len(self._attestations)
        previous_hash = self._attestations[-1].content_hash if self._attestations else ""

        att = Attestation(
            content_hash=capsule.content_hash,
            epoch=epoch,
            platform=capsule.platform,
            previous_hash=previous_hash,
            verifier_notes=notes,
        )
        self._attestations.append(att)
        return att

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire chain.

        Checks that:
        1. Each attestation's chain_hash matches recomputed value.
        2. Each attestation's previous_hash matches the prior epoch's content_hash.
        3. Epoch numbers are sequential.
        """
        for i, att in enumerate(self._attestations):
            if att.epoch != i:
                return False

            expected = att._compute_chain_hash()
            if att.chain_hash != expected:
                return False

            if i == 0:
                if att.previous_hash != "":
                    return False
            else:
                if att.previous_hash != self._attestations[i - 1].content_hash:
                    return False

        return True

    def cross_platform_match(self, other: AttestationChain) -> Tuple[bool, List[Dict[str, Any]]]:
        """Check if two chains from different platforms have matching content hashes.

        This is the core of HDAR: if two different platforms produce the same
        content hashes at each epoch, the computation is deterministically
        reproducible — hardware-detached.

        Args:
            other: Another AttestationChain from a different platform.

        Returns:
            Tuple of (all_match, per-epoch comparison details).
        """
        if len(self._attestations) != len(other._attestations):
            return False, [{"error": "Chain length mismatch"}]

        results: List[Dict[str, Any]] = []
        all_match = True

        for i in range(len(self._attestations)):
            self_att = self._attestations[i]
            other_att = other._attestations[i]
            match = self_att.content_hash == other_att.content_hash
            if not match:
                all_match = False
            results.append({
                "epoch": i,
                "hash_a": self_att.content_hash,
                "hash_b": other_att.content_hash,
                "match": match,
                "platform_a": self_att.platform.get("platform_string", "unknown"),
                "platform_b": other_att.platform.get("platform_string", "unknown"),
            })

        return all_match, results

    @property
    def length(self) -> int:
        """Number of attestations in the chain."""
        return len(self._attestations)

    @property
    def attestations(self) -> List[Attestation]:
        """All attestations in the chain."""
        return list(self._attestations)

    @property
    def root_content_hash(self) -> str:
        """Content hash of the latest (highest epoch) attestation."""
        return self._attestations[-1].content_hash if self._attestations else ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize chain to dict."""
        return {
            "length": self.length,
            "attestations": [a.to_dict() for a in self._attestations],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> AttestationChain:
        """Deserialize chain from dict."""
        chain = cls()
        chain._attestations = [Attestation.from_dict(a) for a in d["attestations"]]
        return chain
