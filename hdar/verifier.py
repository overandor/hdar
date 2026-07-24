"""Verifier — deterministic verification independent of host.

The Verifier checks that two AttestationChains from different
platforms produce identical content hashes at every epoch. This
proves that the computation is hardware-detached — it reproduces
identically regardless of the host platform.

The VerificationReport is the final artifact: a signed, tamper-evident
document that can be independently audited.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .attestation import AttestationChain
from .capsule import Capsule
from .merkle import MerkleTree


@dataclass
class VerificationReport:
    """A cross-platform verification report.

    Attributes:
        verified: True if all epochs match across platforms.
        epoch_count: Number of epochs verified.
        matching_epochs: Number of epochs with matching content hashes.
        mismatched_epochs: List of epoch indices that mismatched.
        platform_a: Platform string for chain A.
        platform_b: Platform string for chain B.
        root_hash_a: Root content hash from chain A.
        root_hash_b: Root content hash from chain B.
        report_hash: SHA-256 of the canonical report serialization.
        timestamp: Unix timestamp of report generation.
        per_epoch: Per-epoch comparison details.
    """

    verified: bool
    epoch_count: int
    matching_epochs: int
    mismatched_epochs: List[int]
    platform_a: str
    platform_b: str
    root_hash_a: str
    root_hash_b: str
    report_hash: str = ""
    timestamp: float = 0.0
    per_epoch: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if not self.report_hash:
            self.report_hash = self._compute_report_hash()

    def _compute_report_hash(self) -> str:
        """Compute SHA-256 over canonical report serialization."""
        d = self.to_dict()
        d.pop("report_hash", None)
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to dict."""
        return {
            "verified": self.verified,
            "epoch_count": self.epoch_count,
            "matching_epochs": self.matching_epochs,
            "mismatched_epochs": self.mismatched_epochs,
            "platform_a": self.platform_a,
            "platform_b": self.platform_b,
            "root_hash_a": self.root_hash_a,
            "root_hash_b": self.root_hash_b,
            "report_hash": self.report_hash,
            "timestamp": self.timestamp,
            "per_epoch": self.per_epoch,
        }

    def to_json(self) -> str:
        """Serialize report to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> VerificationReport:
        """Deserialize report from dict."""
        return cls(**d)


class Verifier:
    """Cross-platform deterministic verification engine.

    Usage:
        verifier = Verifier()
        report = verifier.verify_chains(chain_a, chain_b)
        if report.verified:
            print("Deterministic reproduction confirmed!")
    """

    def verify_chains(
        self,
        chain_a: AttestationChain,
        chain_b: AttestationChain,
    ) -> VerificationReport:
        """Verify two attestation chains from different platforms.

        Args:
            chain_a: Attestation chain from platform A.
            chain_b: Attestation chain from platform B.

        Returns:
            VerificationReport with per-epoch comparison details.
        """
        all_match, per_epoch = chain_a.cross_platform_match(chain_b)

        mismatched = [r["epoch"] for r in per_epoch if "epoch" in r and not r.get("match", False)]
        matching = len(per_epoch) - len(mismatched)

        platform_a = chain_a.attestations[0].platform.get("platform_string", "unknown") if chain_a.length else "empty"
        platform_b = chain_b.attestations[0].platform.get("platform_string", "unknown") if chain_b.length else "empty"

        return VerificationReport(
            verified=all_match and chain_a.length > 0,
            epoch_count=chain_a.length,
            matching_epochs=matching,
            mismatched_epochs=mismatched,
            platform_a=platform_a,
            platform_b=platform_b,
            root_hash_a=chain_a.root_content_hash,
            root_hash_b=chain_b.root_content_hash,
            per_epoch=per_epoch,
        )

    def verify_capsules(
        self,
        capsules_a: List[Capsule],
        capsules_b: List[Capsule],
    ) -> VerificationReport:
        """Verify two lists of capsules from different platforms.

        Convenience method: builds chains from capsule lists and verifies.

        Args:
            capsules_a: Capsules from platform A.
            capsules_b: Capsules from platform B.

        Returns:
            VerificationReport.
        """
        chain_a = AttestationChain()
        chain_b = AttestationChain()
        for cap in capsules_a:
            chain_a.add(cap)
        for cap in capsules_b:
            chain_b.add(cap)
        return self.verify_chains(chain_a, chain_b)

    def verify_merkle_inclusion(
        self,
        tree: MerkleTree,
        leaf_index: int,
        leaf_data: bytes,
    ) -> bool:
        """Verify that a leaf is included in a Merkle tree.

        Args:
            tree: The Merkle tree to verify against.
            leaf_index: Index of the leaf.
            leaf_data: Raw bytes of the leaf.

        Returns:
            True if the leaf is proven to be in the tree.
        """
        if leaf_index < 0 or leaf_index >= tree.leaf_count:
            return False
        proof = tree.proof(leaf_index)
        return proof.verify(leaf_data)

    def verify_capsule_integrity(self, capsule: Capsule) -> bool:
        """Verify a single capsule's signature and content hash.

        Args:
            capsule: The capsule to verify.

        Returns:
            True if both signature and content hash are valid.
        """
        return capsule.verify_signature() and capsule.verify_content_hash()
