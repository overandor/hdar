"""
HDAR — Hardware-Detached Agent Runtime

Unified SDK: canonical capsules, Ed25519 attestations, Merkle proof trees,
epoch chaining, portable protocol, cross-platform verification, and MorphOS
orchestration integration.

Core innovation: prove that a computation ran identically on two
different hardware/platform combinations without trusting either host.
"""

from .keys import KeyPair
from .capsule import Capsule, CapsuleSealer
from .merkle import MerkleTree, MerkleProof
from .attestation import Attestation, AttestationChain
from .verifier import Verifier, VerificationReport

__version__ = "1.0.0"
__all__ = [
    "KeyPair",
    "Capsule",
    "CapsuleSealer",
    "MerkleTree",
    "MerkleProof",
    "Attestation",
    "AttestationChain",
    "Verifier",
    "VerificationReport",
]
