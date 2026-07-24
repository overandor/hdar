"""Capsule — content-addressed, cryptographically sealed computation unit.

A capsule is the fundamental unit of HDAR. It captures:
  - A payload (arbitrary bytes — code, data, config, results)
  - Content-addressed hash (SHA-256 of canonical serialization)
  - Ed25519 signature from the producing agent
  - Platform metadata (OS, arch, Python version, hostname hash)
  - Epoch number for chaining

The capsule is the atom of cross-platform proof. Two capsules with
the same content hash on different platforms prove deterministic
reproduction.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .keys import KeyPair


def _canonical_json(obj: Any) -> bytes:
    """Serialize to deterministic JSON (sorted keys, no spaces)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _platform_metadata() -> Dict[str, str]:
    """Capture platform identity for attestation (hostname hashed for privacy)."""
    hostname = platform.node()
    hostname_hash = hashlib.sha256(hostname.encode()).hexdigest()[:16] if hostname else "unknown"
    return {
        "os": platform.system(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "platform_string": platform.platform(),
        "hostname_hash": hostname_hash,
    }


@dataclass
class Capsule:
    """A sealed computation capsule.

    Attributes:
        payload: Arbitrary bytes representing the computation unit.
        content_hash: SHA-256 hex of canonical payload serialization.
        signature: Ed25519 signature over content_hash.
        public_key: Ed25519 public key bytes (32 bytes).
        platform: Platform metadata dict.
        epoch: Chain epoch number (0 for genesis).
        timestamp: Unix timestamp at creation.
        metadata: Additional user-provided metadata.
    """

    payload: bytes
    content_hash: str
    signature: bytes
    public_key: bytes
    platform: Dict[str, str]
    epoch: int
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize capsule to a JSON-compatible dict."""
        return {
            "payload_hex": self.payload.hex(),
            "content_hash": self.content_hash,
            "signature_hex": self.signature.hex(),
            "public_key_hex": self.public_key.hex(),
            "platform": self.platform,
            "epoch": self.epoch,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize capsule to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Capsule:
        """Deserialize capsule from dict."""
        return cls(
            payload=bytes.fromhex(d["payload_hex"]),
            content_hash=d["content_hash"],
            signature=bytes.fromhex(d["signature_hex"]),
            public_key=bytes.fromhex(d["public_key_hex"]),
            platform=d["platform"],
            epoch=d["epoch"],
            timestamp=d["timestamp"],
            metadata=d.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, s: str) -> Capsule:
        """Deserialize capsule from JSON string."""
        return cls.from_dict(json.loads(s))

    def verify_signature(self) -> bool:
        """Verify the capsule's Ed25519 signature against its content hash."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            pub = Ed25519PublicKey.from_public_bytes(self.public_key)
            pub.verify(self.signature, self.content_hash.encode("utf-8"))
            return True
        except Exception:
            return False

    def verify_content_hash(self) -> bool:
        """Recompute and verify the content hash matches the payload."""
        return self.content_hash == self._compute_hash(self.payload, self.metadata)

    @staticmethod
    def _compute_hash(payload: bytes, metadata: Dict[str, Any]) -> str:
        """Compute SHA-256 content hash over canonical payload + metadata."""
        h = hashlib.sha256()
        h.update(payload)
        h.update(_canonical_json(metadata))
        return h.hexdigest()

    @property
    def short_hash(self) -> str:
        """First 16 chars of content hash for display."""
        return self.content_hash[:16]


class CapsuleSealer:
    """Factory for creating sealed capsules with a signing key pair.

    Usage:
        sealer = CapsuleSealer(keypair)
        capsule = sealer.seal(b"computation output", epoch=1)
        assert capsule.verify_signature()
        assert capsule.verify_content_hash()
    """

    def __init__(self, keypair: KeyPair) -> None:
        self._keypair = keypair

    def seal(
        self,
        payload: bytes,
        epoch: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Capsule:
        """Create a sealed capsule from payload bytes.

        Args:
            payload: The computation unit content (code, data, results).
            epoch: Chain epoch number (0 for genesis).
            metadata: Additional metadata to include in content hash.

        Returns:
            A sealed Capsule with signature and platform attestation.
        """
        meta = metadata or {}
        content_hash = Capsule._compute_hash(payload, meta)
        signature = self._keypair.sign(content_hash.encode("utf-8"))
        public_key = self._keypair.public_bytes()

        return Capsule(
            payload=payload,
            content_hash=content_hash,
            signature=signature,
            public_key=public_key,
            platform=_platform_metadata(),
            epoch=epoch,
            timestamp=time.time(),
            metadata=meta,
        )

    def verify(self, capsule: Capsule) -> bool:
        """Verify both signature and content hash of a capsule."""
        return capsule.verify_signature() and capsule.verify_content_hash()
