"""Ed25519 key pair generation and signing utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class KeyPair:
    """Ed25519 signing key pair.

    Attributes:
        private_key: Ed25519 private key for signing.
        public_key: Ed25519 public key for verification.
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a new random Ed25519 key pair."""
        priv = Ed25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    def sign(self, data: bytes) -> bytes:
        """Sign raw bytes with the private key."""
        return self.private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a signature against data. Returns True if valid."""
        try:
            self.public_key.verify(signature, data)
            return True
        except Exception:
            return False

    def public_bytes(self) -> bytes:
        """Return raw public key bytes (32 bytes for Ed25519)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_bytes_pem(self, password: Optional[bytes] = None) -> bytes:
        """Serialize private key to PEM format."""
        if password:
            enc = serialization.BestAvailableEncryption(password)
        else:
            enc = serialization.NoEncryption()
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    @classmethod
    def from_private_pem(cls, pem: bytes, password: Optional[bytes] = None) -> KeyPair:
        """Load key pair from PEM-encoded private key."""
        priv = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("Not an Ed25519 private key")
        return cls(private_key=priv, public_key=priv.public_key())
