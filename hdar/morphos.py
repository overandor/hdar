"""HDAR MorphOS Integration — bridge capsules into the MorphOS multi-node orchestrator.

This module provides:
  - Node registration with HDAR lineage tracking
  - Command execution with automatic capsule sealing
  - Cross-node verification via MorphOS API
  - Observer logging for prompt chain tracking
"""

from __future__ import annotations

import json
import os
import platform
import time
from typing import Any, Dict, Optional

from .capsule import Capsule, CapsuleSealer
from .keys import KeyPair
from .attestation import AttestationChain
from .verifier import Verifier, VerificationReport


class MorphOSNode:
    """A MorphOS node with HDAR lineage tracking.

    Each node has:
      - A unique node ID
      - An Ed25519 key pair for signing capsules
      - An attestation chain recording all epochs
      - An optional MorphOS orchestrator URL for registration

    Usage:
        node = MorphOSNode("colab-01", orchestrator_url="http://localhost:7860")
        node.register()
        receipt = node.execute("echo hello", workspace="quad-a")
    """

    def __init__(
        self,
        node_id: str,
        node_kind: str = "colab",
        orchestrator_url: str = "",
        api_key: str = "",
        keypair: Optional[KeyPair] = None,
    ) -> None:
        self.node_id = node_id
        self.node_kind = node_kind
        self.orchestrator_url = orchestrator_url.rstrip("/")
        self.api_key = api_key
        self._keypair = keypair or KeyPair.generate()
        self._sealer = CapsuleSealer(self._keypair)
        self._chain = AttestationChain()
        self._epoch = 0
        self._public_url = ""
        self._registered = False

    @property
    def public_key_hex(self) -> str:
        return self._keypair.public_bytes().hex()

    @property
    def chain(self) -> AttestationChain:
        return self._chain

    @property
    def chain_length(self) -> int:
        return self._chain.length

    def seal_epoch(self, payload: bytes, objective: str = "", notes: str = "") -> Capsule:
        """Seal a new epoch capsule and add it to the chain."""
        cap = self._sealer.seal(
            payload,
            epoch=self._epoch,
            metadata={
                "node_id": self.node_id,
                "node_kind": self.node_kind,
                "objective": objective,
            },
        )
        self._chain.add(cap, notes=notes or f"Epoch {self._epoch} on {self.node_id}")
        self._epoch += 1
        return cap

    def register(self) -> Dict[str, Any]:
        """Register this node with the MorphOS orchestrator."""
        import requests

        if not self.orchestrator_url:
            return {"ok": False, "error": "No orchestrator URL set"}

        payload = {
            "node_id": self.node_id,
            "kind": self.node_kind,
            "public_url": self._public_url,
            "platform": platform.platform(),
            "hdar_public_key": self.public_key_hex,
            "hdar_chain_length": self._chain.length,
        }
        try:
            r = requests.post(
                f"{self.orchestrator_url}/nodes/register",
                json=payload,
                headers={"X-API-Key": self.api_key},
                timeout=10,
            )
            result = r.json()
            self._registered = result.get("ok", False)
            return result
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def heartbeat(self) -> Dict[str, Any]:
        """Send a heartbeat to the MorphOS orchestrator."""
        import requests

        if not self.orchestrator_url:
            return {"ok": False, "error": "No orchestrator URL set"}

        payload = {
            "node_id": self.node_id,
            "chain_length": self._chain.length,
            "epoch": self._epoch,
            "platform": platform.platform(),
        }
        try:
            r = requests.post(
                f"{self.orchestrator_url}/nodes/heartbeat",
                json=payload,
                headers={"X-API-Key": self.api_key},
                timeout=10,
            )
            return r.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def execute(
        self,
        command: str,
        workspace: str = "default",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Execute a command via the MorphOS orchestrator and seal the result.

        Args:
            command: Shell command to execute.
            workspace: Target workspace (e.g., quad-a, quad-b).
            timeout: Command timeout in seconds.

        Returns:
            Dict with command result and HDAR capsule info.
        """
        import requests

        if not self.orchestrator_url:
            return {"ok": False, "error": "No orchestrator URL set"}

        payload = {
            "workspace": workspace,
            "command": command,
            "timeout_seconds": timeout,
            "create_receipt": True,
        }
        try:
            r = requests.post(
                f"{self.orchestrator_url}/terminal/run",
                json=payload,
                headers={"X-API-Key": self.api_key},
                timeout=timeout + 5,
            )
            result = r.json()
        except Exception as e:
            return {"ok": False, "error": str(e)}

        # Seal the result as an HDAR capsule
        result_bytes = json.dumps(result, sort_keys=True).encode()
        cap = self.seal_epoch(
            result_bytes,
            objective=f"execute: {command[:80]}",
            notes=f"workspace={workspace} rc={result.get('returncode', '?')}",
        )

        return {
            "ok": True,
            "result": result,
            "capsule": {
                "content_hash": cap.content_hash,
                "short_hash": cap.short_hash,
                "epoch": cap.epoch,
                "signature_valid": cap.verify_signature(),
            },
            "chain_length": self._chain.length,
        }

    def verify_cross_platform(self, other_chain: AttestationChain) -> VerificationReport:
        """Verify this node's chain against another node's chain."""
        verifier = Verifier()
        return verifier.verify_chains(self._chain, other_chain)

    def export_chain(self) -> str:
        """Export the attestation chain as JSON."""
        return json.dumps(self._chain.to_dict(), indent=2, sort_keys=True)

    def import_chain(self, chain_json: str) -> None:
        """Import an attestation chain from JSON."""
        self._chain = AttestationChain.from_dict(json.loads(chain_json))
        self._epoch = self._chain.length

    def status(self) -> Dict[str, Any]:
        """Return node status summary."""
        return {
            "node_id": self.node_id,
            "node_kind": self.node_kind,
            "platform": platform.platform(),
            "hdar_public_key": self.public_key_hex,
            "hdar_chain_length": self._chain.length,
            "hdar_epoch": self._epoch,
            "hdar_chain_valid": self._chain.verify_chain(),
            "registered": self._registered,
            "orchestrator": self.orchestrator_url,
        }
