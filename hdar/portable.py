"""HDAR Portable Protocol — workspace-level sealing, transport, and verification.

This module provides the workspace-level operations that complement the
capsule-level SDK. It implements:
  - Workspace hashing (content-addressed file blocks)
  - Capsule sealing with owner + executor signatures
  - Capsule verification (integrity + signature + content blocks)
  - Transport capsule creation (tar.gz)
  - Capsule restoration (extract workspace from capsule)
  - Host A / Host B / Host C workflow
  - Independent verifier

This is derived from hdar-hitelesites/hdar_portable.py and unified
into the single HDAR package.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tarfile
import time
from pathlib import Path

from .keys import KeyPair

# ---------------------------------------------------------------------------
# Canonical constants
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "hdar/v1.1-seed"
CAPSULE_SCHEMA = "hdar.transport-capsule/v1.1"
RECEIPT_SCHEMA = "hdar.receipt/v1.1"
REPORT_SCHEMA = "hdar.host-report/v1.1"
VERIFIER_SCHEMA = "hdar.verifier-report/v1.1"
AGENT_ID = "hdar-seed-agent"
CHUNK_SIZE = 1024 * 1024

# ---------------------------------------------------------------------------
# Hashing primitives
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


# ---------------------------------------------------------------------------
# Workspace hashing
# ---------------------------------------------------------------------------


def hash_workspace(workspace: Path) -> dict:
    files: list[dict] = []
    total_size = 0
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel_path = path.relative_to(workspace).as_posix()
        st = path.stat()
        entry = {
            "rel_path": rel_path,
            "sha256": sha256_file(path),
            "size": st.st_size,
            "mode": st.st_mode & 0o777,
        }
        files.append(entry)
        total_size += entry["size"]
    root_material = "\n".join(
        f"{f['rel_path']}|{f['sha256']}|{f['size']}|{f['mode']}" for f in files
    ).encode()
    return {
        "root_hash": sha256_bytes(root_material),
        "files": files,
        "total_size": total_size,
    }


# ---------------------------------------------------------------------------
# Crypto — Ed25519 via KeyPair
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    kp = KeyPair.generate()
    priv_bytes = kp.private_key.private_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.Raw,
        encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
    )
    pub_bytes = kp.public_bytes()
    return priv_bytes, pub_bytes


def sign_message(priv_bytes: bytes, message: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    try:
        priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv.sign(message)
    except Exception:
        return sha256_bytes(message + priv_bytes).encode()


def verify_signature(pub_bytes: bytes, message: bytes, signature: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(signature, message)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Capsule seal with Host attestation signatures
# ---------------------------------------------------------------------------

_EXCLUDE_FROM_HASH = {"manifest_hash", "owner_signature", "executor_signature"}


def seal_workspace(
    workspace: Path,
    capsule_dir: Path,
    *,
    epoch: int,
    parent_manifest_hash: str | None,
    source_host_label: str,
    objective: str,
    continuation_point: str,
    owner_private_key: bytes | None = None,
    owner_public_key: bytes | None = None,
    executor_private_key: bytes | None = None,
    executor_public_key: bytes | None = None,
    executor_platform_attestation: str = "local-host-runtime",
) -> dict:
    capsule_dir.mkdir(parents=True, exist_ok=True)
    blocks_dir = capsule_dir / "blocks"
    blocks_dir.mkdir(parents=True, exist_ok=True)

    workspace_manifest = hash_workspace(workspace)
    for entry in workspace_manifest["files"]:
        src = workspace / entry["rel_path"]
        digest = entry["sha256"]
        dest = blocks_dir / digest[:2] / digest
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    manifest: dict = {
        "schema": CAPSULE_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "agent_id": AGENT_ID,
        "epoch": epoch,
        "parent_manifest_hash": parent_manifest_hash,
        "created_at": time.time(),
        "source_host_label": source_host_label,
        "objective": objective,
        "continuation_point": continuation_point,
        "verification_mode": "sha256-content-addressed",
        "workspace_manifest": workspace_manifest,
    }

    if owner_public_key is not None:
        manifest["owner_signature_algorithm"] = "ed25519"
        manifest["owner_public_key"] = owner_public_key.hex()

    if executor_public_key is not None:
        manifest["executor_signature_algorithm"] = "ed25519"
        manifest["executor_public_key"] = executor_public_key.hex()
        manifest["executor_host_label"] = source_host_label
        manifest["executor_platform_attestation"] = executor_platform_attestation

    manifest["manifest_hash"] = sha256_bytes(
        canonical_json({k: v for k, v in manifest.items() if k not in _EXCLUDE_FROM_HASH})
    )

    if owner_private_key is not None and owner_public_key is not None:
        owner_sig = sign_message(owner_private_key, manifest["manifest_hash"].encode())
        manifest["owner_signature"] = owner_sig.hex()

    if executor_private_key is not None and executor_public_key is not None:
        exec_sig = sign_message(executor_private_key, manifest["manifest_hash"].encode())
        manifest["executor_signature"] = exec_sig.hex()

    (capsule_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True)
    )

    receipt: dict = {
        "schema": RECEIPT_SCHEMA,
        "event": "capsule_sealed",
        "agent_id": AGENT_ID,
        "epoch": epoch,
        "source_host_label": source_host_label,
        "manifest_hash": manifest["manifest_hash"],
        "workspace_root_hash": workspace_manifest["root_hash"],
        "timestamp": time.time(),
        "platform": platform.platform(),
    }
    receipt["receipt_hash"] = sha256_bytes(
        canonical_json({k: v for k, v in receipt.items() if k != "receipt_hash"})
    )
    (capsule_dir / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True)
    )
    return manifest


# ---------------------------------------------------------------------------
# Capsule verify
# ---------------------------------------------------------------------------


def verify_capsule(capsule_dir: Path, owner_public_key: bytes | None = None) -> dict:
    problems: list[str] = []
    if not (capsule_dir / "manifest.json").exists():
        return {"ok": False, "problems": ["manifest.json missing"]}

    try:
        manifest = json.loads((capsule_dir / "manifest.json").read_text())
    except Exception as e:
        return {"ok": False, "problems": [f"failed to parse manifest.json: {e}"]}

    expected_hash = sha256_bytes(
        canonical_json({k: v for k, v in manifest.items() if k not in _EXCLUDE_FROM_HASH})
    )
    if expected_hash != manifest.get("manifest_hash"):
        problems.append("manifest hash mismatch")

    missing = 0
    corrupt = 0
    for entry in manifest.get("workspace_manifest", {}).get("files", []):
        digest = entry["sha256"]
        blob = capsule_dir / "blocks" / digest[:2] / digest
        if not blob.exists():
            missing += 1
        elif sha256_file(blob) != digest:
            corrupt += 1
    if missing:
        problems.append(f"{missing} content blocks missing")
    if corrupt:
        problems.append(f"{corrupt} content blocks corrupt")

    if owner_public_key is not None:
        stored_pub = manifest.get("owner_public_key", "")
        if stored_pub and bytes.fromhex(stored_pub) != owner_public_key:
            problems.append("owner public key mismatch")
        sig_hex = manifest.get("owner_signature", "")
        if sig_hex:
            valid = verify_signature(
                owner_public_key,
                manifest["manifest_hash"].encode(),
                bytes.fromhex(sig_hex),
            )
            if not valid:
                problems.append("owner signature verification failed")

    receipt_path = capsule_dir / "receipt.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        expected_rh = sha256_bytes(
            canonical_json({k: v for k, v in receipt.items() if k != "receipt_hash"})
        )
        if expected_rh != receipt.get("receipt_hash"):
            problems.append("receipt hash mismatch")

    return {"ok": len(problems) == 0, "problems": problems}


# ---------------------------------------------------------------------------
# Transport capsule (tar.gz)
# ---------------------------------------------------------------------------


def create_transport_capsule(capsule_dir: Path, output_path: Path) -> Path:
    with tarfile.open(output_path, "w:gz") as tf:
        tf.add(str(capsule_dir), arcname=capsule_dir.name)
    return output_path


def extract_transport_capsule(tar_path: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tf:
        tf.extractall(dest_dir)
    children = list(dest_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir


# ---------------------------------------------------------------------------
# Restore workspace from capsule
# ---------------------------------------------------------------------------


def restore_workspace(capsule_dir: Path, target_dir: Path) -> dict:
    target_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((capsule_dir / "manifest.json").read_text())
    blocks_dir = capsule_dir / "blocks"

    restored = 0
    for entry in manifest.get("workspace_manifest", {}).get("files", []):
        digest = entry["sha256"]
        blob = blocks_dir / digest[:2] / digest
        if blob.exists():
            dest = target_dir / entry["rel_path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(blob, dest)
            restored += 1

    return {
        "restored_files": restored,
        "total_files": len(manifest.get("workspace_manifest", {}).get("files", [])),
        "manifest_hash": manifest.get("manifest_hash", ""),
    }
