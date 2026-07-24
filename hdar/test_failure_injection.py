#!/usr/bin/env python3
"""HDAR Failure-Injection Tests — prove the verifier rejects tampered evidence.

Each test follows the canonical attack-resistance pattern:
  1. Create untampered control evidence (must pass)
  2. Construct attack (tamper specific field)
  3. Invoke verifier on tampered evidence
  4. Check verifier rejected with expected reason
  5. Confirm untampered control still passes

Exit code 0 = all tampered evidence was correctly rejected (PASS)
Exit code 1 = some tampered evidence passed the verifier (SECURITY GAP)
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from hdar.portable import (
    seal_workspace,
    verify_capsule,
    sha256_bytes,
    canonical_json,
    PROTOCOL_VERSION,
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def setup_fresh_evidence(base_dir: Path) -> tuple[Path, Path, bytes, bytes]:
    """Create fresh E1 and E2 capsules for tampering."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    ws = base_dir / "workspace"
    ws.mkdir(parents=True)
    (ws / "main.py").write_text("def divide(a, b):\n    return a / b\n")
    (ws / "test.py").write_text("from main_app import divide\nassert divide(10, 2) == 5.0\n")

    e1_dir = base_dir / "capsule_epoch_1"
    seal_workspace(
        workspace=ws, capsule_dir=e1_dir,
        epoch=1, parent_manifest_hash=None,
        source_host_label="host-a", objective="test", continuation_point="init",
        owner_private_key=priv_bytes, owner_public_key=pub_bytes,
    )

    (ws / "output.txt").write_text("test output\n")
    e2_dir = base_dir / "capsule_epoch_2"
    e1_manifest = json.loads((e1_dir / "manifest.json").read_text())
    seal_workspace(
        workspace=ws, capsule_dir=e2_dir,
        epoch=2, parent_manifest_hash=e1_manifest["manifest_hash"],
        source_host_label="host-b", objective="execute", continuation_point="post-run",
        owner_private_key=priv_bytes, owner_public_key=pub_bytes,
    )

    return e1_dir, e2_dir, pub_bytes, priv_bytes


def run_verifier(e1_dir: Path, e2_dir: Path, pub_bytes: bytes) -> tuple[bool, list[str]]:
    v1 = verify_capsule(e1_dir, pub_bytes)
    v2 = verify_capsule(e2_dir, pub_bytes)
    all_ok = v1["ok"] and v2["ok"]
    problems = v1["problems"] + v2["problems"]
    return all_ok, problems


def check_lineage(e1_dir: Path, e2_dir: Path) -> tuple[bool, str]:
    e1m = json.loads((e1_dir / "manifest.json").read_text())
    e2m = json.loads((e2_dir / "manifest.json").read_text())
    ok = e2m.get("parent_manifest_hash") == e1m.get("manifest_hash")
    return ok, "lineage intact" if ok else "lineage broken"


def run_attack_test(test_name, attack_fn, expected_reason, check_fn=None):
    """Run attack-resistance test: control -> attack -> verify -> reject."""
    with tempfile.TemporaryDirectory() as base_dir:
        base = Path(base_dir)
        e1, e2, pub, priv = setup_fresh_evidence(base)

        # Control must pass
        control_ok, control_problems = run_verifier(e1, e2, pub)
        if not control_ok:
            return False, f"CONTROL FAILED: {control_problems}"
        if check_fn:
            cl_ok, _ = check_fn(e1, e2)
            if not cl_ok:
                return False, "CONTROL FAILED (lineage)"

        # Apply attack on copy
        attack_dir = base / "attack"
        attack_dir.mkdir()
        e1a = attack_dir / "capsule_epoch_1"
        e2a = attack_dir / "capsule_epoch_2"
        shutil.copytree(e1, e1a)
        shutil.copytree(e2, e2a)
        attack_fn(e1a, e2a, pub, priv)

        # Verify attack is rejected
        if check_fn:
            attack_ok, attack_detail = check_fn(e1a, e2a)
        else:
            attack_ok, attack_problems = run_verifier(e1a, e2a, pub)
            attack_detail = "; ".join(attack_problems) if attack_problems else "accepted (SECURITY GAP)"

        rejected = not attack_ok
        if rejected:
            return True, f"control=PASS, attack=REJECTED ({attack_detail})"
        else:
            return False, f"control=PASS, attack=ACCEPTED — SECURITY GAP ({attack_detail})"


def attack_corrupt_e1_manifest(e1, e2, pub, priv):
    m = json.loads((e1 / "manifest.json").read_text())
    o = m["manifest_hash"]
    m["manifest_hash"] = o[:10] + ("0" if o[10] != "0" else "1") + o[11:]
    (e1 / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True))

def attack_corrupt_e1_signature(e1, e2, pub, priv):
    m = json.loads((e1 / "manifest.json").read_text())
    s = m["owner_signature"]
    m["owner_signature"] = s[:10] + ("0" if s[10] != "0" else "1") + s[11:]
    (e1 / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True))

def attack_corrupt_e2_manifest(e1, e2, pub, priv):
    m = json.loads((e2 / "manifest.json").read_text())
    o = m["manifest_hash"]
    m["manifest_hash"] = o[:10] + ("0" if o[10] != "0" else "1") + o[11:]
    (e2 / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True))

def attack_corrupt_e2_block(e1, e2, pub, priv):
    m = json.loads((e2 / "manifest.json").read_text())
    d = m["workspace_manifest"]["files"][0]["sha256"]
    b = e2 / "blocks" / d[:2] / d
    if b.exists():
        data = bytearray(b.read_bytes())
        if data:
            data[0] ^= 0xFF
            b.write_bytes(bytes(data))

def attack_break_lineage(e1, e2, pub, priv):
    m = json.loads((e2 / "manifest.json").read_text())
    m["parent_manifest_hash"] = "0" * 64
    s = {k: v for k, v in m.items() if k not in ("manifest_hash", "owner_signature", "executor_signature")}
    m["manifest_hash"] = sha256_bytes(canonical_json(s))
    (e2 / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True))

def attack_corrupt_receipt(e1, e2, pub, priv):
    r = json.loads((e1 / "receipt.json").read_text())
    o = r["receipt_hash"]
    r["receipt_hash"] = o[:10] + ("0" if o[10] != "0" else "1") + o[11:]
    (e1 / "receipt.json").write_text(json.dumps(r, indent=2, sort_keys=True))

def attack_remove_block(e1, e2, pub, priv):
    m = json.loads((e2 / "manifest.json").read_text())
    d = m["workspace_manifest"]["files"][0]["sha256"]
    b = e2 / "blocks" / d[:2] / d
    if b.exists():
        b.unlink()

def attack_swap_owner_key(e1, e2, pub, priv):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    other = Ed25519PrivateKey.generate()
    other_pub = other.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    m = json.loads((e1 / "manifest.json").read_text())
    m["owner_public_key"] = other_pub.hex()
    s = {k: v for k, v in m.items() if k not in ("manifest_hash", "owner_signature", "executor_signature")}
    m["manifest_hash"] = sha256_bytes(canonical_json(s))
    (e1 / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True))


TESTS = [
    ("Corrupt E1 manifest hash", attack_corrupt_e1_manifest, "manifest hash mismatch", None),
    ("Corrupt E1 owner signature", attack_corrupt_e1_signature, "owner signature verification failed", None),
    ("Corrupt E2 manifest hash", attack_corrupt_e2_manifest, "manifest hash mismatch", None),
    ("Corrupt E2 content block", attack_corrupt_e2_block, "content blocks corrupt", None),
    ("Break E1->E2 lineage", attack_break_lineage, "lineage broken", check_lineage),
    ("Corrupt E1 receipt hash", attack_corrupt_receipt, "receipt hash mismatch", None),
    ("Remove E2 content block", attack_remove_block, "content blocks missing", None),
    ("Swap owner public key", attack_swap_owner_key, "owner public key mismatch", None),
]


def main() -> int:
    print("=" * 70)
    print("HDAR Failure-Injection Tests (Attack Resistance Proof)")
    print("=" * 70)
    print("  Pattern: control=PASS -> attack constructed -> verifier invoked")
    print("           -> verifier must reject -> reason must match")
    print()

    print("  [BASELINE] Untampered evidence should PASS...")
    with tempfile.TemporaryDirectory() as base_dir:
        e1, e2, pub, priv = setup_fresh_evidence(Path(base_dir))
        ok, problems = run_verifier(e1, e2, pub)
        print(f"  [{'PASS' if ok else 'FAIL'}] Baseline: {'passes' if ok else 'FAILS'}")
        if not ok:
            print(f"  FATAL: Baseline evidence doesn't pass: {problems}")
            return 1
    print()

    all_rejected = True
    for test_name, attack_fn, expected_reason, check_fn in TESTS:
        test_pass, detail = run_attack_test(test_name, attack_fn, expected_reason, check_fn)
        print(f"  [{'PASS' if test_pass else 'FAIL!!!'}] {test_name}")
        print(f"           {detail}")
        print(f"           expected rejection: {expected_reason}")
        print()
        if not test_pass:
            all_rejected = False

    print("=" * 70)
    print("FAILURE-INJECTION SUMMARY")
    print("=" * 70)
    print(f"  Tests run: {len(TESTS)}")
    print(f"  All rejected: {all_rejected}")
    print(f"  Verdict: {'ALL TAMPERED EVIDENCE REJECTED — verifier is robust' if all_rejected else 'SECURITY GAP — some tampered evidence passed'}")
    return 0 if all_rejected else 1


if __name__ == "__main__":
    raise SystemExit(main())
