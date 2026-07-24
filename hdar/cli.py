"""CLI for HDAR SDK — capsule sealing, verification, cross-platform proof, and MorphOS integration."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .attestation import AttestationChain
from .capsule import Capsule, CapsuleSealer
from .keys import KeyPair
from .merkle import MerkleTree
from .verifier import Verifier


def cmd_seal(args: argparse.Namespace) -> int:
    """Seal a payload into a capsule."""
    with open(args.input, "rb") as f:
        payload = f.read()

    if args.keyfile:
        with open(args.keyfile, "rb") as f:
            kp = KeyPair.from_private_pem(f.read())
    else:
        kp = KeyPair.generate()

    sealer = CapsuleSealer(kp)
    capsule = sealer.seal(payload, epoch=args.epoch, metadata={"filename": args.input})

    output = capsule.to_json()
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Sealed capsule -> {args.output}")
    else:
        print(output)

    print(f"Content hash: {capsule.content_hash}", file=sys.stderr)
    print(f"Short hash:   {capsule.short_hash}", file=sys.stderr)
    print(f"Epoch:        {capsule.epoch}", file=sys.stderr)
    print(f"Platform:     {capsule.platform.get('platform_string', 'unknown')}", file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a capsule's signature and content hash."""
    with open(args.capsule) as f:
        capsule = Capsule.from_json(f.read())

    sig_ok = capsule.verify_signature()
    hash_ok = capsule.verify_content_hash()

    print(f"Capsule Verification")
    print(f"  Content hash: {capsule.content_hash}")
    print(f"  Epoch:        {capsule.epoch}")
    print(f"  Platform:     {capsule.platform.get('platform_string', 'unknown')}")
    print(f"  Signature:    {'VALID' if sig_ok else 'INVALID'}")
    print(f"  Content hash: {'VALID' if hash_ok else 'INVALID'}")

    if sig_ok and hash_ok:
        print("  Result:       VERIFIED")
        return 0
    else:
        print("  Result:       FAILED")
        return 1


def cmd_merkle(args: argparse.Namespace) -> int:
    """Build a Merkle tree from files and optionally prove inclusion."""
    leaves: List[bytes] = []
    for path in args.files:
        with open(path, "rb") as f:
            leaves.append(f.read())

    tree = MerkleTree(leaves)
    print(f"Merkle Tree")
    print(f"  Leaves:    {tree.leaf_count}")
    print(f"  Root hash: {tree.root_hash}")

    for i, path in enumerate(args.files):
        print(f"  Leaf {i}: {path} -> {tree.leaf_hashes[i][:16]}...")

    if args.prove is not None:
        idx = args.prove
        if idx < 0 or idx >= tree.leaf_count:
            print(f"  Error: index {idx} out of range", file=sys.stderr)
            return 1
        proof = tree.proof(idx)
        valid = proof.verify(leaves[idx])
        print(f"\n  Proof for leaf {idx}:")
        print(f"    Path length: {len(proof.path)}")
        print(f"    Valid: {valid}")

    return 0


def cmd_cross_verify(args: argparse.Namespace) -> int:
    """Cross-verify two capsule chains from different platforms."""
    with open(args.chain_a) as f:
        chain_a = AttestationChain.from_dict(json.load(f))
    with open(args.chain_b) as f:
        chain_b = AttestationChain.from_dict(json.load(f))

    verifier = Verifier()
    report = verifier.verify_chains(chain_a, chain_b)

    print(f"Cross-Platform Verification Report")
    print(f"  Verified:       {report.verified}")
    print(f"  Epochs:         {report.epoch_count}")
    print(f"  Matching:       {report.matching_epochs}")
    print(f"  Mismatched:     {report.mismatched_epochs}")
    print(f"  Platform A:     {report.platform_a}")
    print(f"  Platform B:     {report.platform_b}")
    print(f"  Root hash A:    {report.root_hash_a[:16]}...")
    print(f"  Root hash B:    {report.root_hash_b[:16]}...")
    print(f"  Report hash:    {report.report_hash[:16]}...")

    if args.output:
        with open(args.output, "w") as f:
            f.write(report.to_json())
        print(f"\n  Report saved -> {args.output}")

    return 0 if report.verified else 1


def cmd_test(args: argparse.Namespace) -> int:
    """Run self-tests."""
    print("HDAR SDK -- Self-Tests")
    print("=" * 50)
    passed = 0
    failed = 0

    def check(name: str, cond: bool) -> None:
        nonlocal passed, failed
        if cond:
            print(f"  PASS  {name}")
            passed += 1
        else:
            print(f"  FAIL  {name}")
            failed += 1

    # 1. Key generation and signing.
    print("\n  Test 1: Ed25519 Key Pair")
    kp = KeyPair.generate()
    sig = kp.sign(b"hello world")
    check("Sign and verify", kp.verify(sig, b"hello world"))
    check("Reject wrong data", not kp.verify(sig, b"wrong data"))
    check("Public key is 32 bytes", len(kp.public_bytes()) == 32)

    # 2. Capsule sealing.
    print("\n  Test 2: Capsule Sealing")
    sealer = CapsuleSealer(kp)
    cap = sealer.seal(b"computation output", epoch=0, metadata={"task": "test"})
    check("Signature valid", cap.verify_signature())
    check("Content hash valid", cap.verify_content_hash())
    check("Sealer verify", sealer.verify(cap))
    print(f"    -> Content hash: {cap.short_hash}...")

    # 3. Tamper detection.
    print("\n  Test 3: Tamper Detection")
    tampered = Capsule(
        payload=b"tampered output",
        content_hash=cap.content_hash,
        signature=cap.signature,
        public_key=cap.public_key,
        platform=cap.platform,
        epoch=cap.epoch,
        timestamp=cap.timestamp,
        metadata=cap.metadata,
    )
    check("Tampered payload detected", not tampered.verify_content_hash())

    # 4. Merkle tree.
    print("\n  Test 4: Merkle Tree")
    leaves = [b"file1", b"file2", b"file3", b"file4"]
    tree = MerkleTree(leaves)
    check("Tree has 4 leaves", tree.leaf_count == 4)
    check("Root hash non-empty", len(tree.root_hash) == 64)

    proof0 = tree.proof(0)
    check("Proof for leaf 0 valid", proof0.verify(b"file1"))
    proof2 = tree.proof(2)
    check("Proof for leaf 2 valid", proof2.verify(b"file3"))
    check("Proof rejects wrong data", not proof0.verify(b"wrong"))
    print(f"    -> Root: {tree.root_hash[:16]}...")

    # 5. Odd number of leaves.
    print("\n  Test 5: Odd Leaf Count")
    tree_odd = MerkleTree([b"a", b"b", b"c"])
    check("Odd tree root non-empty", len(tree_odd.root_hash) == 64)
    proof1 = tree_odd.proof(1)
    check("Proof for odd tree leaf 1", proof1.verify(b"b"))

    # 6. Attestation chain.
    print("\n  Test 6: Attestation Chain")
    chain = AttestationChain()
    cap0 = sealer.seal(b"epoch 0 output", epoch=0)
    cap1 = sealer.seal(b"epoch 1 output", epoch=1)
    cap2 = sealer.seal(b"epoch 2 output", epoch=2)
    chain.add(cap0)
    chain.add(cap1)
    chain.add(cap2)
    check("Chain has 3 attestations", chain.length == 3)
    check("Chain verification passes", chain.verify_chain())

    # 7. Chain tamper detection.
    print("\n  Test 7: Chain Tamper Detection")
    from .attestation import Attestation
    chain._attestations[1].content_hash = "tampered"
    check("Tampered chain detected", not chain.verify_chain())

    # 8. Cross-platform verification.
    print("\n  Test 8: Cross-Platform Verification")
    chain_a = AttestationChain()
    chain_b = AttestationChain()
    for i in range(5):
        payload = f"computation epoch {i}".encode()
        cap_a = sealer.seal(payload, epoch=i)
        cap_b = sealer.seal(payload, epoch=i)
        chain_a.add(cap_a)
        chain_b.add(cap_b)

    verifier = Verifier()
    report = verifier.verify_chains(chain_a, chain_b)
    check("Cross-platform verified", report.verified)
    check("All 5 epochs match", report.matching_epochs == 5)
    check("No mismatches", len(report.mismatched_epochs) == 0)
    check("Report hash non-empty", len(report.report_hash) == 64)
    print(f"    -> Report hash: {report.report_hash[:16]}...")

    # 9. Cross-platform mismatch detection.
    print("\n  Test 9: Cross-Platform Mismatch")
    chain_c = AttestationChain()
    for i in range(5):
        cap_c = sealer.seal(f"different epoch {i}".encode(), epoch=i)
        chain_c.add(cap_c)
    report_mismatch = verifier.verify_chains(chain_a, chain_c)
    check("Mismatch detected", not report_mismatch.verified)
    check("5 mismatches found", len(report_mismatch.mismatched_epochs) == 5)

    # 10. Capsule serialization round-trip.
    print("\n  Test 10: Serialization Round-Trip")
    cap_orig = sealer.seal(b"round trip test", epoch=42, metadata={"key": "value"})
    json_str = cap_orig.to_json()
    cap_restored = Capsule.from_json(json_str)
    check("Round-trip content hash", cap_orig.content_hash == cap_restored.content_hash)
    check("Round-trip signature", cap_restored.verify_signature())
    check("Round-trip payload", cap_orig.payload == cap_restored.payload)

    print(f"\n{'=' * 50}")
    print(f"  Results: {passed} passed, {failed} failed")
    return 1 if failed > 0 else 0


def cmd_prove(args: argparse.Namespace) -> int:
    """Run one-command cross-platform proof."""
    from . import prove as _prove
    return _prove.run_proof(args)


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="hdar",
        description="HDAR -- Hardware-Detached Agent Runtime",
    )
    sub = parser.add_subparsers(dest="command")

    p_seal = sub.add_parser("seal", help="Seal a payload into a capsule")
    p_seal.add_argument("--input", required=True, help="Input file to seal")
    p_seal.add_argument("--output", help="Output JSON file for capsule")
    p_seal.add_argument("--keyfile", help="PEM private key file (generates new if omitted)")
    p_seal.add_argument("--epoch", type=int, default=0, help="Epoch number")

    p_verify = sub.add_parser("verify", help="Verify a capsule")
    p_verify.add_argument("--capsule", required=True, help="Capsule JSON file")

    p_merkle = sub.add_parser("merkle", help="Build Merkle tree from files")
    p_merkle.add_argument("files", nargs="+", help="Files to include in tree")
    p_merkle.add_argument("--prove", type=int, help="Generate and verify proof for leaf index")

    p_cross = sub.add_parser("cross-verify", help="Cross-verify two capsule chains")
    p_cross.add_argument("--chain-a", required=True, help="Chain A JSON file")
    p_cross.add_argument("--chain-b", required=True, help="Chain B JSON file")
    p_cross.add_argument("--output", help="Save report to file")

    sub.add_parser("test", help="Run self-tests")

    p_prove = sub.add_parser("prove", help="Run one-command cross-platform proof")
    p_prove.add_argument("--local-only", action="store_true", help="Run local simulation (no E2B)")
    p_prove.add_argument("--out", default="/tmp/hdar_proof", help="Output directory")

    args = parser.parse_args()

    if args.command == "seal":
        return cmd_seal(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "merkle":
        return cmd_merkle(args)
    elif args.command == "cross-verify":
        return cmd_cross_verify(args)
    elif args.command == "test":
        return cmd_test(args)
    elif args.command == "prove":
        return cmd_prove(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
