"""Unified HDAR test suite — covers SDK, portable protocol, and MorphOS integration."""

import json
import pytest
from pathlib import Path

from hdar import KeyPair, Capsule, CapsuleSealer, MerkleTree, AttestationChain, Verifier
from hdar.portable import (
    seal_workspace, verify_capsule, hash_workspace, restore_workspace,
    create_transport_capsule, extract_transport_capsule, sha256_bytes,
)


class TestKeys:
    def test_generate_and_sign(self):
        kp = KeyPair.generate()
        sig = kp.sign(b"hello")
        assert kp.verify(sig, b"hello")
        assert not kp.verify(sig, b"wrong")

    def test_public_key_32_bytes(self):
        kp = KeyPair.generate()
        assert len(kp.public_bytes()) == 32

    def test_pem_roundtrip(self):
        kp = KeyPair.generate()
        pem = kp.private_bytes_pem()
        kp2 = KeyPair.from_private_pem(pem)
        assert kp.public_bytes() == kp2.public_bytes()


class TestCapsule:
    def test_seal_and_verify(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        cap = sealer.seal(b"payload", epoch=0, metadata={"task": "test"})
        assert cap.verify_signature()
        assert cap.verify_content_hash()
        assert sealer.verify(cap)

    def test_tamper_detection(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        cap = sealer.seal(b"original", epoch=0)
        tampered = Capsule(
            payload=b"tampered", content_hash=cap.content_hash,
            signature=cap.signature, public_key=cap.public_key,
            platform=cap.platform, epoch=cap.epoch, timestamp=cap.timestamp,
            metadata=cap.metadata,
        )
        assert not tampered.verify_content_hash()

    def test_json_roundtrip(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        cap = sealer.seal(b"round trip", epoch=42, metadata={"k": "v"})
        restored = Capsule.from_json(cap.to_json())
        assert restored.content_hash == cap.content_hash
        assert restored.verify_signature()
        assert restored.payload == cap.payload


class TestMerkle:
    def test_basic_tree(self):
        tree = MerkleTree([b"f1", b"f2", b"f3", b"f4"])
        assert tree.leaf_count == 4
        assert len(tree.root_hash) == 64

    def test_inclusion_proof(self):
        tree = MerkleTree([b"f1", b"f2", b"f3"])
        proof = tree.proof(1)
        assert proof.verify(b"f2")
        assert not proof.verify(b"wrong")

    def test_odd_leaves(self):
        tree = MerkleTree([b"a", b"b", b"c"])
        assert len(tree.root_hash) == 64
        assert tree.proof(0).verify(b"a")


class TestAttestationChain:
    def test_chain_integrity(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain = AttestationChain()
        for i in range(3):
            chain.add(sealer.seal(f"epoch {i}".encode(), epoch=i))
        assert chain.length == 3
        assert chain.verify_chain()

    def test_tamper_detected(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain = AttestationChain()
        chain.add(sealer.seal(b"e0", epoch=0))
        chain.add(sealer.seal(b"e1", epoch=1))
        chain._attestations[0].content_hash = "tampered"
        assert not chain.verify_chain()


class TestVerifier:
    def test_cross_platform_match(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain_a = AttestationChain()
        chain_b = AttestationChain()
        for i in range(5):
            payload = f"epoch {i}".encode()
            chain_a.add(sealer.seal(payload, epoch=i))
            chain_b.add(sealer.seal(payload, epoch=i))
        v = Verifier()
        report = v.verify_chains(chain_a, chain_b)
        assert report.verified
        assert report.matching_epochs == 5

    def test_cross_platform_mismatch(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain_a = AttestationChain()
        chain_b = AttestationChain()
        for i in range(3):
            chain_a.add(sealer.seal(f"same {i}".encode(), epoch=i))
            chain_b.add(sealer.seal(f"different {i}".encode(), epoch=i))
        v = Verifier()
        report = v.verify_chains(chain_a, chain_b)
        assert not report.verified
        assert len(report.mismatched_epochs) == 3


class TestPortable:
    def test_workspace_hash(self, tmp_path):
        (tmp_path / "a.py").write_text("print('a')")
        (tmp_path / "b.py").write_text("print('b')")
        manifest = hash_workspace(tmp_path)
        assert len(manifest["root_hash"]) == 64
        assert len(manifest["files"]) == 2

    def test_seal_and_verify_workspace(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.py").write_text("print('hello')\n")
        cap_dir = tmp_path / "capsule"

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

        manifest = seal_workspace(
            workspace=ws, capsule_dir=cap_dir,
            epoch=1, parent_manifest_hash=None,
            source_host_label="test", objective="test", continuation_point="test",
            owner_private_key=priv_bytes, owner_public_key=pub_bytes,
        )
        assert "manifest_hash" in manifest

        result = verify_capsule(cap_dir, pub_bytes)
        assert result["ok"], result["problems"]

    def test_restore_workspace(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "data.txt").write_text("test data")
        cap_dir = tmp_path / "capsule"
        target = tmp_path / "restored"

        seal_workspace(
            workspace=ws, capsule_dir=cap_dir,
            epoch=1, parent_manifest_hash=None,
            source_host_label="test", objective="test", continuation_point="test",
        )
        info = restore_workspace(cap_dir, target)
        assert info["restored_files"] == 1
        assert (target / "data.txt").read_text() == "test data"

    def test_transport_capsule(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "f.txt").write_text("x")
        cap_dir = tmp_path / "capsule"
        tar_path = tmp_path / "transport.tar.gz"

        seal_workspace(
            workspace=ws, capsule_dir=cap_dir,
            epoch=1, parent_manifest_hash=None,
            source_host_label="test", objective="test", continuation_point="test",
        )
        create_transport_capsule(cap_dir, tar_path)
        assert tar_path.exists()

        dest = tmp_path / "extracted"
        extracted = extract_transport_capsule(tar_path, dest)
        assert (extracted / "manifest.json").exists()


class TestMorphOSNode:
    def test_node_creation(self):
        from hdar.morphos import MorphOSNode
        node = MorphOSNode("test-01", node_kind="test")
        assert node.node_id == "test-01"
        assert len(node.public_key_hex) == 64
        assert node.chain_length == 0

    def test_seal_epoch(self):
        from hdar.morphos import MorphOSNode
        node = MorphOSNode("test-01")
        cap = node.seal_epoch(b"test payload", objective="test")
        assert cap.verify_signature()
        assert cap.verify_content_hash()
        assert node.chain_length == 1
        assert node.chain.verify_chain()

    def test_status(self):
        from hdar.morphos import MorphOSNode
        node = MorphOSNode("test-01", node_kind="colab")
        status = node.status()
        assert status["node_id"] == "test-01"
        assert status["hdar_chain_valid"] is True

    def test_export_import_chain(self):
        from hdar.morphos import MorphOSNode
        node1 = MorphOSNode("node-1")
        node1.seal_epoch(b"e0", objective="test")
        node1.seal_epoch(b"e1", objective="test")

        chain_json = node1.export_chain()
        node2 = MorphOSNode("node-2")
        node2.import_chain(chain_json)
        assert node2.chain_length == 2
        assert node2.chain.verify_chain()
