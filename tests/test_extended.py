"""Additional tests from the original hdar-sdk test suite — ensures backward compatibility."""

import pytest
from hdar import KeyPair, Capsule, CapsuleSealer, MerkleTree, AttestationChain, Verifier


class TestKeysExtended:
    def test_sign_empty_message(self):
        kp = KeyPair.generate()
        sig = kp.sign(b"")
        assert kp.verify(sig, b"")
        assert len(sig) == 64

    def test_sign_large_message(self):
        kp = KeyPair.generate()
        msg = b"x" * 100000
        sig = kp.sign(msg)
        assert kp.verify(sig, msg)

    def test_different_keys_different_signatures(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        msg = b"same message"
        sig1 = kp1.sign(msg)
        sig2 = kp2.sign(msg)
        assert sig1 != sig2
        assert kp1.verify(sig1, msg)
        assert kp2.verify(sig2, msg)
        assert not kp1.verify(sig2, msg)

    def test_public_bytes_deterministic(self):
        kp = KeyPair.generate()
        assert kp.public_bytes() == kp.public_bytes()


class TestCapsuleExtended:
    def test_capsule_short_hash(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        cap = sealer.seal(b"test", epoch=0)
        assert len(cap.short_hash) == 16
        assert cap.content_hash.startswith(cap.short_hash)

    def test_capsule_epoch_preserved(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        cap = sealer.seal(b"data", epoch=42)
        assert cap.epoch == 42

    def test_capsule_metadata_preserved(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        meta = {"task": "compute", "priority": "high", "nested": {"key": "value"}}
        cap = sealer.seal(b"data", epoch=0, metadata=meta)
        assert cap.metadata["task"] == "compute"
        assert cap.metadata["nested"]["key"] == "value"

    def test_capsule_platform_info(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        cap = sealer.seal(b"data", epoch=0)
        assert "platform_string" in cap.platform
        assert "python" in cap.platform

    def test_wrong_key_rejected(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        sealer = CapsuleSealer(kp1)
        cap = sealer.seal(b"data", epoch=0)
        # Verify with wrong public key
        cap_wrong_key = Capsule(
            payload=cap.payload, content_hash=cap.content_hash,
            signature=cap.signature, public_key=kp2.public_bytes(),
            platform=cap.platform, epoch=cap.epoch, timestamp=cap.timestamp,
            metadata=cap.metadata,
        )
        assert not cap_wrong_key.verify_signature()


class TestMerkleExtended:
    def test_single_leaf(self):
        tree = MerkleTree([b"only"])
        assert tree.leaf_count == 1
        assert len(tree.root_hash) == 64
        proof = tree.proof(0)
        assert proof.verify(b"only")

    def test_empty_tree(self):
        tree = MerkleTree([])
        assert tree.leaf_count == 0
        assert tree.root_hash == ""  # empty tree has empty root

    def test_two_leaves(self):
        tree = MerkleTree([b"a", b"b"])
        assert tree.leaf_count == 2
        assert tree.proof(0).verify(b"a")
        assert tree.proof(1).verify(b"b")

    def test_many_leaves(self):
        leaves = [f"file_{i}".encode() for i in range(100)]
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 100
        for i in range(100):
            assert tree.proof(i).verify(leaves[i])

    def test_proof_out_of_range(self):
        tree = MerkleTree([b"a", b"b"])
        with pytest.raises(IndexError):
            tree.proof(2)


def sha256_empty() -> str:
    import hashlib
    return hashlib.sha256(b"").hexdigest()


class TestAttestationChainExtended:
    def test_empty_chain(self):
        chain = AttestationChain()
        assert chain.length == 0
        assert chain.verify_chain()

    def test_single_attestation(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain = AttestationChain()
        chain.add(sealer.seal(b"e0", epoch=0))
        assert chain.length == 1
        assert chain.verify_chain()

    def test_chain_root_hash(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain = AttestationChain()
        for i in range(3):
            chain.add(sealer.seal(f"e{i}".encode(), epoch=i))
        assert len(chain.root_content_hash) == 64

    def test_chain_to_dict_roundtrip(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain = AttestationChain()
        chain.add(sealer.seal(b"e0", epoch=0))
        chain.add(sealer.seal(b"e1", epoch=1))
        d = chain.to_dict()
        restored = AttestationChain.from_dict(d)
        assert restored.length == 2
        assert restored.verify_chain()
        assert restored.root_content_hash == chain.root_content_hash


class TestVerifierExtended:
    def test_empty_chains(self):
        v = Verifier()
        chain_a = AttestationChain()
        chain_b = AttestationChain()
        report = v.verify_chains(chain_a, chain_b)
        assert not report.verified
        assert report.epoch_count == 0

    def test_different_length_chains(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain_a = AttestationChain()
        chain_b = AttestationChain()
        for i in range(5):
            chain_a.add(sealer.seal(f"e{i}".encode(), epoch=i))
        for i in range(3):
            chain_b.add(sealer.seal(f"e{i}".encode(), epoch=i))
        v = Verifier()
        report = v.verify_chains(chain_a, chain_b)
        assert not report.verified
        assert report.epoch_count == 5

    def test_verify_capsule_integrity(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        cap = sealer.seal(b"data", epoch=0)
        v = Verifier()
        assert v.verify_capsule_integrity(cap)

    def test_verify_merkle_inclusion(self):
        tree = MerkleTree([b"a", b"b", b"c"])
        v = Verifier()
        assert v.verify_merkle_inclusion(tree, 0, b"a")
        assert v.verify_merkle_inclusion(tree, 2, b"c")
        assert not v.verify_merkle_inclusion(tree, 0, b"wrong")
        assert not v.verify_merkle_inclusion(tree, 10, b"x")

    def test_report_serialization(self):
        kp = KeyPair.generate()
        sealer = CapsuleSealer(kp)
        chain_a = AttestationChain()
        chain_b = AttestationChain()
        for i in range(3):
            chain_a.add(sealer.seal(f"e{i}".encode(), epoch=i))
            chain_b.add(sealer.seal(f"e{i}".encode(), epoch=i))
        v = Verifier()
        report = v.verify_chains(chain_a, chain_b)
        d = report.to_dict()
        assert "verified" in d
        assert "report_hash" in d
        restored = type(report).from_dict(d)
        assert restored.verified == report.verified
        assert restored.report_hash == report.report_hash
