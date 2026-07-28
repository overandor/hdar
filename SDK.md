# HDAR SDK

The importable surface for the Hardware-Detached Agent Runtime.
Part of the [syndication standard](https://github.com/overandor/jorki/blob/main/syndication/STANDARD.md).

## Install

```bash
pip install -e .
```

## Minimal example (runs offline)

```python
from hdar import KeyPair, CapsuleSealer

kp = KeyPair.generate()
sealer = CapsuleSealer(kp)
capsule = sealer.seal(b"computation output", epoch=0, metadata={"task": "demo"})

assert capsule.verify_signature()      # Ed25519 owner signature
assert capsule.verify_content_hash()   # content address matches
print(capsule.content_hash)
```

## Public API

| Symbol | Purpose |
|---|---|
| `KeyPair` | Ed25519 key generation & signing |
| `CapsuleSealer` | Seal payloads into content-addressed, signed capsules |
| `Capsule` | A signed computation unit (`verify_signature`, `verify_content_hash`) |
| `MerkleTree` / `MerkleProof` | SHA-256 Merkle tree + inclusion proofs |
| `Attestation` / `AttestationChain` | Tamper-evident epoch chain of capsules |
| `Verifier` / `VerificationReport` | Compare two attestation chains; signed report |

## Stability

- **Stable (44/44 tests):** `KeyPair`, `CapsuleSealer`, `Capsule`, `MerkleTree`,
  `AttestationChain` sealing and integrity.
- **Use with care:** `Verifier.verify_chains` establishes equivalence only when
  the two chains are produced on **genuinely different hosts**. It reads
  self-reported platform strings, so two in-process chains prove determinism,
  not cross-platform execution. See [`MODES.md`](MODES.md) and
  [`hdar-cross-platform-proof`](https://github.com/overandor/hdar-cross-platform-proof).
