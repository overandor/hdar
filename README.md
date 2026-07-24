# HDAR — Hardware-Detached Agent Runtime

**Verifiable state continuity & provenance infrastructure for autonomous AI agents.**

HDAR proves that a computation ran identically on two different hardware/platform combinations without trusting either host. This is the unified, seed-ready system that consolidates five prior repositories into one.

## Consolidated Repositories

| Prior Repo | Role | Unified Into |
|---|---|---|
| `hdar-sdk` | Core SDK: capsules, keys, Merkle, attestation, verifier | `hdar/` package |
| `hdar-hitelesites` | Portable protocol: workspace sealing, transport, restore | `hdar/portable.py` |
| `hdar-host-b-proof` | Host B proof runner (E2B sandbox) | `hdar/prove.py` |
| `hdar-cross-platform-proof` | Cross-platform proof + Rust verifier | `hdar/prove.py` + CLI |
| `jentic-egy` | Production diagnostics + Ed25519 attestation | `hdar/morphos.py` |

## Architecture

```
hdar/
├── hdar/
│   ├── __init__.py      # Public API
│   ├── keys.py          # Ed25519 key pair generation & signing
│   ├── capsule.py       # Content-addressed, signed computation capsules
│   ├── merkle.py        # SHA-256 Merkle trees with inclusion proofs
│   ├── attestation.py   # Cross-platform attestation chains
│   ├── verifier.py      # Deterministic verification engine
│   ├── portable.py      # Workspace-level sealing, transport, restore
│   ├── morphos.py       # MorphOS multi-node orchestrator integration
│   ├── prove.py         # One-command cross-platform proof
│   └── cli.py           # Unified CLI
├── tests/
│   └── test_hdar.py     # Full test suite
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Quick Start

```bash
pip install -e .
```

### Seal a Capsule

```python
from hdar import KeyPair, CapsuleSealer

kp = KeyPair.generate()
sealer = CapsuleSealer(kp)
capsule = sealer.seal(b"computation output", epoch=0, metadata={"task": "demo"})

assert capsule.verify_signature()
assert capsule.verify_content_hash()
print(f"Content hash: {capsule.content_hash}")
```

### Cross-Platform Verification

```python
from hdar import KeyPair, CapsuleSealer, AttestationChain, Verifier

kp = KeyPair.generate()
sealer = CapsuleSealer(kp)

chain_a = AttestationChain()
chain_b = AttestationChain()

for i in range(5):
    payload = f"computation epoch {i}".encode()
    chain_a.add(sealer.seal(payload, epoch=i))
    chain_b.add(sealer.seal(payload, epoch=i))

verifier = Verifier()
report = verifier.verify_chains(chain_a, chain_b)
print(f"Verified: {report.verified}")  # True
```

### One-Command Proof

```bash
# Local proof (no E2B required)
python -m hdar.prove --local-only --out /tmp/hdar_proof

# Full cross-platform proof (requires E2B_API_KEY)
E2B_API_KEY="e2b_..." python -m hdar.prove --out /tmp/hdar_proof
```

### CLI

```bash
# Seal a file
hdar seal --input myfile.txt --output capsule.json --epoch 0

# Verify a capsule
hdar verify --capsule capsule.json

# Build Merkle tree
hdar merkle file1.txt file2.txt --prove 0

# Cross-verify two chains
hdar cross-verify --chain-a chain_a.json --chain-b chain_b.json

# Run self-tests
hdar test

# Run cross-platform proof
hdar prove --local-only
```

### MorphOS Integration

```python
from hdar.morphos import MorphOSNode

node = MorphOSNode(
    node_id="colab-01",
    node_kind="colab",
    orchestrator_url="http://localhost:7860",
    api_key="morphos2026",
)

# Register with orchestrator
node.register()

# Execute command with automatic HDAR sealing
result = node.execute("echo hello", workspace="quad-a")
print(f"Capsule: {result['capsule']['short_hash']}")

# Check status
print(node.status())
```

## Core Concepts

- **Capsule**: Content-addressed, Ed25519-signed computation unit with platform metadata
- **Merkle Tree**: SHA-256 binary hash tree for workspace integrity with inclusion proofs
- **Attestation Chain**: Tamper-evident epoch chain linking capsules across platforms
- **Verifier**: Checks that two chains from different platforms produce identical content hashes
- **Portable Protocol**: Workspace-level sealing, transport (tar.gz), and restoration
- **MorphOS Node**: Multi-node orchestrator integration with automatic lineage tracking

## Cryptographic Primitives

- **Signing**: Ed25519 (32-byte public key, 64-byte signature)
- **Hashing**: SHA-256
- **Content addressing**: SHA-256 over canonical JSON + payload bytes
- **Chain integrity**: SHA-256 over (previous_hash + content_hash + epoch)

## License

Apache-2.0
