# HDAR Roadmap

## Phase 1: Hardware-Backed Key Attestation & Enclave Signing
- **Secure Enclave Integration (macOS)**: Sign HDAR capsules with hardware-backed keys via Apple SEP
- **Cloud KMS Integration**: AWS KMS and GCP Cloud KMS drivers — executor keys never in plaintext

## Phase 2: Decentralized Registry & Sparse Merkle Indexing
- **Global Capsule Registry**: DHT or lightweight ledger for manifest hash publishing
- **Sparse Merkle Trees**: O(log N) membership proofs for large workspaces (>100GB)

## Phase 3: Platform Sandbox Integrations & Attestation Drivers
- **Sandboxed Runtimes**: E2B, Docker, Kubernetes, GitHub Actions drivers
- **Confidential Computing**: AWS Nitro Enclaves, GCP Confidential VMs (SEV-SNP, SGX)

## Phase 4: Multi-Agent Consensus & Self-Healing
- **Consensus Reconciler**: Three-way merge over Merkle tree diffs for parallel agents
- **Autonomous Rollbacks**: Auto-revert on verifier security predicate failures

## Metric Targets

| Metric | Phase 1-2 | Phase 3-4 |
|---|---|---|
| Max workspace size | 10 GB | 1 TB |
| Verification latency | <500ms | <50ms |
| Attestation coverage | OS & Python | CPU (SGX) & KMS |
