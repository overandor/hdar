# HDAR — operating modes

How to run HDAR in every mode, honest about what each actually does today.
Part of the [syndication standard](https://github.com/overandor/jorki/blob/main/syndication/STANDARD.md).

| Mode | Command | Requires | Status |
|---|---|---|---|
| `test` | `hdar test` or `pytest` | deps | ✅ real — 44/44 tests pass (unit + failure-injection) |
| `local` | `python -m hdar.prove --local-only --out /tmp/hdar_proof` | deps | ⚠️ currently exits 0 **without emitting artifacts** — use `test` mode as the real local check until this is fixed |
| `prod` | `E2B_API_KEY="e2b_..." python -m hdar.prove --out /tmp/hdar_proof` | `E2B_API_KEY`, network | real cross-platform proof via an E2B Firecracker sandbox |

## CLI sub-modes

```bash
hdar seal --input FILE --output capsule.json --epoch 0   # seal a file into a signed capsule
hdar verify --capsule capsule.json                       # verify a capsule
hdar merkle f1 f2 f3 --prove 0                            # build a Merkle tree + inclusion proof
hdar cross-verify --chain-a a.json --chain-b b.json      # compare two attestation chains
hdar prove --local-only                                  # one-command proof (see local mode caveat)
```

## Honest notes

- **`local` mode gap:** `--local-only` returns exit 0 but produced no output
  directory in testing. Treat `hdar test` / `pytest` as the trustworthy local
  signal until the local proof path emits its artifacts.
- **`cross-verify` semantics:** `Verifier.verify_chains` compares each chain's
  **self-reported** `platform_string`. Running both chains in one process (as the
  README quick-start does) proves determinism of a loop, **not** cross-platform
  execution. Genuine cross-platform evidence comes from `prove.py` across real
  hosts and the published `hdar-cross-platform-proof` repo (Rust verifier + E2B).
