#!/usr/bin/env python3
"""End-to-end HDAR demo: Host A seals -> Host B restores, executes, seals successor.

This script runs the complete signed capsule flow in one command using
the unified HDAR package:

  1. Host A: create workspace, seal Epoch 1 with Ed25519 owner signature
  2. Host B: restore E1, verify signature, execute pipeline, seal Epoch 2
  3. Verifier C: independently verify all artifacts

Usage:
    python -m hdar.demo --out /tmp/hdar_demo
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from hdar.portable import (
    seal_workspace,
    verify_capsule,
    restore_workspace,
    create_transport_capsule,
    extract_transport_capsule,
)
from hdar.prove import phase1_build, phase2_local, phase3_verify


def main() -> int:
    ap = argparse.ArgumentParser(description="HDAR end-to-end signed capsule demo")
    ap.add_argument("--out", default="/tmp/hdar_demo", help="Output directory")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    print("=" * 60)
    print("  HDAR END-TO-END DEMO")
    print("  Using unified hdar package")
    print("=" * 60)

    # Phase 1: Host A builds and seals
    info = phase1_build(out)

    # Phase 2: Host B restores, executes, seals E2
    exec_info = phase2_local(info, out)

    # Phase 3: Verifier independently verifies
    verdict = phase3_verify(info, exec_info, out)

    print("\n" + "=" * 60)
    print("  DEMO COMPLETE")
    print(f"  Verifier: {verdict.get('passed', 0)}/{verdict.get('total_checks', 0)}")
    print(f"  All passed: {verdict.get('all_checks_passed', False)}")
    print("=" * 60)

    return 0 if verdict.get("all_checks_passed", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
