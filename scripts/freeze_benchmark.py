"""Freeze Benchmark Datasets and Generate Immutable SHA-256 Manifest.

Phase 4 Requirement:
- FREEZE the benchmark — no further changes to held-out labels
- Create immutable benchmark snapshot in benchmark/frozen_v1/
- Compute SHA-256 checksums of all benchmark datasets and fixture files
- Save manifest_sha256.json for verification against GCS Benchmark Vault
"""

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = ROOT_DIR / "benchmark"
TIER_A_DIR = BENCHMARK_DIR / "tier_a"
TIER_B_DIR = BENCHMARK_DIR / "tier_b"
FROZEN_DIR = BENCHMARK_DIR / "frozen_v1"


def compute_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    FROZEN_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load Tier A and Tier B
    tier_a_cases_file = TIER_A_DIR / "cases.json"
    tier_b_file = TIER_B_DIR / "tier_b.json"

    with open(tier_a_cases_file, "r", encoding="utf-8") as f:
        tier_a_cases = json.load(f)

    with open(tier_b_file, "r", encoding="utf-8") as f:
        tier_b_data = json.load(f)

    print(f"Freezing benchmark: {len(tier_a_cases)} Tier A cases, {len(tier_b_data['cases'])} Tier B cases.")

    # 2. Write frozen copies
    frozen_tier_a_path = FROZEN_DIR / "tier_a_frozen.json"
    frozen_tier_b_path = FROZEN_DIR / "tier_b_frozen.json"

    with open(frozen_tier_a_path, "w", encoding="utf-8") as f:
        json.dump(tier_a_cases, f, indent=2)

    with open(frozen_tier_b_path, "w", encoding="utf-8") as f:
        json.dump(tier_b_data, f, indent=2)

    # Copy Tier B hand audit if exists
    hand_audit_src = TIER_B_DIR / "hand_audit.json"
    if hand_audit_src.exists():
        shutil.copy2(hand_audit_src, FROZEN_DIR / "hand_audit_frozen.json")

    # 3. Compute checksums of all files in frozen_v1 and tier_a fixtures
    manifest_files = {}

    for file_path in sorted(FROZEN_DIR.glob("*.json")):
        if file_path.name == "manifest_sha256.json":
            continue
        rel_path = file_path.relative_to(ROOT_DIR).as_posix()
        manifest_files[rel_path] = {
            "sha256": compute_sha256(file_path),
            "size_bytes": file_path.stat().st_size,
        }

    # Also include all case.json files in Tier A fixtures
    for case_spec in sorted(TIER_A_DIR.glob("case_*/case.json")):
        rel_path = case_spec.relative_to(ROOT_DIR).as_posix()
        manifest_files[rel_path] = {
            "sha256": compute_sha256(case_spec),
            "size_bytes": case_spec.stat().st_size,
        }

    freeze_timestamp = datetime.now(timezone.utc).isoformat()

    manifest = {
        "metadata": {
            "benchmark_version": "v1.0-frozen",
            "freeze_timestamp": freeze_timestamp,
            "decision_checkpoint": "D-06",
            "frozen_by": "Agent & User",
            "tier_a_cases_count": len(tier_a_cases),
            "tier_b_cases_count": len(tier_b_data["cases"]),
            "total_benchmark_cases": len(tier_a_cases) + len(tier_b_data["cases"]),
            "gcs_vault_target": "gs://dependency_impact_analyzer/benchmarks/frozen_v1/",
            "integrity_algorithm": "SHA-256",
        },
        "files": manifest_files,
    }

    manifest_path = FROZEN_DIR / "manifest_sha256.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 60)
    print("BENCHMARK FREEZE COMPLETE (CHECKPOINT D-06 EXECUTED)")
    print(f"Frozen directory: {FROZEN_DIR.relative_to(ROOT_DIR)}")
    print(f"Total files hashed: {len(manifest_files)}")
    print(f"Manifest written to: {manifest_path.relative_to(ROOT_DIR)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
