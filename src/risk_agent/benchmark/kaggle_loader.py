"""Kaggle Dataset Loader for PyRiskBench (Phase 7).

Enables Google Cloud Run Jobs, Cloud Shell, and local environments to fetch,
verify, and stream the benchmark dataset directly from KaggleHub or local cache.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("risk_agent.benchmark.kaggle_loader")

DEFAULT_KAGGLE_DATASET = "madheshraj/python-dependency-upgrade-risk-benchmark"


def resolve_benchmark_root(dataset_id: Optional[str] = None, force_download: bool = False) -> Path:
    """Resolves the benchmark root directory.
    
    Priority:
    1. PYRISKBENCH_DATASET_DIR environment variable if explicitly set.
    2. Local project repository `benchmark/` folder (if exists and not force_download).
    3. KaggleHub download cache.
    """
    env_dir = os.getenv("PYRISKBENCH_DATASET_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.exists():
            logger.info(f"Using benchmark dataset from environment variable: {p}")
            return p

    repo_benchmark = Path(__file__).resolve().parent.parent.parent.parent / "benchmark"
    if not force_download and repo_benchmark.exists() and (repo_benchmark / "frozen_v1").exists():
        logger.info(f"Using local benchmark directory: {repo_benchmark}")
        return repo_benchmark

    target_id = dataset_id or os.getenv("KAGGLE_DATASET_ID", DEFAULT_KAGGLE_DATASET)
    logger.info(f"Downloading PyRiskBench dataset from KaggleHub ({target_id})...")
    try:
        import kagglehub
        download_path = kagglehub.dataset_download(target_id)
        p = Path(download_path)
        logger.info(f"KaggleHub downloaded dataset to: {p}")
        return p
    except Exception as e:
        logger.warning(f"KaggleHub download failed ({e}); falling back to local benchmark if available.")
        if repo_benchmark.exists():
            return repo_benchmark
        raise RuntimeError(f"Unable to load benchmark dataset from Kaggle ({target_id}) or local disk: {e}") from e


def load_tier_a(root_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Loads Tier A 20 fixtures specifications."""
    root = root_dir or resolve_benchmark_root()
    tier_a_frozen = root / "frozen_v1" / "tier_a_frozen.json"
    if tier_a_frozen.exists():
        with open(tier_a_frozen, "r", encoding="utf-8") as f:
            return json.load(f)

    tier_a_cases = root / "tier_a" / "cases.json"
    if tier_a_cases.exists():
        with open(tier_a_cases, "r", encoding="utf-8") as f:
            return json.load(f)

    raise FileNotFoundError(f"Tier A cases not found in {root}")


def load_tier_b_curated(root_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Loads Tier B 30 validated real PR cases."""
    root = root_dir or resolve_benchmark_root()
    tier_b_frozen = root / "frozen_v1" / "tier_b_frozen.json"
    if tier_b_frozen.exists():
        with open(tier_b_frozen, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("cases", data)

    tier_b_path = root / "tier_b" / "tier_b.json"
    if tier_b_path.exists():
        with open(tier_b_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("cases", data)

    raise FileNotFoundError(f"Tier B curated cases not found in {root}")


def load_all_candidates(root_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Loads all harvested candidates from candidates.jsonl (140+ real PR cases)."""
    root = root_dir or resolve_benchmark_root()
    candidates_file = root / "tier_b" / "candidates.jsonl"
    if not candidates_file.exists():
        raise FileNotFoundError(f"candidates.jsonl not found in {candidates_file}")

    candidates = []
    with open(candidates_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                candidates.append(json.loads(line))
    return candidates


def filter_replayable_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filters candidate PRs that have no confounding variables and are ready for differential replay."""
    filtered = []
    for c in candidates:
        chk = c.get("validation_checklist", {})
        # Criteria: single dependency verified, commit SHAs captured, lockfile confound-free
        if chk.get("single_dependency_verified") and chk.get("commit_shas_captured") and chk.get("lockfile_confound_free"):
            filtered.append(c)
    return filtered
