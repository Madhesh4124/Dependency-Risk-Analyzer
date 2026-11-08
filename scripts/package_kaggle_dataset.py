"""Packages the Tier A and Tier B benchmark datasets into a clean distribution ready for Kaggle upload.

Creates:
1. dist/kaggle_pyriskbench/ (folder with clean files, no pycache, with dataset-metadata.json)
2. dist/pyriskbench_kaggle.zip (ready for 1-click drag-and-drop into Kaggle)
"""

import json
import os
import shutil
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT_DIR / "dist"
KAGGLE_DIR = DIST_DIR / "kaggle_pyriskbench"
ZIP_PATH = DIST_DIR / "pyriskbench_kaggle.zip"


def create_metadata(kaggle_dir: Path):
    metadata = {
        "title": "Python Dependency Upgrade Risk Benchmark (PyRiskBench)",
        "id": "madhesh4124/pyriskbench-dependency-risk",
        "licenses": [{"name": "CC0-1.0"}],
        "keywords": [
            "python",
            "software-engineering",
            "dependencies",
            "supply-chain-security",
            "static-analysis",
            "benchmarks",
            "large-language-models",
            "prompt-injection"
        ]
    }
    with open(kaggle_dir / "dataset-metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


def copy_clean(src: Path, dst: Path):
    """Copies a directory tree omitting __pycache__, .pytest_cache, and .pyc files."""
    def ignore_patterns(path, names):
        ignored = []
        for name in names:
            if name in ("__pycache__", ".pytest_cache", ".git"):
                ignored.append(name)
            elif name.endswith(".pyc") or name.endswith(".pyo"):
                ignored.append(name)
        return ignored

    shutil.copytree(src, dst, ignore=ignore_patterns, dirs_exist_ok=True)


def package():
    print(f"Creating clean Kaggle package at {KAGGLE_DIR}...")
    if KAGGLE_DIR.exists():
        shutil.rmtree(KAGGLE_DIR)
    KAGGLE_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy Tier A
    print("Copying Tier A fixtures...")
    copy_clean(ROOT_DIR / "benchmark" / "tier_a", KAGGLE_DIR / "tier_a")

    # 2. Copy Tier B
    print("Copying Tier B data (candidates.jsonl, tier_b.json, etc.)...")
    (KAGGLE_DIR / "tier_b").mkdir(parents=True, exist_ok=True)
    for f in (ROOT_DIR / "benchmark" / "tier_b").glob("*"):
        if f.is_file():
            shutil.copy2(f, KAGGLE_DIR / "tier_b" / f.name)

    # 3. Copy Frozen V1
    print("Copying Frozen V1 snapshot and SHA-256 manifests...")
    copy_clean(ROOT_DIR / "benchmark" / "frozen_v1", KAGGLE_DIR / "frozen_v1")

    # 4. Copy Label Protocol
    docs_dir = KAGGLE_DIR / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    if (ROOT_DIR / "docs" / "label_protocol.md").exists():
        shutil.copy2(ROOT_DIR / "docs" / "label_protocol.md", docs_dir / "label_protocol.md")

    # 5. Create dataset-metadata.json
    create_metadata(KAGGLE_DIR)

    # 6. Copy Kaggle README description
    desc_src = ROOT_DIR / "docs" / "kaggle_dataset_description.md"
    if desc_src.exists():
        shutil.copy2(desc_src, KAGGLE_DIR / "README.md")

    # 7. Create ZIP archive
    print(f"Creating ZIP archive at {ZIP_PATH}...")
    if ZIP_PATH.exists():
        ZIP_PATH.unlink()
    
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file in KAGGLE_DIR.rglob("*"):
            if file.is_file():
                rel_path = file.relative_to(KAGGLE_DIR)
                zipf.write(file, arcname=str(rel_path))

    size_mb = ZIP_PATH.stat().st_size / (1024 * 1024)
    print(f"Success! Packaged {ZIP_PATH} ({size_mb:.2f} MB)")
    print(f"Directory ready at {KAGGLE_DIR}")


if __name__ == "__main__":
    package()
