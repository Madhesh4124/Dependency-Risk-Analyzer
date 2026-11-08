# PyRiskBench: Python Dependency Upgrade Risk Benchmark

**PyRiskBench** is an empirical ground-truth benchmark for evaluating static analysis tools and LLM agents on detecting **breaking changes, silent semantic drift, and prompt injection attacks** in Python dependency updates.

---

## 📁 Dataset Structure

- **`tier_a/` (20 Synthetic Ground-Truth Fixtures):** Minimal Python repositories with reproducible breakages (API removals, parameter changes, return type alterations, deprecations, benign patches, and prompt-injection variants).
- **`tier_b/` (Empirical Real-World PRs):**
  - `candidates.jsonl`: 140 harvested GitHub pull requests with commit SHAs, manifest diffs, and CI outcomes across `fastapi`, `sqlalchemy`, `pydantic`, `numpy`, `pandas`, `cryptography`, `httpx`, and `redis`.
  - `tier_b.json`: 30 verified ground-truth cases validated via offline differential replay.
- **`frozen_v1/`:** Cryptographically hashed (SHA-256) immutable snapshot for reproducible research.
- **`docs/label_protocol.md`:** Standardized exclusion rules and labeling protocol.

---

## 🏷️ Risk Labels

| Verdict | Meaning |
| :--- | :--- |
| **`NO_RISK_FOUND`** 🟢 | Upgrade is safe; backwards-compatible; no affected call sites in repo AST. |
| **`REVIEW`** 🟡 | Human inspection advised; missing release notes, deprecation warnings, or ambiguous usage. |
| **`RISKY`** 🔴 | High confidence downstream breakage; breaking change confirmed in changelog and called in repo AST. |

---

## 🚀 Quickstart

```python
import kagglehub
import json
from pathlib import Path

# 1. Download dataset
path = Path(kagglehub.dataset_download("madhesh4124/pyriskbench-dependency-risk"))

# 2. Load Tier A fixtures
with open(path / "tier_a" / "cases.json") as f:
    fixtures = json.load(f)
print(f"Loaded {len(fixtures)} Tier A fixtures")

# 3. Load Tier B candidate PRs
candidates = [json.loads(line) for line in open(path / "tier_b" / "candidates.jsonl")]
print(f"Loaded {len(candidates)} real-world candidate PRs")
```

---

## 📜 License
Released under **Creative Commons Zero 1.0 (CC0 1.0) Public Domain**.
