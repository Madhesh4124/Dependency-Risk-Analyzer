# Dependency Upgrade Risk Agent

An automated risk analysis agent that detects breaking changes, API removals, and upgrade risks in Python dependency upgrade pull requests (e.g., Dependabot, Renovate) before merging.

<p align="center">
  <a href="https://github.com/apps/dependency-impact-analyzer/installations/new">
    <img src="https://img.shields.io/badge/GitHub%20App-1--Click%20Install-2ea44f?style=for-the-badge&logo=github" alt="1-Click Install GitHub App" />
  </a>
</p>

---

## 🎯 Project Overview

Automated dependency bumping tools (such as Dependabot) frequently submit pull requests that update library versions. However, passing continuous integration (CI) or semantic versioning assumptions often fail to catch subtle breaking changes, deprecation removals, runtime incompatibilities, or breaking transitive constraints.

The **Dependency Upgrade Risk Agent** evaluates dependency upgrade PRs through a multi-stage deterministic pipeline layered with verified LLM extraction to classify upgrade risk into:
- **`NO_RISK_FOUND`**: Test-verified and evidence-backed backwards compatibility.
- **`REVIEW`**: Ambiguous risk, unexercised breaking changes, or missing documentation requiring human review.
- **`RISKY`**: Attributable breaking changes, API removals, signature changes, or unsupported runtime environments.

---

## 🔬 Benchmark Methodology

Evaluation is structured across distinct tiers to avoid noisy proxy metrics:

| Tier | Dataset Construction | Reliability | Target Count | Status |
|:---:|---|:---:|:---:|:---:|
| **Tier A** | Constructed synthetic fixtures with known ground-truth breaks | High (by construction) | ~20 cases | Next (Phase 1) |
| **Tier B** | Real open-source PRs evaluated via offline differential test replay | High (empirical test parity) | ~30–50 cases | **Populated (57 candidates, Phase 0 Complete)** |
| **Tier C** | Observational GitHub CI / merge / revert outcomes | Low (noisy proxy) | Exploratory only | Analysis only |

---

## 📊 Phase 0: Label Protocol Pilot Report

**Status:** Completed ✅ (Exit Criterion Met: 5/5 Defensible Labels)

Before building downstream agent logic, **Phase 0** established and validated the empirical labeling protocol ([docs/label_protocol.md](docs/label_protocol.md)) on real public GitHub repositories.

### 1. Automated Collector Infrastructure
A scalable cloud collection pipeline was deployed on Google Cloud Platform (Cloud Run Job + Cloud Workflows + Cloud Scheduler) to harvest, filter, and analyze public dependency update PRs:
- Evaluated **140 unique candidate PRs** across major Python ecosystems (`fastapi`, `sqlalchemy`, `numpy`, `pandas`, `cryptography`, `click`, `httpx`, `redis`).
- Curated **57 strictly verified accepted candidates** with 100% green baseline CI (`base_ci_status == "SUCCESS"`) in [`benchmark/tier_b/candidates.jsonl`](benchmark/tier_b/candidates.jsonl).
- Enforced lockfile churn isolation, AST manifest diff parsing, companion package pairing (`pydantic` + `pydantic-core`), and polite rate-limit throttling (0.5s throttle).

### 2. Empirical Differential Replay
5 candidate PRs were subjected to offline differential testing:
1. **Base Commit Check:** Verified repository tests pass cleanly on baseline commit with the old dependency version (ruling out pre-existing breaks per `EXC-01`).
2. **Upgraded Commit Check:** Executed the test suite with the upgraded target dependency.
3. **3x Rerun Validation:** Verified test results across 3 consecutive reruns to ensure zero test flakiness (`EXC-02`).
4. **Causal Attribution:** Analyzed tracebacks and logs to attribute failures directly to the dependency upgrade.

All findings are persisted in [`benchmark/tier_b/pilot.json`](benchmark/tier_b/pilot.json):

| Case ID | Repository & PR | Target Package Bump | Base Tests | Upgraded Tests | 3x Rerun | Ground Truth Label | Differential Replay Findings |
|---|---|---|:---:|:---:|:---:|:---:|---|
| **PILOT-01** | [`TheKyleChau/utf8-api#35`](https://github.com/TheKyleChau/utf8-api/pull/35) | `fastapi` 0.141.1 → 0.146.0 | **PASS** (113/113) | **PASS** (113/113) | Consistent | `NO_RISK_FOUND` | Full test suite executed with parity; no deprecations or runtime regressions. |
| **PILOT-02** | [`moveeeax/urlshrink#29`](https://github.com/moveeeax/urlshrink/pull/29) | `sqlalchemy` 2.0.51 → 2.1.6 | **PASS** (132/132) | **PASS** (132/132) | Consistent | `NO_RISK_FOUND` | Database transaction commits, schema constraints, and SQL injection tests pass cleanly. |
| **PILOT-03** | [`Synthetic-Control-Robustness-Envelopes-Public#4`](https://github.com/Maar10Herr/Synthetic-Control-Robustness-Envelopes-Public/pull/4) | `numpy` 2.5.2 → 2.5.3 | **PASS** (61/61) | **PASS** (61/61) | Consistent | `NO_RISK_FOUND` | **Why CI Failed:** Head CI failed on GitHub Actions because Dependabot modified `.github/dependabot.yml` without updating `MANIFEST.sha256`. The actual unit tests and math solvers passed 100%. |
| **PILOT-04** | [`shaikn6/credit-arena#11`](https://github.com/shaikn6/credit-arena/pull/11) | `pandas` 3.0.6 → 3.1.0 | **PASS** (13/13) | **PASS** (13/13) | Consistent | `NO_RISK_FOUND` | **Why CI Failed:** GitHub Actions failed during an external OpenML HTTP dataset download, skipping pytest. Under controlled local replay, all 13 credit modeling tests passed. |
| **PILOT-05** | [`espinoso/mentorshipMatchingApp#4`](https://github.com/espinoso/mentorshipMatchingApp/pull/4) | `numpy` 2.4.6 → 2.5.4 | **PASS** | **FAIL** | Consistent | `RISKY` | **Causal Packaging Break:** `numpy 2.5.4` dropped Python 3.11 support (`requires-python >= 3.12`), deterministically breaking dependency resolution on Python 3.11. |

#### Negative / Exclusion Controls Verified
- **`CTRL-01` (`cfdude/datacommons-mcp#62`):** Excluded under `EXC-01` & `EXC-03` (base commit fails 12 tests due to missing live Data Commons credentials).
- **`CTRL-02` (`AnonymousRand/python_markdown_environments#41`):** Excluded under `EXC-01` (base commit fails `test_thm_heading` prior to upgrade).

### 3. Key Empirical Insight: Raw CI Cannot Be Ground Truth
A critical takeaway from Phase 0 is that **observational GitHub CI is noisy and cannot serve as ground truth**:
- If we had relied on GitHub CI status alone, **PILOT-03** and **PILOT-04** would have been misclassified as `RISKY` due to an unrelated file-integrity script and an external network timeout.
- Differential testing proved that their code changes were completely backwards-compatible (`NO_RISK_FOUND`).

---

## 📁 Repository Structure

```text
.
├── benchmark/
│   ├── tier_a/                      # Deterministic synthetic ground-truth fixture cases
│   │   ├── cases.json               # Master registry of 8 Tier A fixtures
│   │   ├── reproduction_report.json # 3-run reproduction verification report
│   │   └── case_01..08/             # Isolated fixture environments (repo, pkgs, notes)
│   └── tier_b/
│       ├── candidates.jsonl         # Canonical dataset of 57 accepted candidate PRs
│       └── pilot.json               # Phase 0 differential testing ground truth dataset
├── docs/
│   ├── guides/                      # Production guides for Cloud Run & GitHub App
│   │   ├── phase_5_gcp_guide.md     # Phase 5 GCP Web Console & Cloud Run guide
│   │   └── phase_6_guide.md         # Phase 6 GitHub App & Model Armor setup guide
│   └── label_protocol.md            # Standard operating procedure & exclusion rules (EXC-01..10)
├── infra/
│   └── collector/                   # GCP Cloud Run Job collector & AST diff parser
├── scripts/                         # Analysis, validation, and reproduction test runners
├── src/
│   └── risk_agent/                  # Core deterministic risk analyzer package
│       ├── webhook/                 # HMAC-SHA256 signature validation & delivery deduplication
│       ├── parser/                  # PR diff & manifest parser (requirements, pyproject, setup.cfg)
│       ├── resolver/                # Package-to-import module name resolution
│       ├── fetcher/                 # Strict allowlisted release note fetcher
│       ├── verifier/                # Normalized token-sequence quote verifier
│       ├── scanner/                 # Python AST usage detector with confidence tiers
│       ├── policy/                  # Deterministic verdict policy engine & floor rules
│       ├── models/                  # Pydantic domain models and schemas
│       ├── pipeline.py              # End-to-end deterministic evaluation pipeline
│       └── config.py                # Security thresholds and global configurations
└── tests/
    ├── collector/                   # 56 automated unit & end-to-end tests for collector
    ├── fixtures/                    # Automated reproduction verification test suite
    ├── unit/                        # 44 unit tests covering all deterministic components
    └── integration/                 # 8 integration tests validating Tier A fixtures
```

---

## 🚀 Roadmap

- [x] **Phase 0 — Label Protocol Pilot:** Define label protocol, build GCP collector, harvest Tier B candidates, and validate 5 pilot cases with differential testing.
- [x] **Phase 1 — Tier A Fixtures:** Construct deterministic synthetic fixture repositories with verified breaking and non-breaking changes.
- [x] **Phase 2 — Deterministic Pipeline & Risk Floor:** Build webhook validator, AST usage scanner, release note fetcher, and deterministic risk policy engine.
- [x] **Phase 3 — LLM Extraction & Workflow:** Layer structured LLM extraction with quote verification and prompt injection defenses using Google Vertex AI.
- [x] **Phase 4 — Benchmark & Evaluation:** Run the agent and baseline comparisons on frozen Tier A and Tier B benchmarks.
- [x] **Phase 5 — Deployment & Demo:** Containerize with `uv` and deploy read-only webhook service to Cloud Run ([docs/guides/phase_5_gcp_guide.md](docs/guides/phase_5_gcp_guide.md)).
- [x] **Phase 6 — 1-Click GitHub App, PR Reporting & Injection Shield:** Author production setup guide, multi-tenant GitHub App auth, prompt injection shield, PR comment formatter, idempotent comment client, and webhook pipeline ([docs/guides/phase_6_guide.md](docs/guides/phase_6_guide.md)).

---

## 🛠️ Running Tests

To run the complete test suite (collector + deterministic pipeline + Tier A fixtures):

```bash
uv run pytest
```

To run individual test suites:

```bash
# Deterministic unit tests (44 tests)
uv run pytest tests/unit -v

# Deterministic integration tests on Tier A (8 tests)
uv run pytest tests/integration -v

# Tier A fixture ground-truth reproduction suite
uv run pytest tests/fixtures -v

# GCP collector test suite
uv run pytest tests/collector -v
```

