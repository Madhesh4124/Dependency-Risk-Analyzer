# Benchmark Labeling Protocol (Tier B)

> **Purpose:** Standard Operating Procedure for establishing ground-truth labels for Python dependency upgrade pull requests through offline differential testing.
> **Scope:** Ground truth evaluation for Tier B benchmark cases and pilot validation.

---

## 1. Core Label Definitions

Every evaluated dependency update PR is assigned exactly one primary label based on empirical differential testing and evidence analysis:

### 1.1 `RISKY` (Test-Detected Breaking Change)
An upgrade is labeled `RISKY` if and only if **all** of the following conditions are met:
1. **Old version passes:** The repository test suite passes cleanly on the baseline commit using the old dependency version.
2. **New version fails:** The test suite fails when only the target dependency is upgraded to the new version.
3. **Attributable failure:** The failure stack trace or error message directly implicates the upgraded library (e.g., `AttributeError`, `ImportError`, changed function signature, altered return type, or removed deprecation).
4. **Reproducibility:** The failure reproduces consistently across **three consecutive reruns** under identical containerized environments.
5. **No confounding factors:** The failure is not caused by unrelated network flakes, expired certificates, timing issues, or unpinned transitive dependencies.

### 1.2 `NO_RISK_FOUND` (No Test-Detected Breaking Change)
An upgrade is labeled `NO_RISK_FOUND` if and only if **all** of the following conditions are met:
1. **Both versions pass:** The test suite passes cleanly on the old version AND on the new version under identical environments.
2. **Relevant tests executed:** The test suite actually exercises code paths that import or interact with the upgraded package (verified via coverage or static AST check).
3. **No deprecation warnings treated as errors:** No fatal deprecations are raised during execution.

> ⚠️ **Critical Disclaimer:** `NO_RISK_FOUND` measures **test-detected compatibility only**. It does *not* prove absolute absence of bugs or guarantee production safety if test coverage is incomplete.

### 1.3 `REVIEW` (Ambiguous or Inconclusive Evidence)
An upgrade is labeled `REVIEW` when:
1. **Behavioral change without clear failure:** Tests pass on both versions, but deprecation warnings are emitted in the test logs for code actively invoked by the repository.
2. **Documented break with unexercised code:** Release notes document an explicit breaking change, and static analysis shows repository usage, but the test suite does not exercise the affected code path.
3. **Missing or empty release documentation:** The package underwent a major or significant minor bump, but changelogs/release notes are missing, inaccessible, or uninformative, requiring human scrutiny.

---

## 2. Exclusion Rules (When to Discard a PR)

A candidate PR **must be excluded** from the benchmark if any of the following apply:

| Exclusion Code | Rule | Reason |
|---|---|---|
| `EXC-01` | **Old version fails baseline tests** | Cannot perform differential comparison if the codebase was already broken. |
| `EXC-02` | **Flaky or non-reproducible test failures** | Test failures that appear intermittently (e.g., race conditions, async timing, socket timeouts) prevent causal attribution. |
| `EXC-03` | **Environment or external dependency failure** | Failures caused by unavailable external services, expired API tokens, missing system C-libraries, or network outages. |
| `EXC-04` | **Confounding transitive changes** | Upgrading package A also updated unpinned package B to a major version that broke the build, making it impossible to attribute the root cause solely to package A. |
| `EXC-05` | **Unreproducible build environment** | Obsolete Python versions, private wheels, or unresolvable lockfiles where a clean container cannot be constructed. |
| `EXC-06` | **Bundled non-dependency changes** | PR contains manual code refactoring, feature additions, or unrelated bugfixes alongside the dependency bump. |

---

## 3. Operational Environment & Security Controls

Differential testing must be performed under strict environmental controls to prevent contamination and security risks:

1. **Isolated Containers:** Run each test cycle inside an ephemeral, disposable container (e.g., Docker container with explicit resource caps: max 2 vCPUs, 4GB RAM, 10-minute timeout).
2. **Zero Credentials:** Test containers must never have access to production tokens, cloud credentials, or GitHub write tokens.
3. **Network Isolation:** After initial dependency acquisition (`pip`/`uv` download), disable container outbound networking during test execution where feasible to prevent hidden live network dependencies.
4. **Environment Snapshots:** Pin and record:
   - Operating System image and architecture
   - Python minor version (e.g., 3.11.8)
   - Exact wheel/sdist hashes of both old and new dependencies
   - Complete terminal stdout/stderr logs from all 3 reruns.

---

## 4. Differential Testing Procedure (Step-by-Step)

```
[Candidate PR]
      │
      ▼
1. Inspect PR diff ──────────────► Contains manual code edits? ──► YES: Exclude (EXC-06)
      │ NO
      ▼
2. Checkout Base Commit
      │
      ▼
3. Install Old Dependency & Run Test Suite
      │
      ├─► Fails? ───────────────► Exclude (EXC-01)
      │
      ▼ Passes
4. Upgrade Target Dependency to New Version
      │
      ▼
5. Run Test Suite (Run 1)
      │
      ├─► Passes? ──────────────► Verify repo usages ──► Label NO_RISK_FOUND
      │
      ▼ Fails
6. Rerun Test Suite 2 more times (Runs 2 & 3)
      │
      ├─► Intermittent? ────────► Exclude (EXC-02)
      │
      ▼ Consistent (3/3 failures)
7. Inspect Traceback & Lockfile Changes
      │
      ├─► Caused by unpinned transitive package? ─► Exclude (EXC-04)
      ├─► Caused by external network / service? ──► Exclude (EXC-03)
      │
      ▼ Attributable directly to upgraded package
8. Assign Label: RISKY
```

---

## 5. Audit & Quality Gate

- For every batch of Tier B candidates, at least **15 cases** (or 100% of pilot cases) must be independently hand-audited.
- If label disagreement or ambiguity exceeds **20%**, the protocol must be revised and tightened before proceeding to benchmark evaluation.

