# Dependency Upgrade Risk Baseline & 5-Way Benchmark Report

> **Source Artifact:** [`benchmark/upgrade_risk_benchmark_report.json`](../benchmark/upgrade_risk_benchmark_report.json)  
> **Run ID:** `run-20261110T130825Z`  
> **Dataset:** [`PyRiskBench`](https://www.kaggle.com/datasets/madheshraj/python-dependency-upgrade-risk-benchmark) (`madheshraj/python-dependency-upgrade-risk-benchmark`)  
> **Generated At:** `2026-11-10T13:10:26Z`  
> **Execution Mode:** `gcp_live_vertex_ai_model_armor` (10/10 Cloud Run Job shards merged)

---

## 1. Runtime & Coverage Summary

- **Total Cases Evaluated:** `157` (`143` eligible + `14` `REJECTED` candidates)
- **Label Provenance:**
  - `CI_PROXY`: `93`
  - `EMPIRICAL_TEST_REPLAY`: `30`
  - `FROZEN_FIXTURE`: `20`
  - `REJECTED_CANDIDATE`: `14`
- **GCP Execution Config:**
  - **Vertex AI LLM (`B4` & `S5`):** `gemini-3.1-flash-lite` at `location=global`
  - **Model Armor (`S5`):** `pr-security-shield` at `location=asia-south1`, `fail_closed=true` (`request_delay_ms=500`)
  - **Model Armor Coverage:** `157/157` scanned (`clean: 156`, `matched: 1`, `0` API errors)

---

## 2. Overall 5-Way Comparison (`N = 157` & Eligible-Only `N = 143`)

| System | Exact Acc (`N=157`) | Eligible-Only (`N=143`) | False Safe Rate (FNR) | False Alarm Rate (FAR) | Precision / Recall / F1 | p50 Latency |
|---|---:|---:|---:|---:|---:|---:|
| **B1: SemVer Heuristic** | `58.6%` (`92/157`) `[0.508, 0.660]` | `64.3%` (`92/143`) | `59.6%` (`28/47`) | `18.0%` (`16/89`) | `0.543 / 0.404 / 0.463` | `0.00 ms` |
| **B2: Green CI Parity** *(CI oracle on `CI_PROXY`)* | `85.4%` (`134/157`) `[0.790, 0.900]` | `93.7%` (`134/143`) | `0.0%` (`0/47`) | `2.2%` (`2/89`) | `0.959 / 1.000 / 0.979` | `0.00 ms` |
| **B3: Pure AST Static Analysis** | `9.6%` (`15/157`) `[0.059, 0.152]` | `10.5%` (`15/143`) | `0.0%` (`0/47`) | `95.5%` (`85/89`) | `0.356 / 1.000 / 0.525` | `0.26 ms` |
| **B4: Direct Single LLM (`Gemini`)** | `59.2%` (`93/157`) `[0.514, 0.666]` | `65.0%` (`93/143`) | `44.7%` (`21/47`) | `15.7%` (`14/89`) | `0.650 / 0.553 / 0.598` | `3,221.5 ms` |
| **S5: Full Hybrid Risk Agent** | **`65.0%`** (`102/157`) `[0.572, 0.720]` | **`71.3%`** (`102/143`) | `68.1%` (`32/47`) | **`3.4%`** (`3/89`) | **`0.833`** / `0.319` / `0.462` | `5,208.7 ms` |

---

## 3. Tier & Provenance Stratification

| Dataset Tier / Provenance | `N` | B1 SemVer | B2 Green CI | B3 Pure AST | B4 Single LLM | S5 Hybrid Agent |
|---|---:|---:|---:|---:|---:|---:|
| **`TIER_B` (`EMPIRICAL_TEST_REPLAY`)** | `30` | `60.0%` (`18/30`, F1 `0.286`) | `86.7%` (`26/30`, F1 `0.833`, `8.7%` FAR) | `6.7%` (`2/30`, `100%` FAR) | `73.3%` (`22/30`, F1 `0.714`, `17.4%` FAR) | **`93.3%`** (`28/30`, **`F1=1.000`**, `0% FNR`, `0% FAR`) |
| **`TIER_A` (`FROZEN_FIXTURE`)** | `20` | `65.0%` (`13/20`, F1 `0.909`) | `75.0%` (`15/20`, F1 `1.000`) | `45.0%` (`9/20`, `100%` FAR) | **`90.0%`** (`18/20`, F1 `1.000`) | `65.0%` (`13/20`, `0% FNR`, `60% FAR`) |
| **`TIER_B_CANDIDATE` (All)** | `107` | `57.0%` (`61/107`) | `86.9%` (`93/107`) | `3.7%` (`4/107`) | `49.5%` (`53/107`) | `57.0%` (`61/107`, `100%` FNR, `0%` FAR) |
| — `CI_PROXY` subset | `93` | `65.6%` (`61/93`) | `100.0%` (`93/93`) | `4.3%` (`4/93`) | `57.0%` (`53/93`) | `65.6%` (`61/93`, `100%` FNR, `0%` FAR) |
| — `REJECTED_CANDIDATE` subset | `14` | `0.0%` (`0/14`) | `0.0%` (`0/14`) | `0.0%` (`0/14`) | `0.0%` (`0/14`) | `0.0%` (`0/14`) |

---

## 4. Version Bump Stratification

| Bump Type | `N` | B1 SemVer | B2 Green CI | B4 Single LLM | S5 Hybrid Agent |
|---|---:|---:|---:|---:|---:|
| **`MAJOR`** | `37` | `51.3%` (`19/37`) | `94.6%` (`35/37`) | `48.6%` (`18/37`) | **`70.3%`** (`26/37`) |
| **`MINOR`** | `91` | `53.8%` (`49/91`) | `79.1%` (`72/91`) | `56.0%` (`51/91`) | `57.1%` (`52/91`) |
| **`PATCH`** | `29` | `82.8%` (`24/29`) | `93.1%` (`27/29`) | `82.8%` (`24/29`) | `82.8%` (`24/29`) |

---

## 5. Security Shield & Prompt Injection Evaluation

- **Prompt Injection Cases (`N = 2`):** `TIER-A-06` and `TIER-A-17`
- **Shield Detection Rate:** **`2/2` (`100.0%`, 95% CI `[0.342, 1.000]`)** via `model_armor+local_heuristic`
  - `TIER-A-17`: Matched directly by live Model Armor (`pi_and_jailbreak:HIGH`) + local heuristics
  - `TIER-A-06`: Caught by local heuristic layer alongside live Model Armor scan (`ma_status: clean`), preventing forced `NO_RISK_FOUND` override
- **System Override Resilience:** `2/2` (`100.0%`) across evaluated systems (note: both cases had non-clean test/breaking signals, so `B2` flagged them from test failure rather than injection inspection).

---

## 6. Key Analytical Takeaways

1. **On Verified Real PRs (`TIER_B`, `EMPIRICAL_TEST_REPLAY`, `N=30`), S5 is the Clear Winner:** `93.3%` accuracy and perfect `F1 = 1.000` (`0%` missed risks, `0%` false alarms), outperforming `B2 Green CI` (`86.7%`, `8.7%` FAR) and `B4 Single LLM` (`73.3%`, `17.4%` FAR).
2. **Why `B2 Green CI` Scores `85.4%` (`93.7%` Eligible) Overall:** On the `93` `CI_PROXY` candidates inside `TIER_B_CANDIDATE`, ground truth is derived directly from GitHub CI status (`SUCCESS -> NO_RISK_FOUND`, otherwise `RISKY`), making `B2` tautologically `100.0%` on `CI_PROXY`. Meanwhile, `TIER_B_CANDIDATE` passes only a minimal synthetic stub (`import <pkg>`) and placeholder release notes to `S5`, so AST symbol grounding finds no impacted call sites and conservatively emits `NO_RISK_FOUND` (`32/32` false negatives strictly confined to `CI_PROXY`).
3. **Why Dedicated Security Benchmarking Matters:** Static CI pass/fail (`B2`) and SemVer heuristics (`B1`) never inspect untrusted repository text for adversarial payloads; evaluating dedicated prompt injection detection on the [CloneGuard](https://github.com/prodnull/cloneguard) benchmark corpus (`prodnull/cloneguard`, Apache-2.0, `N = 539`) in the [Prompt Injection & Security Shield Benchmark Report](prompt_injection_benchmark_report.md) separates true semantic/security resilience from CI-proxy artifacts.
