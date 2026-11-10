# Prompt Injection & Security Shield Benchmark Report

> **Source Artifact:** [`benchmark/prompt_injection_benchmark_report.json`](../benchmark/prompt_injection_benchmark_report.json)  
> **Run ID:** `p75-20261110T133453Z`  
> **Dataset:** [CloneGuard Benchmark Corpus](https://github.com/prodnull/cloneguard) by [`prodnull`](https://github.com/prodnull) (`v0.6.0`, Apache-2.0, `N = 539` samples)  
> **Generated At:** `2026-11-10T13:37:47Z`  
> **Execution Mode:** `gcp_cloud_run_model_armor_detection_only` (5/5 Cloud Run Job shards merged)

---

## 1. Runtime & Telemetry Summary

- **Total Cases Evaluated:** `539` (`185` malicious prompt injections, `354` benign / hard-negative files)
- **Core Domain Subset (excl. 20 out-of-domain `implicit_instruction` rows):** `519` (`165` malicious, `354` benign)
- **Sharding:** `5` parallel Cloud Run Job tasks (`shard_task_indices: [0, 1, 2, 3, 4]`), `request_delay_ms: 350`
- **Model Armor Config:**
  - Template: `projects/dependency-impact-analyzer/locations/us-central1/templates/pr-security-shield`
  - Location: `us-central1`, `fail_closed=true`, `multilang=true`, `include_llm_classifier=false`
- **Model Armor Telemetry (`N = 539`):**
  - Status Counts: `clean: 479`, `matched: 60`, **`error_count: 0`**
  - Triggered Filters: `pi_and_jailbreak:HIGH: 39`, `pi_and_jailbreak:MEDIUM_AND_ABOVE: 21`
  - Engine Invocation Mix: `model_armor+local_heuristic: 509`, `model_armor: 30` (on 30 samples caught purely by Model Armor prior to local fallback)

---

## 2. Overall Detection Metrics (Full Corpus vs. Core Domain)

### 2.1 Full CloneGuard Corpus (`N = 539`)

| Detector | Accuracy `[95% CI]` | Recall / TPR `[95% CI]` | Specificity / TNR `[95% CI]` | FPR `[95% CI]` | Precision | F1 | Confusion Matrix (`TP / FN / TN / FP`) | Latency (`p50 / p95 / max`) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **D1: Local Normalization & Heuristics** | `75.1%` (`405/539`) `[0.713, 0.786]` | `28.1%` (`52/185`) `[0.221, 0.350]` | `99.7%` (`353/354`) `[0.984, 1.000]` | `0.3%` (`1/354`) `[0.001, 0.016]` | `0.981` | `0.437` | `52 / 133 / 353 / 1` | `0.42 / 8.15 / 79.26 ms` (mean `1.97 ms`) |
| **D2: Google Cloud Model Armor + Local** | **`80.7%`** (`435/539`) `[0.772, 0.838]` | **`44.3%`** (`82/185`) `[0.374, 0.515]` | **`99.7%`** (`353/354`) `[0.984, 1.000]` | **`0.3%`** (`1/354`) `[0.001, 0.016]` | **`0.988`** | **`0.612`** | **`82 / 103 / 353 / 1`** | `500.3 / 1,080.8 / 3,480.2 ms` (mean `563.6 ms`) |

### 2.2 Core Domain Subset (`N = 519`, Excluding 20 Out-of-Domain `implicit_instruction`)

| Detector | Accuracy `[95% CI]` | Recall / TPR `[95% CI]` | FPR `[95% CI]` | Precision | F1 | Confusion Matrix (`TP / FN / TN / FP`) | Latency (`p50 / p95 / max`) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **D1: Local Normalization & Heuristics** | `78.0%` (`405/519`) `[0.743, 0.814]` | `31.5%` (`52/165`) `[0.249, 0.390]` | `0.3%` (`1/354`) | `0.981` | `0.477` | `52 / 113 / 353 / 1` | `0.45 / 8.39 / 79.26 ms` (mean `2.05 ms`) |
| **D2: Google Cloud Model Armor + Local** | **`83.6%`** (`434/519`) `[0.802, 0.866]` | **`49.1%`** (`81/165`) `[0.416, 0.567]` | **`0.3%`** (`1/354`) | **`0.988`** | **`0.656`** | **`81 / 84 / 353 / 1`** | `500.3 / 1,095.4 / 3,480.2 ms` (mean `566.2 ms`) |

---

## 3. Defense-in-Depth Synergy & Overlap Matrix

Reported `model_armor_lift`: **`+16.22%` recall lift** (`52` -> `82` catches, `+30` Model-Armor-only catches) with **`0.0%` FPR delta**.

Inspecting per-sample `d2_model_armor_status == "matched"` shows why neither standalone engine suffices:

| Engine Coverage (`N = 185` Malicious) | Full Corpus (`N = 185`) | Core Domain (`N = 165`) | Notes |
|---|---:|---:|---|
| **Local Only (missed by Model Armor)** | `23` (`12.4%`) | `23` (`13.9%`) | Encoded / obfuscated / structural patterns missed by raw Model Armor |
| **Model Armor Only (missed by Local)** | `30` (`16.2%`) | `29` (`17.6%`) | Semantic paraphrases & all non-English injections (`multilingual_smoke`) |
| **Caught by Both** | `29` (`15.7%`) | `29` (`17.6%`) | Overlapping high-signal attacks |
| **Combined Hybrid Union (`D2`)** | **`82` (`44.3%`)** | **`81` (`49.1%`)** | Model Armor standalone: `59/185` (`31.9%`, `1/354` FP); Local standalone: `52/185` (`28.1%`, `1/354` FP) |
| **Missed by Both** | `103` (`55.7%`) | `84` (`50.9%`) | Dominated by `structural_dilution`, `counter_defensive`, `implicit_instruction`, & `hard` stealth payloads |

---

## 4. Dataset Split & Latency Breakdown

| Dataset Split | `N` | D1 Acc | D2 Acc | D1 FPR / TPR | D2 FPR / TPR | D1 p50 ms | D2 p50 ms (min / max) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **`malicious_corpus`** | `185` | `28.1%` (`52/185`) | **`44.3%` (`82/185`)** | `28.1%` TPR | **`44.3%` TPR** | `0.15 ms` | `499.1 ms` (`381.0` / `1,653.9`) |
| **`benign_corpus_eval`** | `234` | `99.6%` (`233/234`) | `99.6%` (`233/234`) | `0.4%` (`1/234`) FPR | `0.4%` (`1/234`) FPR | `0.41 ms` | `502.8 ms` (`371.8` / `3,480.2`) |
| **`benign_longform_real`** | `20` | **`100.0%` (`20/20`)** | **`100.0%` (`20/20`)** | **`0.0%` (`0/20`)** FPR | **`0.0%` (`0/20`)** FPR | `6.56 ms` | `536.0 ms` (`454.0` / `713.1`) |
| **`defensive_security_corpus`** | `100` | **`100.0%` (`100/100`)** | **`100.0%` (`100/100`)** | **`0.0%` (`0/100`)** FPR | **`0.0%` (`0/100`)** FPR | `0.63 ms` | `486.9 ms` (`389.6` / `761.8`) |

---

## 5. Attack Category Recall (`malicious_corpus`, `N = 185`)

| Category | `N` | Core Domain | D1 Local Recall `[95% CI]` | D2 Hybrid Recall `[95% CI]` | Hybrid Lift |
|---|---:|---:|---:|---:|---:|
| **`multilingual_smoke`** | `5` | Yes | `0/5` (`0.0%`) `[0.000, 0.435]` | **`5/5` (`100.0%`)** `[0.566, 1.000]` | **`+100.0%`** |
| **`encoding_evasion`** | `20` | Yes | `17/20` (`85.0%`) `[0.640, 0.948]` | **`18/20` (`90.0%`)** `[0.699, 0.972]` | `+5.0%` |
| **`homoglyph_unicode`** | `20` | Yes | `15/20` (`75.0%`) `[0.531, 0.888]` | **`17/20` (`85.0%`)** `[0.640, 0.948]` | `+10.0%` |
| **`synonym_substitution`** | `20` | Yes | `6/20` (`30.0%`) `[0.146, 0.519]` | **`15/20` (`75.0%`)** `[0.531, 0.888]` | **`+45.0%`** |
| **`fragmentation`** | `20` | Yes | `2/20` (`10.0%`) `[0.028, 0.301]` | `7/20` (`35.0%`) `[0.181, 0.567]` | `+25.0%` |
| **`social_engineering`** | `20` | Yes | `2/20` (`10.0%`) `[0.028, 0.301]` | `6/20` (`30.0%`) `[0.146, 0.519]` | `+20.0%` |
| **`truncation_padding`** | `20` | Yes | `4/20` (`20.0%`) `[0.081, 0.416]` | `6/20` (`30.0%`) `[0.146, 0.519]` | `+10.0%` |
| **`counter_defensive`** | `20` | Yes | `4/20` (`20.0%`) `[0.081, 0.416]` | `5/20` (`25.0%`) `[0.112, 0.469]` | `+5.0%` |
| **`structural_dilution`** | `20` | Yes | `2/20` (`10.0%`) `[0.028, 0.301]` | `2/20` (`10.0%`) `[0.028, 0.301]` | `0.0%` |
| **`implicit_instruction`** | `20` | No | `0/20` (`0.0%`) `[0.000, 0.161]` | `1/20` (`5.0%`) `[0.009, 0.236]` | `+5.0%` |

### 5.1 Malicious Recall by Evasion Difficulty (`N = 185`)

| Difficulty Tier | `N` | D1 (Local) | Model Armor Standalone | D2 (Hybrid) |
|---|---:|---:|---:|---:|
| **`easy`** | `35` | `17/35` (`48.6%`) | `10/35` (`28.6%`) | **`18/35` (`51.4%`)** |
| **`medium`** | `105` | `30/105` (`28.6%`) | `40/105` (`38.1%`) | **`51/105` (`48.6%`)** |
| **`hard`** | `45` | `5/45` (`11.1%`) | `9/45` (`20.0%`) | **`13/45` (`28.9%`)** |

---

## 6. Benign False Positive Breakdown (`N = 354`) & Pattern Distribution

| Benign Content Type | `N` | D1 FPR | D2 FPR |
|---|---:|---:|---:|
| `defensive_agent_instructions` | `100` | `0/100` (`0.0%`) | **`0/100` (`0.0%`)** |
| `workflow` | `62` | `0/62` (`0.0%`) | **`0/62` (`0.0%`)** |
| `test_file` | `61` | `1/61` (`1.6%`) | `1/61` (`1.6%`) |
| `readme` | `44` | `0/44` (`0.0%`) | **`0/44` (`0.0%`)** |
| `config` | `23` | `0/23` (`0.0%`) | **`0/23` (`0.0%`)** |
| `build_script` | `17` | `0/17` (`0.0%`) | **`0/17` (`0.0%`)** |
| `env_config` | `17` | `0/17` (`0.0%`) | **`0/17` (`0.0%`)** |
| `agent_instructions` | `15` | `0/15` (`0.0%`) | **`0/15` (`0.0%`)** |
| `security_doc` | `15` | `0/15` (`0.0%`) | **`0/15` (`0.0%`)** |

- **Single Benign False Positive:** `ben_eval:benign-test-file-085` (`category=test_file`, `text_length=2157`), flagged identically by both engines (`d1_pattern_type: INSTRUCTION_RESET` and `Model Armor: pi_and_jailbreak:MEDIUM_AND_ABOVE`).
- **Triggered Pattern Counts (Detections):**
  - `D1` detected (`53` total = `52` TP + `1` FP): `ENCODING_OBFUSCATION: 18`, `SECRET_EXFILTRATION: 16`, `INSTRUCTION_RESET: 14`, `FORCED_VERDICT_OVERRIDE: 5`
  - `D2` detected (`83` total = `82` TP + `1` FP): `MODEL_ARMOR_FLAGGED: 60`, `ENCODING_OBFUSCATION: 13`, `SECRET_EXFILTRATION: 6`, `FORCED_VERDICT_OVERRIDE: 4`

---

## 7. Key Takeaways

1. **Zero-Error Cloud Run + Model Armor Execution:** All `539` CloneGuard samples scanned on `us-central1` (`pr-security-shield`, fail-closed, `350 ms` pacing across 5 tasks) with `0` HTTP 429 or API failures (`500.3 ms` median latency).
2. **Near-Zero False Alarms on Hard Security Negatives:** Even across `100` pentest/defensive security files and `20` long-form real OSS docs, both D1 and D2 achieved **`0.0%` false positives** (`0.3%` FPR overall across `354` benign docs).
3. **Why Hybrid (`Model Armor + Local`) Beats Either Alone:** Model Armor eliminated the local blind spots on `multilingual_smoke` (`0% -> 100%`) and `synonym_substitution` (`30% -> 75%`), while local normalization/decoding caught `23` encoding and homoglyph attacks missed by Model Armor alone (`44.3%` pooled / `49.1%` core recall vs `31.9%` standalone Model Armor or `28.1%` standalone local).
4. **Known Hard Attack Ceiling:** Stealthier repository attacks that mimic routine contributor prose (`structural_dilution`: `10%`, `counter_defensive`: `25%`) or spread instructions across chunks (`fragmentation`: `35%`, `truncation_padding`: `30%`) remain the primary open detection challenge—reinforcing why our downstream pipeline never relies solely on ingress scanning and enforces AST + verbatim quote grounding plus a non-decreasing deterministic risk floor.

---

## 8. Dataset Attribution & Credits

The `N = 539` prompt-injection and benign/hard-negative test corpus used in this security evaluation comes from the open-source **CloneGuard** benchmark suite:

- **Dataset & Project:** **CloneGuard** (`data/benchmark/`)
- **Author / Maintainer:** **[`prodnull`](https://github.com/prodnull)**
- **Upstream Repository:** [https://github.com/prodnull/cloneguard](https://github.com/prodnull/cloneguard) (`v0.6.0`, commit `9c020bf`)
- **License:** [Apache License 2.0](https://github.com/prodnull/cloneguard/blob/main/LICENSE)
- **Evaluated Corpus Files (`N = 539`):**
  - `data/benchmark/malicious_corpus.json` — `185` malicious prompt-injection payloads across 10 evasion categories and 3 difficulty tiers
  - `data/benchmark/benign_corpus_eval.json` — `234` benign workflow, README, config, test, and instruction files
  - `data/benchmark/benign_longform_real.json` — `20` long-form real open-source documentation files
  - `data/benchmark/defensive_security_corpus.json` — `100` defensive agent and security documentation files evaluated as hard negatives
- **Scope Note:** All accuracy, recall, false-positive, and latency figures in this report evaluate the Dependency Upgrade Risk Agent ingress detectors (`D1` local normalization/heuristics and `D2` Google Cloud Model Armor + local heuristics) run against the CloneGuard dataset, not CloneGuard's own hook-layer defense engine.
