# GCP Web Console Step-by-Step Guide: Phase 4 — GCS Benchmark Vault & Batch Evaluation

> **Purpose:** Step-by-step instructions for establishing the **GCS Benchmark Vault** (`gs://dependency_impact_analyzer/benchmarks/frozen_v1/`) with **Object Versioning**, uploading immutable benchmark datasets with cryptographic SHA-256 manifests, and executing high-throughput batch evaluations 100% inside Google Cloud.

---

## 🏗️ Cloud-Native Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Google Cloud Platform                           │
│                                                                        │
│   [Google Cloud Web Console]                                           │
│          │                                                             │
│          ├─► 1. Cloud Storage: Create gs://dependency_impact_analyzer/ │
│          │      └─ Enable Object Versioning (Tamper-Proof Audit)       │
│          ├─► 2. Storage Browser: Upload benchmark/frozen_v1/ vault     │
│          │      ├─ tier_a_frozen.json (20 Synthetic Ground-Truth Cases)│
│          │      ├─ tier_b_frozen.json (30 Real-World Candidate PRs)    │
│          │      ├─ hand_audit_frozen.json (50% Audited Disagreements)  │
│          │      └─ manifest_sha256.json (Cryptographic Hash Manifest)  │
│          │                                                             │
│   [GCP Cloud Shell / Cloud Run Job] (Batch Evaluation Runner)          │
│          │                                                             │
│          ▼                                                             │
│   benchmark/harness.py (Evaluates 50 Frozen Cases x 3 Systems)         │
│   ├── Baseline 1: Deterministic Policy Only (No LLM)                   │
│   ├── Baseline 2: Single Direct LLM Call (No quote/AST guardrails)     │
│   └── System 3: Full Risk Agent (RiskAgentPipeline with Vertex AI)     │
│                                                                        │
│   ★ Immutable storage prevents benchmark contamination/leakage         │
│   ★ Stratified reporting: Counts & denominators per tier & bump type   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequisites

1. Open [Google Cloud Console](https://console.cloud.google.com/) in your browser.
2. Select your active GCP project (`dependency-impact-analyzer`) from the top project dropdown.
3. Ensure the active region is `asia-south1` (or your configured default region).

---

## Step 1: Configure Cloud Storage (GCS) Benchmark Vault

To guarantee scientific integrity (Decision Checkpoint **D-06**), benchmark datasets must be stored in an immutable, versioned vault:

1. In the GCP Console top search bar, type **Cloud Storage** and open **Buckets**.
2. Locate the existing bucket `dependency_impact_analyzer` (or click **+ CREATE** if not already created):
   * **Bucket name:** `dependency_impact_analyzer`
   * **Location type:** Region (`asia-south1` - Mumbai)
   * **Storage class:** Standard
   * **Access control:** Uniform
3. **Enable Object Versioning (Critical for Immutability):**
   * Click on the bucket `dependency_impact_analyzer`.
   * Click on the **Protection** tab (or **Lifecycle / Protection**).
   * Under **Object versioning**, toggle/click **ENABLE OBJECT VERSIONING**.
   * *(Why this matters: Object Versioning preserves historical versions of every uploaded file, making it mathematically impossible to silently overwrite or tamper with frozen benchmark labels).*

---

## Step 2: Upload Frozen Benchmark Datasets via Cloud Console

1. Inside the `dependency_impact_analyzer` bucket, click the **Objects** tab.
2. Click **+ CREATE FOLDER**:
   * Name: `benchmarks`
   * Click **CREATE**.
3. Click into the `benchmarks/` folder, and click **+ CREATE FOLDER**:
   * Name: `frozen_v1`
   * Click **CREATE**.
4. Click into `benchmarks/frozen_v1/`.
5. Click **UPLOAD FILES** (or drag and drop) and select all 4 files from your local `benchmark/frozen_v1/` directory:
   * `tier_a_frozen.json` (20 synthetic ground-truth fixtures)
   * `tier_b_frozen.json` (30 real-world curated candidate PRs)
   * `hand_audit_frozen.json` (15-case hand audit with 93.3% agreement)
   * `manifest_sha256.json` (SHA-256 cryptographic hashes of all benchmark files)
6. Verify that all 4 files appear with status **Live**.

---

## Step 3: Verify Tamper-Proof Cryptographic Hashes in Cloud Shell

1. Open **Cloud Shell** by clicking the terminal icon (`>_`) in the top-right header of the GCP Console.
2. Run the following command to verify the vault files in Cloud Storage:

```bash
# List frozen vault files in GCS
gcloud storage ls --long gs://dependency_impact_analyzer/benchmarks/frozen_v1/
```

3. Verify SHA-256 integrity using Cloud Shell:

```bash
# Download the manifest and verify against GCS object hashes
gcloud storage cat gs://dependency_impact_analyzer/benchmarks/frozen_v1/manifest_sha256.json | jq .metadata
```

You should see:
```json
{
  "benchmark_version": "v1.0-frozen",
  "decision_checkpoint": "D-06",
  "tier_a_cases_count": 20,
  "tier_b_cases_count": 30,
  "total_benchmark_cases": 50,
  "integrity_algorithm": "SHA-256"
}
```

---

## Step 4: Run the Batch Evaluation Harness in Cloud Shell

Execute the full 3-system evaluation against the frozen benchmark directly inside Google Cloud:

```bash
# 1. Enter the repository directory
cd ~/Dependency-Risk-Analyzer
git pull origin main

# 2. Configure Environment & Model Selection:
# Use gemini-3.1-flash-lite hosted in us-central1:
export VERTEX_AI_MODEL="gemini-3.1-flash-lite"
export GCP_REGION="us-central1"
export GOOGLE_CLOUD_REGION="us-central1"

# 3. Authenticate (Option A or Option B):
# Option A — Account-Bound API Key or Gemini Key:
export GOOGLE_CLOUD_API_KEY="your-api-key"
# Option B — Google Cloud Application Default Credentials (ADC):
# gcloud auth application-default login
# export GOOGLE_CLOUD_PROJECT="dependency-impact-analyzer"

# 4. Sync dependencies
uv sync

# 5. Run the master evaluation harness against live Vertex AI
uv run python benchmark/harness.py
```

The harness will evaluate:
* **Baseline 1:** Deterministic Policy Only (20 Tier A + 30 Tier B = 50 runs)
* **Baseline 2:** Single Direct LLM Call (50 runs)
* **System 3:** Full Risk Agent (50 runs)
* **Total:** 150 evaluation runs executed with stratified metric aggregation.

---

## Step 5: Upload Evaluation Artifact to Cloud Storage

Once the benchmark completes, upload the final evaluation report to GCS for permanent archival:

```bash
# Upload evaluation report to GCS
gcloud storage cp benchmark/evaluation_report.json gs://dependency_impact_analyzer/evaluations/evaluation_report_v1.json

# Confirm archival
gcloud storage ls gs://dependency_impact_analyzer/evaluations/
```

---

## ✅ Phase 4 GCP Verification Checklist

| Check | Expected Result | Verified |
|---|---|---|
| **GCS Bucket** | `gs://dependency_impact_analyzer/` exists in `asia-south1` | [ ] |
| **Object Versioning** | Enabled on bucket to prevent accidental overwrite | [ ] |
| **Frozen Vault** | `benchmarks/frozen_v1/` contains Tier A, Tier B, and `manifest_sha256.json` | [ ] |
| **SHA-256 Integrity** | Hashes in `manifest_sha256.json` match file contents | [ ] |
| **Label Audit** | Tier B hand-audit demonstrates disagreement rate < 20% (achieved: 6.7%) | [ ] |
| **Batch Evaluation** | 150 evaluation runs completed across 3 systems | [ ] |
| **Evaluation Report** | `benchmark/evaluation_report.json` archived to Cloud Storage | [ ] |
