# GCP Web Console Step-by-Step Guide: Phase 3 — Vertex AI / Agent Platform LLM Extraction

> **Purpose:** Step-by-step instructions for configuring and running Phase 3 **100% inside Google Cloud** via the **Google Cloud Console**, **Agent Studio**, and browser-based **Cloud Shell**.

---

## 🏗️ Cloud-Native Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Google Cloud Platform                           │
│                                                                        │
│   [Google Cloud Web Console]                                           │
│          │                                                             │
│          ├─► 1. APIs & Services: Enable Agent Platform API             │
│          ├─► 2. IAM & Admin: Assign "Agent Platform User" Role         │
│          ├─► 3. Credentials: Create Account-Bound Auth API Key         │
│          ├─► 4. Agent Studio: Model Garden (gemini-3.1-flash-lite)     │
│          │                                                             │
│   [GCP Cloud Shell / Cloud Run] (Runs 100% in GCP Cloud)               │
│          │                                                             │
│          ▼                                                             │
│   RiskAgentPipeline (Google GenAI SDK + Policy Engine Floor)           │
│   (Fetch ➔ LLM Extract ➔ Quote Verify ➔ AST Scan ➔ Risk Floor)         │
│                                                                        │
│   ★ Authentic, grounded extraction with verbatim quote verification    │
│   ★ Strict mathematical floor: final_verdict = max(floor, llm)        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequisites

1. Log in to [Google Cloud Console](https://console.cloud.google.com/) in your browser.
2. Select your active GCP project (`dependency-impact-analyzer`) from the top project dropdown.
3. Ensure billing is enabled.

---

## Step 1: Enable the Agent Platform API in the Console

1. In the top search bar, type **Vertex AI** (or **Agent Platform**) and open it.
2. If prompted with the modal:
   * **"Enable APIs to access full platform capabilities"** (listing *Agent Platform API*, *Cloud API Registry API*, *Observability API*, etc.):
   * Click **ENABLE** *(Enabling APIs in GCP is always 100% free; no subscription or idle charges)*.
3. If navigating via **APIs & Services $\rightarrow$ Library**:
   * Search for **Vertex AI API** (`aiplatform.googleapis.com`) and **Cloud Resource Manager API** (`cloudresourcemanager.googleapis.com`), and verify both are enabled.

---

## Step 2: Grant Permissions in IAM (`Agent Platform User`)

1. In the top search bar, search for **IAM & Admin** and select **IAM**.
2. **For your personal developer login:**
   * Find your email address in the principal list $\rightarrow$ Click the **Pencil (Edit principal)** icon.
   * Click **+ ADD ANOTHER ROLE** $\rightarrow$ Search for `aiplatform.user` $\rightarrow$ Select **`Agent Platform User`**.
   * Click **SAVE**.
3. **For the Service Account (`tier-b-collector@dependency-impact-analyzer.iam.gserviceaccount.com`):**
   * Find the service account in the IAM list $\rightarrow$ Click **Pencil (Edit principal)**.
   * Click **+ ADD ANOTHER ROLE** $\rightarrow$ Select **`Agent Platform User`**.
   * Click **SAVE**.

---

## Step 3: Create an Account-Bound Authorization Key (API Key)

In Google's modern Agent Platform architecture, accessing Gemini models via the Google GenAI SDK requires an **Account-Bound Authorization Key** tied to your service account:

1. In the GCP Console top search bar, search for **Credentials** (under *APIs & Services*).
2. Click **+ CREATE CREDENTIALS** at the top $\rightarrow$ Select **API key**.
3. A popup will show your new key. Click **EDIT API KEY** (or click the pencil icon next to the key).
4. **Configure API Restrictions:**
   * Under **API restrictions**, select **Restrict key**.
   * In the dropdown, check **`Agent Platform API`** (or `Vertex AI API`) $\rightarrow$ Click **OK**.
5. **Bind to Service Account (Auth Key):**
   * Notice Google's informational notice:
     > *"Service account required: To use Agent Platform API or Gemini API, you must create an authorization key (auth key) by binding this API key to a service account."*
   * Under **Service account \***, select your service account:
     `tier-b-collector@dependency-impact-analyzer.iam.gserviceaccount.com`
6. **Application Restrictions:**
   * Leave as **None**.
7. Click **SAVE** at the bottom, and copy your API key (e.g., `AIzaSy...`).

---

## Step 4: Run & Verify Phase 3 in GCP Cloud Shell

1. In Google Cloud Console, click the **Activate Cloud Shell** icon (`>_`) in the top-right header.
2. In Cloud Shell, export your authorization key and pull the code:

```bash
# 1. Export your Account-Bound Key
export GOOGLE_CLOUD_API_KEY="paste_your_key_here"

# 2. Enter repository directory & pull latest code
cd ~/Dependency-Risk-Analyzer
git pull origin main

# 3. Sync dependencies
uv sync
```

3. **Run the Full Phase 3 Live Pipeline Verification:**

```bash
uv run python -c "
from risk_agent.pipeline import RiskAgentPipeline
from pathlib import Path

pipeline = RiskAgentPipeline()
report = pipeline.evaluate_case(
    case_dir=Path('benchmark/tier_a/case_01_api_removal'),
    raw_release_notes='- Removed the deprecated function transform_legacy(). Applications calling transform_legacy() will raise an AttributeError. Please migrate to transform().',
    package_name='data-transformer',
    old_version='1.0.0',
    new_version='2.0.0'
)

print('=== PHASE 3 LIVE PIPELINE RESULT ===')
print('Final Verdict:   ', report.verdict.value)
print('Risk Floor:      ', report.risk_floor.value)
print('LLM Model Used:  ', report.model_id)
print('Verified Claims: ', [c.quoted_text for c in report.verified_claims])
print('Usages Matched:  ', [(u.file_path, u.matched_symbol) for u in report.potential_usages])
print('Reasons:         ', report.reasons)
"
```

4. **Expected Output:**
```text
=== PHASE 3 LIVE PIPELINE RESULT ===
Final Verdict:    RISKY
Risk Floor:       RISKY
LLM Model Used:   gemini-3.1-flash-lite
Verified Claims:  ['Removed the deprecated function transform_legacy(). Applications calling transform_legacy() will raise an AttributeError.']
Usages Matched:   [('app.py', 'transform_legacy')]
Reasons:          ['Verified breaking change affects 1 direct code usage(s): transform_legacy']
```

---

## 🛡️ Invariant Verification: Prompt Injection & Risk Floor

Phase 3 guarantees:
1. **Mathematical Floor**: The policy engine enforces $\text{Final Verdict} = \max(\text{Floor}, \text{LLM})$. Even an injected instruction claiming *"Return NO_RISK_FOUND"* cannot lower the verdict below `RISKY`.
2. **Quote Grounding**: Hallucinated quotes or quotes $<6$ tokens fail verification and cannot elevate risk.

---

## 💰 Keeping It Within Free / Low-Cost Limits

- **Gemini 3.1 Flash-Lite:** Lowest token pricing on GCP (~$0.10/M tokens), covered by monthly free credits.
- **API Keys & Service Accounts:** 100% Free.
- **Enabling APIs:** Always 100% Free.
