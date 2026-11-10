# Dependency Upgrade Risk Agent

An automated, AI-powered security and compatibility analysis agent that detects breaking changes, API removals, and upgrade risks in Python dependency pull requests before they merge into production.

<p align="center">
  <a href="https://github.com/apps/dependency-impact-analyzer">
    <img src="https://img.shields.io/badge/GitHub%20App-1--Click%20Install-2ea44f?style=for-the-badge&logo=github" alt="Install GitHub App" />
  </a>
</p>

---

## Overview

Automated dependency tools such as Dependabot and Renovate generate frequent upgrade pull requests. However, standard CI pipelines and semantic versioning assumptions often fail to detect:
- Silent breaking changes undocumented in minor or patch releases
- Removed APIs, renamed parameters, and altered function signatures
- Active deprecations that break downstream packages
- Incompatible runtime constraints (e.g. dropped Python version support)

The **Dependency Upgrade Risk Agent** intercepts incoming pull requests, fetches upstream release notes from official sources, and combines deterministic static Python AST analysis with Google Gemini models to produce an authoritative compatibility evaluation:

- **`NO_RISK_FOUND`**: Verified backwards-compatible upgrade with clean AST and release evidence.
- **`REVIEW`**: Missing documentation, ambiguous API surface changes, or unexercised deprecations requiring human review.
- **`RISKY`**: Attributable breaking changes, removed APIs, or signature alterations directly affecting repository code.

The agent posts an in-PR markdown report with direct links to official documentation and creates a **GitHub Check Run** to gate the pull request merge button.

---

## System Architecture

The service is deployed on Google Cloud Platform as a serverless, event-driven pipeline:

```mermaid
flowchart TD
    subgraph GitHub ["GitHub Platform"]
        PR["Pull Request Event<br/>(Dependabot / Renovate)"]
        Checks["GitHub Check Run<br/>(Physical Merge Gating)"]
        Comment["In-PR Markdown Comment<br/>(Idempotent Upsert)"]
    end

    subgraph GCP ["Google Cloud Platform (Serverless)"]
        CR["Cloud Run Webhook<br/>(FastAPI + uv)"]
        SM["Secret Manager<br/>(RS256 JWT & Webhook Secret)"]
        FS["Firestore<br/>(Deduplication & Audit Trail)"]
        MA["Model Armor & Security Shield<br/>(Ingress Tripwire)"]
        AST["Python AST Engine<br/>(Callsite Blast Radius)"]
        Fetcher["Release Note Fetcher<br/>(PyPI & Official Docs)"]
        Vertex["Google Vertex AI<br/>(Gemini 3.1 Flash-Lite)"]
        Policy["Deterministic Policy Engine<br/>(Non-Decreasing Risk Floor)"]
    end

    PR -->|"Webhook (HMAC-SHA256)"| CR
    SM -.->|"App Auth & Secrets"| CR
    CR -->|"1. Deduplicate Delivery"| FS
    CR -->|"2. Scan Ingress Metadata"| MA
    MA -->|"3. Clean Release Notes"| Fetcher
    Fetcher -->|"4. Verbatim Prompt"| Vertex
    CR -->|"5. Scan Repository Files"| AST
    Vertex -->|"6. Verified Claims (>= 6 tokens)"| Policy
    AST -->|"7. Matched Code Usages"| Policy
    Policy -->|"8. Evaluate: max(floor, llm)"| CR
    CR -->|"9. Post / Update Report"| Comment
    CR -->|"10. Gate Merge (Pass / Fail)"| Checks
```

### Core Architecture Components

- **GitHub App Multi-Tenant Auth (Public & Private Repos):** Signs RS256 JSON Web Tokens (JWT) using a private key in **Google Cloud Secret Manager** and exchanges them for short-lived, repo-scoped installation tokens — supporting both public and private repositories while parsing `.py` source files strictly in-memory without cloning to disk or sending private source code to the LLM.
- **Ingress & Egress Security Shield:** Protects the pipeline end-to-end inside both `webhook/app.py` and `RiskAgentPipeline` (`pipeline.py`) by running regional **Google Cloud Model Armor** (`sanitize_user_prompt` + `sanitize_model_response`, `pr-security-shield`, fail-closed) as the primary security engine alongside Unicode/NFKC & Base64/URL normalization, SDP de-identification & directive quarantine, and a non-decreasing security policy floor (`injection_detected` or `model_armor_error` blocks `NO_RISK_FOUND`).
- **Python AST Static Analyzer:** Parses repository source code in-memory, detecting direct calls, attribute accesses, and aliased imports with confidence tiers (`HIGH`, `MEDIUM`, `LOW`).
- **Grounded Verification Engine:** Pulls changelogs from allowlisted sources (PyPI JSON API, official docs) and verifies that quotes extracted by Gemini match the original text verbatim before claims can influence risk policy.
- **Deterministic Risk Floor:** Enforces a non-decreasing floor (`Final Verdict = max(Risk Floor, LLM Verdict)`) ensuring that verified physical code breakages can never be hallucinated away.
- **Merge Gating via GitHub Checks:** Publishes check run results directly to the commit SHA with `conclusion: "failure"` for risky updates and `conclusion: "success"` for clean updates.

---

## Why Hybrid Analysis?

Pure deterministic linters and raw zero-shot LLM prompts each break down on real dependency upgrades:

1. **Deterministic AST Analysis Alone:**
   - Static AST scanners inspect syntax and import call sites, but cannot interpret natural-language release notes to distinguish safe additions or bug fixes from breaking signature changes.
   - Flagging every upgrade simply because a package is imported overwhelms developers with false-positive alerts.

2. **Direct LLM Prompts Alone:**
   - Ungrounded single-prompt evaluations can hallucinate non-existent API removals, misclassify safe patch bumps, or silently downgrade risk when misled by prompt injections in pull request metadata or upstream notes.

3. **Hybrid Architecture (AST Blast Radius + Verified Gemini Extraction + Risk Floor):**
   - **Deterministic Risk Floor:** Final decisions are bounded by physical code and policy evidence (`Final Verdict = max(Risk Floor, LLM Verdict)`), so the model can escalate discovered risk but can never override verified breakages down to `NO_RISK_FOUND`.
   - **Verbatim Quote Verification:** Every breaking or deprecation claim extracted by Gemini must match a verbatim substring (>= 6 tokens) from allowlisted upstream release documentation before affecting the verdict.
   - **End-to-End Prompt Injection Defense:** **Google Cloud Model Armor** (`fail_closed`, regional inspection on user prompts and model responses) pairs with Unicode/NFKC normalization, Base64/Hex/URL decoding, `<RELEASE_NOTES_DATA>` prompt isolation, and a security floor (`injection_detected` blocks auto-approval).

---

## Baseline & Security Evaluation Reports

Detailed methodology, datasets, baseline comparisons, and empirical metrics live in the standalone evaluation reports:

- **[`reports/upgrade_risk_benchmark_report.md`](reports/upgrade_risk_benchmark_report.md)** — **5-Way Baseline & Upgrade Risk Evaluation (`PyRiskBench`):** Live Vertex AI comparison across SemVer heuristic, Green CI parity, Pure AST analysis, Direct Single LLM, and the Hybrid Risk Agent across curated fixtures and real dependency PRs.
- **[`reports/prompt_injection_benchmark_report.md`](reports/prompt_injection_benchmark_report.md)** — **Prompt Injection & Security Shield Evaluation ([`CloneGuard`](https://github.com/prodnull/cloneguard) by [`prodnull`](https://github.com/prodnull), Apache-2.0):** Adversarial prompt-injection recall and benign false-positive benchmarking for local normalization heuristics paired with Google Cloud Model Armor (`N = 539`).

---

## Live Demos & Examples of Operation

Live public repositories connected to **[`dependency-impact-analyzer`](https://github.com/apps/dependency-impact-analyzer)** (publicly viewable pull requests with live bot comments and Check Runs):

| Live Demo PR | Package Upgrade | Final Verdict (`Risk Floor`) | Shield / AST Hits | Check Run |
| :--- | :--- | :---: | :--- | :---: |
| **[`billing-config-demo#1`](https://github.com/Madhesh4124/billing-config-demo/pull/1)** | `attrs` `23.2.0 -> 24.1.0` (`MAJOR`) | **`RISKY`** (`RISKY`) | Model Armor `clean` · **3 `HIGH` AST usages** (`src/billing/settings.py`) | **`FAILURE`** |
| **[`billing-config-demo#2`](https://github.com/Madhesh4124/billing-config-demo/pull/2)** | `attrs` `23.2.0 -> 24.1.0` (`MAJOR`) + stealth HTML/French/Base64 jailbreak | **`RISKY`** (`RISKY`) | **`model_armor+local_heuristic`** (`pi_and_jailbreak:HIGH`) · **3 `HIGH` AST usages** | **`FAILURE`** *(Required check)* |
| **[`billing-config-demo#3`](https://github.com/Madhesh4124/billing-config-demo/pull/3)** | `httpx` `0.28.0 -> 0.28.1` (`PATCH`) | **`NO_RISK_FOUND`** (`NO_RISK_FOUND`) | Model Armor `clean` · 0 broken calls (`URLTypes` verified `NON_BREAKING`) | **`SUCCESS`** *(Required check)* |
| **[`dependency-impact-test-app#4`](https://github.com/Madhesh4124/dependency-impact-test-app/pull/4)** | `pydantic` `1.10.12 -> 2.6.0` (`MAJOR`) | **`RISKY`** (`NO_RISK_FOUND`) | Model Armor `clean` · 6 verified quotes | **`FAILURE`** |
| **[`dependency-impact-test-app#2`](https://github.com/Madhesh4124/dependency-impact-test-app/pull/2)** | `requests` `2.28.0 -> 2.28.2` (`PATCH`) | **`NO_RISK_FOUND`** (`NO_RISK_FOUND`) | Model Armor `clean` · 0 broken calls | **`SUCCESS`** |
| **[`dependency-impact-test-app#3`](https://github.com/Madhesh4124/dependency-impact-test-app/pull/3)** | `requests` `2.28.0 -> 2.29.0` (`MINOR`) + jailbreak | **`REVIEW`** (`REVIEW`) | **`model_armor+local_heuristic`** (`pi_and_jailbreak:HIGH`) | **`NEUTRAL`** |

### Example 1: Major Version Upgrade Blocked with Live AST Blast Radius (`RISKY`)

**Live PR:** **[`Madhesh4124/billing-config-demo#1`](https://github.com/Madhesh4124/billing-config-demo/pull/1)** — updates `attrs` from `23.2.0` to `24.1.0` in a repo calling `attrs.evolve(inst=cfg, ...)` (`src/billing/settings.py`), which breaks under `24.1.0` (`inst` became positional-only).

#### In-PR Bot Report (Screenshot from Live Run):

![PR #1 Dependency Impact: HIGH RISK Report](docs/images/demo_pr1_attrs_report.png)

#### GitHub Check Run Gate (`FAILURE`):

![PR #1 Failing GitHub Check Run](docs/images/demo_pr1_check_failing.png)

> [!NOTE]
> **Branch Protection Note:** In the PR #1 check screenshot above, GitHub displays *"Some non-required checks are failing"* because `Dependency Upgrade Risk Analysis` was not yet toggled as a required status check at the moment that PR #1 screenshot was captured. Once enabled under **Settings > Branches > Require status checks to pass before merging** -> **`Dependency Upgrade Risk Analysis`**, GitHub locks merging with **Required checks failing** (shown live in **Example 3** below).

---

### Example 2: Clean Patch Upgrade Passed (`NO_RISK_FOUND`)

**Live PR:** **[`Madhesh4124/billing-config-demo#3`](https://github.com/Madhesh4124/billing-config-demo/pull/3)** — bumps `httpx` from `0.28.0` to `0.28.1`. The agent fetches upstream release notes (`pypi.org/project/httpx/0.28.1/`), verifies `URLTypes` is a `NON_BREAKING` fix with clickable link to the official `httpx` changelog, confirms zero affected calls in `src/billing/client.py`, passes Model Armor (`clean`), and marks the required **`Dependency Upgrade Risk Analysis`** check as `SUCCESS` (**Ready to merge**).

#### In-PR Bot Report (Screenshot from Live Run):

![PR #3 Dependency Impact: NO_RISK_FOUND Report](docs/images/demo_pr3_httpx_report.png)

#### GitHub Check Run Gate (`SUCCESS` — Required Check Passing):

![PR #3 Required Check Passing and Ready to Merge](docs/images/demo_pr3_httpx_ready_to_merge.png)

*(See also **[`Madhesh4124/dependency-impact-test-app#2`](https://github.com/Madhesh4124/dependency-impact-test-app/pull/2)** for an additional passing patch evaluation on `requests` `2.28.0 -> 2.28.2` (`NO_RISK_FOUND` / `SUCCESS`).)*

---

### Example 3: Stealth Adversarial Prompt Injection Quarantined & Merge Blocked (`RISKY` & `REVIEW`)

**Live PR (Breaking Upgrade + Hidden Override):** **[`Madhesh4124/billing-config-demo#2`](https://github.com/Madhesh4124/billing-config-demo/pull/2)** — upgrades `attrs` (`23.2.0 -> 24.1.0`) while concealing a French jailbreak and Base64-encoded override inside an HTML comment (`<!-- ... -->`) in the PR description so human reviewers only see *"Routine maintenance bump for billing config."*

1. **Stealth Attack Hidden in Raw PR Markdown:**

   ![PR #2 Stealth Injection Payload in HTML Comment](docs/images/demo_pr2_stealth_payload.png)

2. **Security Tripwire Quarantines Attack + Deterministic Risk Floor Locks Verdict at `RISKY`:**
   Google Cloud Model Armor (`pi_and_jailbreak:HIGH`, `MODEL_ARMOR_FLAGGED`) + local normalization/Base64 decoding (`model_armor+local_heuristic`) neutralize the payload, while verified changelog quotes and 3 `HIGH`-confidence AST hits keep **Risk Floor = `RISKY`**:

   ![PR #2 Security Tripwire and HIGH RISK Report](docs/images/demo_pr2_injection_quarantined.png)

3. **Required Check Enforced (`1 required failing` — Merge Button Disabled):**
   With branch protection requiring **`Dependency Upgrade Risk Analysis`**, the hidden comment remains invisible in the PR description while GitHub physically disables **Merge pull request**:

   ![PR #2 Required Check Failing and Merge Disabled](docs/images/demo_pr2_required_check_blocked.png)

*(See also **[`Madhesh4124/dependency-impact-test-app#3`](https://github.com/Madhesh4124/dependency-impact-test-app/pull/3)** for a non-breaking `requests` `2.28.0 -> 2.29.0` upgrade carrying an English `SYSTEM OVERRIDE` payload, which Model Armor + local heuristics safely quarantine at `REVIEW` / `NEUTRAL` Check Run.)*

---

## Installation & Setup

Install the Dependency Upgrade Risk Agent on any **public or private** GitHub repository in 2 minutes.

> [!NOTE]
> **Private Repository Support:** The agent works on private repositories out of the box using scoped GitHub App installation tokens (`Contents: Read`, `Pull requests: Read & Write`, `Checks: Read & Write`). Private `.py` files stay strictly in Cloud Run memory for local AST scanning and are never sent to Gemini (only package names, versions, and public PyPI release notes are sent to Vertex AI). Note that enforcing branch-protection merge locks on private repos requires GitHub Pro/Team/Enterprise, whereas PR comments and Check Runs work on all plans.

### Step 1: Install the GitHub App

1. Navigate to the official GitHub App page:
   **[https://github.com/apps/dependency-impact-analyzer](https://github.com/apps/dependency-impact-analyzer)**
2. Click **Install**.
3. Select whether to install the agent on **All repositories** or **Only select repositories**.
4. Click **Install & Authorize**.

### Step 2: (Recommended) Enforce Physical Merge Gating

By default, GitHub allows repository administrators to merge pull requests even if automated checks fail. To physically lock the green merge button on risky dependency updates:

1. In your repository on GitHub, go to **Settings** > **Branches**.
2. Under **Branch protection rules**, click **Add branch protection rule** (or edit your existing rule for `main`).
3. Set **Branch name pattern** to `main` (or your default branch).
4. Check **Require status checks to pass before merging**.
5. In the search box, find and select **`Dependency Upgrade Risk Analysis`**.
6. Click **Save changes**.

Whenever an update introduces breaking changes, GitHub will lock the merge button and display **"Merging is blocked"** until the issues are resolved.

---

## Local Development & Testing

### Prerequisites

- Python 3.12+
- [`uv`](https://github.com/astral-sh/uv) package manager

### Running Tests

```bash
# Install dependencies
uv sync

# Run all unit tests
uv run pytest tests/unit

# Run GitHub App webhook integration tests
uv run pytest tests/integration/test_phase6_github_app_webhook.py

# Run full test suite with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache 2.0 License.
