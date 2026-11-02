# GCP Web Console Step-by-Step Guide: Tier B Benchmark Collector

> **Purpose:** This guide walks you through setting up the entire automated pipeline **100% inside the Google Cloud Console web interface** (no CLI required).

---

## 🏗️ Architecture Overview

```
[Cloud Scheduler]  (Triggers daily / on demand)
       │
       ▼
[GCP Workflows]    (Discovers PRs via GitHub API & coordinates tasks)
       │
       ▼
[Cloud Run Job]    (Batch diff analysis & validation)
       │
       ├─────────────────────────┬─────────────────────────┐
       ▼                                                   ▼
[Cloud Storage Bucket]                              [Cloud Firestore]
(tier_b_candidates.jsonl)                         (Collection: tier_b_candidates)
```

---

## 📋 Prerequisites Before You Begin

1. Log in to [Google Cloud Console](https://console.cloud.google.com/).
2. Select your active GCP Project from the top project dropdown.
3. Have your **GitHub Personal Access Token** ready (copy it from GitHub $\rightarrow$ Settings $\rightarrow$ Developer settings $\rightarrow$ Personal access tokens).

---

## Step 1: Enable the Required APIs

1. In the GCP Console top search bar, type **APIs & Services** and select **Library**.
2. Search and click **Enable** for each of these 6 services (if not already enabled):
   * **Workflows API**
   * **Cloud Run Admin API**
   * **Cloud Scheduler API**
   * **Cloud Storage** (Google Cloud Storage JSON API)
   * **Cloud Firestore API**
   * **Secret Manager API**

---

## Step 2: Create the Cloud Storage Bucket

*(This will store the final `tier_b_candidates.jsonl` dataset)*

1. In the top search bar, search for **Cloud Storage** and click **Buckets**.
2. Click the **+ CREATE** button at the top.
3. Fill in the bucket settings:
   * **Name your bucket:** Enter a unique name, e.g., `your-project-id-benchmark-data`.
   * **Location type:** Choose **Region** $\rightarrow$ select `us-central1 (Iowa)` (or your preferred region).
   * **Storage class:** Leave as **Standard**.
   * **Prevent public access:** Keep **Enforce public access prevention on this bucket** checked.
   * **Access control:** Select **Uniform**.
4. Click **CREATE**.

---

## Step 3: Create the Firestore Database

*(This stores indexed metadata for candidate PRs)*

1. In the top search bar, search for **Firestore**.
2. If prompted to choose a database mode, select **Firestore Native Mode** (Do *not* choose Datastore mode).
3. Set the database details:
   * **Database ID:** Leave as `(default)`.
   * **Location:** Choose the same region as your bucket (e.g. `us-central1`).
4. Click **CREATE DATABASE**.

---

## Step 4: Store Your GitHub Token in Secret Manager

*(Keeps your GitHub token secure with zero credentials stored in code)*

1. In the top search bar, search for **Secret Manager** and click it.
2. Click **+ CREATE SECRET** at the top.
3. Configure the secret:
   * **Name:** `github-token`
   * **Secret value:** Paste your GitHub Personal Access Token into the box.
   * **Replication:** Leave as **Automatic**.
4. Click **CREATE SECRET**.

---

## Step 5: Create a Dedicated Service Account with Least Privilege

*(Gives Workflows and Cloud Run permissions to talk to Storage, Firestore, and Secrets)*

1. In the top search bar, search for **IAM & Admin** and select **Service Accounts**.
2. Click **+ CREATE SERVICE ACCOUNT** at the top.
3. **Step 1 (Details):**
   * **Service account name:** `tier-b-collector-sa`
   * **Description:** Service account for Tier B automated benchmark collector.
   * Click **CREATE AND CONTINUE**.
4. **Step 2 (Grant access to project):**
   * Add each of the following roles using the **+ ADD ANOTHER ROLE** button:
     * `Cloud Run Developer` *(to run the batch job)*
     * `Storage Object Admin` *(to write JSONL files to the bucket)*
     * `Cloud Datastore User` *(to write documents to Firestore)*
     * `Secret Manager Secret Accessor` *(to read the github-token)*
     * `Workflows Invoker` *(to run workflow steps)*
     * `Service Account User` *(to act as this service account)*
5. Click **CONTINUE**, then click **DONE**.

---

## Step 6: Create the Cloud Run Job

*(Performs the batch PR diff parsing and validation)*

1. In the top search bar, search for **Cloud Run**.
2. In the left navigation pane, click on the **Jobs** tab (make sure it's **Jobs**, not Services).
3. Click **+ CREATE JOB** at the top.
4. Configure the Job:
   * **Job name:** `tier-b-collector-job`
   * **Region:** `us-central1` (same as bucket).
5. **Container Image:**
   * Under Container, enter the pre-built collector image, or click **Deploy from source repository** if you connected your Git repo, or enter:
     `gcr.io/cloudrun/hello` *(temporary placeholder until built)*.
6. **Job Capacity & Settings:**
   * **Task timeout:** `15 minutes` (900 seconds).
   * **Number of retries:** `1`.
7. Expand **Container, Volumes, Networking, Security**:
   * **Service Account:** Under the *Security* tab, select `tier-b-collector-sa`.
   * **Environment Variables:** Under the *Variables & Secrets* tab, click **+ ADD VARIABLE**:
     * Name: `GCS_BUCKET_NAME` | Value: `your-project-id-benchmark-data`
     * Name: `FIRESTORE_PROJECT_ID` | Value: `your-gcp-project-id`
   * **Secrets:** Under *Secrets*, click **REFERENCE A SECRET**:
     * Secret: `github-token`
     * Reference method: **Expose as environment variable**
     * Environment variable name: `GITHUB_TOKEN`
     * Version: `latest`
8. Click **CREATE**.

---

## Step 7: Create the GCP Workflow

*(Discovers PRs via GitHub Search API and triggers the Cloud Run Job)*

1. In the top search bar, search for **Workflows** and select it.
2. Click **+ CREATE** at the top.
3. **Step 1: Workflow details:**
   * **Workflow name:** `tier-b-collector-workflow`
   * **Region:** `us-central1`
   * **Service account:** Select `tier-b-collector-sa`.
   * Click **NEXT**.
4. **Step 2: Define your workflow:**
   * You will see a code editor with a YAML template.
   * **Delete the placeholder code** and paste the entire contents of [**`infra/collector/workflow.yaml`**](file:///d:/CODE/Projects/V/infra/collector/workflow.yaml):

```yaml
main:
  params: [args]
  steps:
    - init:
        assign:
          - projectId: ${sys.get_env("GOOGLE_CLOUD_PROJECT_ID")}
          - region: "asia-south1"
          - jobName: "tier-b-collector-job"
          - queryPackages: ["fastapi", "sqlalchemy", "httpx", "cryptography", "numpy", "pandas", "click", "redis"]
          - candidateUrls: []
          - githubAuthHeader: ""

    - checkOverrides:
        switch:
          - condition: ${args != null and "region" in args}
            assign:
              - region: ${args.region}
          - condition: ${args != null and "jobName" in args}
            assign:
              - jobName: ${args.jobName}
          - condition: ${args != null and "queryPackages" in args}
            assign:
              - queryPackages: ${args.queryPackages}

    - tryLoadSecret:
        try:
          steps:
            - accessSecret:
                call: googleapis.secretmanager.v1.projects.secrets.versions.access
                args:
                  name: ${"projects/" + projectId + "/secrets/github-token/versions/latest"}
                result: secretResp
            - setAuthHeader:
                assign:
                  - githubAuthHeader: ${"Bearer " + text.decode(base64.decode(secretResp.payload.data))}
        except:
          as: err
          steps:
            - ignoreSecretError:
                assign:
                  - githubAuthHeader: ""

    - iteratePackages:
        for:
          value: pkg
          in: ${queryPackages}
          steps:
            - searchGitHub:
                call: http.get
                args:
                  url: "https://api.github.com/search/issues"
                  headers:
                    User-Agent: "GCP-Workflows-Collector/2.0"
                    Accept: "application/vnd.github.v3+json"
                    Authorization: ${githubAuthHeader}
                  query:
                    q: ${"is:pr is:closed \"Bump " + pkg + " from\" in:title"}
                    sort: "updated"
                    order: "desc"
                    per_page: 10
                result: searchResponse

            - filterCandidates:
                for:
                  value: item
                  in: ${searchResponse.body.items}
                  steps:
                    - appendUrl:
                        assign:
                          - candidateUrls: ${list.concat(candidateUrls, [item.html_url])}

            - pauseToRespectRateLimits:
                call: sys.sleep
                args:
                  seconds: 2

    - checkCandidatesFound:
        switch:
          - condition: ${len(candidateUrls) == 0}
            return:
              status: "NO_CANDIDATES_FOUND"

    - triggerCloudRunJob:
        call: googleapis.run.v2.projects.locations.jobs.run
        args:
          name: ${"projects/" + projectId + "/locations/" + region + "/jobs/" + jobName}
          body:
            overrides:
              containerOverrides:
                - env:
                    - name: "CANDIDATE_PR_URLS"
                      value: ${json.encode_to_string(candidateUrls)}
        result: jobExecution

    - waitJobCompletion:
        call: googleapis.run.v2.projects.locations.jobs.executions.get
        args:
          name: ${jobExecution.name}
        result: executionStatus

    - finish:
        return:
          status: "SUCCESS"
          candidates_dispatched: ${len(candidateUrls)}
          job_execution: ${jobExecution.name}
```

5. Click **DEPLOY**.

---

## Step 8: Set Up Cloud Scheduler (Daily or On-Demand Trigger)

1. In the top search bar, search for **Cloud Scheduler**.
2. Click **+ CREATE JOB** at the top.
3. Configure the trigger:
   * **Name:** `tier-b-daily-trigger`
   * **Region:** `us-central1`
   * **Frequency:** `0 2 * * *` *(runs daily at 2:00 AM UTC)*
   * **Timezone:** Select `UTC` or your local timezone.
4. Click **CONTINUE**.
5. **Configure the execution target:**
   * **Target type:** Select **Workflows**.
   * **Workflow:** Select `tier-b-collector-workflow`.
   * **Location:** `us-central1`.
   * **Auth header:** Select **Add OAuth token**.
   * **Service account:** Select `tier-b-collector-sa`.
6. Click **CREATE**.

---

## 🎮 How to Test & View Results in the Console

### 1. Run the Workflow Manually (One Click)
1. Go to **Workflows** in the GCP Console.
2. Click on **`tier-b-collector-workflow`**.
3. Click the **EXECUTE** button at the top $\rightarrow$ click **EXECUTE** again on the confirmation modal.
4. You will see an interactive visual execution graph turning green step-by-step as it searches GitHub and triggers your Cloud Run Job.

### 2. View Cloud Run Job Logs
1. Go to **Cloud Run** $\rightarrow$ **Jobs** $\rightarrow$ Click **`tier-b-collector-job`**.
2. Click on the latest execution in the **Executions** tab.
3. Click **LOGS** to see live output as it checks each PR, verifies single-dependency bumps, and outputs `PENDING_VALIDATION` candidate records.

### 3. Download the Dataset from Cloud Storage
1. Go to **Cloud Storage** $\rightarrow$ **Buckets** $\rightarrow$ Click on `your-project-id-benchmark-data`.
2. Open the **`tier_b/`** folder.
3. Click on **`tier_b_candidates.jsonl`** $\rightarrow$ Click **DOWNLOAD** or view it directly in the console.

### 4. View Metadata in Firestore
1. Go to **Firestore** $\rightarrow$ **Databases** $\rightarrow$ `(default)`.
2. Under Data, click on the **`tier_b_candidates`** collection.
3. Each document represents a candidate PR with its verified commit SHAs, package versions, and `PENDING_VALIDATION` status.

---

## 💰 Keeping It Free

This setup runs within GCP's **Always Free Tier**:
* **Workflows:** First 5,000 steps/month are $0.
* **Cloud Run Jobs:** Billed only for the 30–60 seconds the task runs (360,000 vCPU-seconds free per month).
* **Storage & Firestore:** Few megabytes of storage ($0).
* **Scheduler:** 3 free scheduler jobs per billing account.
