# Tier B Automated Benchmark Collector (GCP Architecture)

This component automates the harvesting, differential analysis, and labeling of real-world GitHub dependency-upgrade PRs for the **Tier B Benchmark**.

For complete step-by-step GCP setup instructions, refer to [**`guide.md`**](../../guide.md) in the project root.

---

## Architecture Flow

```
   [Cloud Scheduler]  (Daily or On-Demand Cron Trigger)
          │
          ▼
   [GCP Workflows]    (workflow.yaml)
          │
          ├─► Query GitHub REST API (Search for closed dependency bump PRs)
          ├─► Filter candidate PR list
          │
          ▼
   [Cloud Run Job]    (job/main.py)
          │
          ├─► Verify Python repository
          ├─► Verify exactly one dependency bumped
          ├─► Validate semantic versions (packaging library)
          ├─► Detect lockfile & transitive dependency churn
          ├─► Capture full commit SHAs and metadata
          ├─► Assign label: PENDING_VALIDATION
          │
          ├────────────────────────┬────────────────────────┐
          ▼                                                 ▼
   [Cloud Storage]                                   [Cloud Firestore]
(gs://.../tier_b_candidates.jsonl)             (Collection: tier_b_candidates)
```

---

## Directory Structure

```
infra/collector/
├── job/
│   ├── main.py            # Batch PR metadata & git diff validator
│   ├── requirements.txt   # httpx, packaging, google-cloud-storage, firestore
│   └── Dockerfile         # Container image definition for Cloud Run Job
├── workflow.yaml          # GCP Workflows definition
└── README.md              # Component documentation
```

---

## Local Verification

To run and verify the batch job validation logic locally:

```bash
python scripts/test_collector_local.py
```


