"""
Merges multiple Tier B candidate batches into a single canonical candidates.jsonl dataset.
- Deduplicates by canonical PR URL.
- Prefers the latest evaluated state from newer batches.
- Strictly enforces: base_ci_status == "SUCCESS" for ACCEPTED_CANDIDATE.
"""

import json
import os
import shutil


def load_records(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def merge_batches():
    candidates_path = "benchmark/tier_b/candidates.jsonl"
    new_batch_path = "benchmark/tier_b/tier_b.jsonl"
    backup_path = "benchmark/tier_b/candidates_batch1.jsonl"

    if os.path.exists(candidates_path) and not os.path.exists(backup_path):
        shutil.copyfile(candidates_path, backup_path)
        print(f"Backed up original candidates to {backup_path}")

    b1 = load_records(candidates_path)
    b2 = load_records(new_batch_path)

    merged = {}
    for r in b1:
        url = r.get("pull_request", {}).get("url") or r.get("case_id")
        # Enforce strict policy on older records
        if (
            r.get("collection_status") == "ACCEPTED_CANDIDATE"
            and r.get("ci_evidence", {}).get("base_ci_status") != "SUCCESS"
        ):
            r["collection_status"] = "INCONCLUSIVE"
            r["inconclusive_reasons"] = list(r.get("inconclusive_reasons", [])) + [
                "INCONCLUSIVE_NO_BASELINE_CI"
            ]
            if "validation_checklist" in r:
                r["validation_checklist"]["ready_for_differential_replay"] = False
        merged[url] = r

    for r in b2:
        url = r.get("pull_request", {}).get("url") or r.get("case_id")
        merged[url] = r

    records = list(merged.values())

    with open(candidates_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    accepted = [r for r in records if r.get("collection_status") == "ACCEPTED_CANDIDATE"]
    print("=" * 60)
    print("TIER B CANONICAL DATASET UPDATE COMPLETED")
    print("=" * 60)
    print(f"Merged output file: {candidates_path}")
    print(f"Total unique records: {len(records)}")
    print(f"Accepted candidates:  {len(accepted)}")
    print(f"100% green base CI:   {all(r.get('ci_evidence', {}).get('base_ci_status') == 'SUCCESS' for r in accepted)}")


if __name__ == "__main__":
    merge_batches()

