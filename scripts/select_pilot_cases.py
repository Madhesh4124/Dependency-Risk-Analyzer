import json

with open("benchmark/tier_b/candidates.jsonl", "r", encoding="utf-8") as f:
    recs = [
        json.loads(line)
        for line in f
        if line.strip() and json.loads(line).get("collection_status") == "ACCEPTED_CANDIDATE"
    ]

print(f"Total accepted candidates: {len(recs)}")

failing = [r for r in recs if r.get("ci_evidence", {}).get("head_ci_status") == "FAILURE"]
passing = [r for r in recs if r.get("ci_evidence", {}).get("head_ci_status") == "SUCCESS"]

print(f"Failing head CI candidates ({len(failing)}):")
for r in failing:
    p = r["pull_request"]
    b = r["dependency_bump"]
    ci = r["ci_evidence"]
    print(f"  * URL: {p['url']}")
    print(f"    Pkg: {b['package_name']} {b['old_version']} -> {b['new_version']} ({b['bump_type']})")
    print(f"    MergeBase SHA: {p.get('merge_base_sha') or p.get('base_sha')}")
    print(f"    Head SHA:      {p.get('head_sha')}")
    print(f"    Failed Checks: {ci.get('head_failed_checks')}")
    print(f"    Lockfile:      {r['manifest_analysis']['lockfile_status']}")
    print()

print(f"Top passing head CI candidates ({len(passing)}):")
for r in passing[:10]:
    p = r["pull_request"]
    b = r["dependency_bump"]
    ci = r["ci_evidence"]
    print(f"  * URL: {p['url']}")
    print(f"    Pkg: {b['package_name']} {b['old_version']} -> {b['new_version']} ({b['bump_type']})")
    print(f"    MergeBase SHA: {p.get('merge_base_sha') or p.get('base_sha')}")
    print(f"    Head SHA:      {p.get('head_sha')}")
    print(f"    Lockfile:      {r['manifest_analysis']['lockfile_status']}")
    print()

