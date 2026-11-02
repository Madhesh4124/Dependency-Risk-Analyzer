import json
import os

target_file = (
    "benchmark/tier_b/tier_b.jsonl"
    if os.path.exists("benchmark/tier_b/tier_b.jsonl")
    else "benchmark/tier_b/candidates.jsonl"
)

with open(target_file, 'r', encoding='utf-8') as f:
    records = [json.loads(line) for line in f if json.loads(line).get('collection_status') == 'ACCEPTED_CANDIDATE']

print(f"Total Accepted: {len(records)}\n")
for i, r in enumerate(records, 1):
    bump = r['dependency_bump']
    pr = r['pull_request']
    repo = r['repository']['full_name']
    url = pr['url']
    merged = pr.get('merged')
    bsha = pr.get('base_sha', '')[:8]
    hsha = pr.get('head_sha', '')[:8]
    print(f"{i:2d}. {repo} #{pr['number']} | {bump['package_name']} {bump['old_version']} -> {bump['new_version']} ({bump['bump_type']}) | Merged: {merged} | Base: {bsha} | Head: {hsha}")

