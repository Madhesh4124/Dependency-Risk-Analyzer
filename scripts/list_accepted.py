import json

with open('benchmark/tier_b/candidates.jsonl') as f:
    candidates = [
        json.loads(line)
        for line in f
        if line.strip() and json.loads(line).get('collection_status') == 'ACCEPTED_CANDIDATE'
    ]

print(f"Total accepted: {len(candidates)}")
for c in candidates:
    pr = c['pull_request']
    b = c['dependency_bump']
    ci = c['ci_evidence']
    url = pr['url']
    pkg = b['package_name']
    old_v = b['old_version']
    new_v = b['new_version']
    bump = b['bump_type']
    base_ci = ci['base_ci_status']
    head_ci = ci['head_ci_status']
    lock = c['manifest_analysis']['lockfile_status']
    print(f"{url} | {pkg} {old_v}->{new_v} ({bump}) | Base: {base_ci} | Head: {head_ci} | Lock: {lock}")

