import json

with open('benchmark/tier_b/pilot.json', 'r', encoding='utf-8') as f:
    d = json.load(f)

print("Keys:", list(d.keys()))
print("Cases count:", len(d['pilot_cases']))
print("Exclusion controls count:", len(d['exclusion_controls']))
for c in d['pilot_cases']:
    cid = c['case_id']
    repo = c['repository']
    pkg = c['dependency']['package_name']
    old_v = c['dependency']['old_version']
    new_v = c['dependency']['new_version']
    lbl = c['label_verdict']['label']
    conf = c['label_verdict']['confidence']
    print(f"{cid}: {repo} | {pkg} {old_v} -> {new_v} | Label: {lbl} (Confidence: {conf})")

for ex in d['exclusion_controls']:
    cid = ex['control_id']
    repo = ex['repository']
    rule = ex['exclusion_rule']
    print(f"{cid}: {repo} | Excluded under {rule}")

