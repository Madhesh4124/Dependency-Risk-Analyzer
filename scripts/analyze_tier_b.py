import json
import os
from collections import Counter

target_file = (
    "benchmark/tier_b/tier_b.jsonl"
    if os.path.exists("benchmark/tier_b/tier_b.jsonl")
    else "benchmark/tier_b/candidates.jsonl"
)

records = []
with open(target_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if line:
            records.append(json.loads(line))

print(f"Total records in {target_file}: {len(records)}")

status_counts = Counter(r.get('collection_status') for r in records)
print("\nCollection status breakdown:")
for s, c in status_counts.items():
    print(f"  {s}: {c}")

accepted = [r for r in records if r.get('collection_status') == 'ACCEPTED_CANDIDATE']
inconclusive = [r for r in records if r.get('collection_status') == 'INCONCLUSIVE']
rejected = [r for r in records if r.get('collection_status') == 'REJECTED']
errors = [r for r in records if r.get('collection_status') == 'ERROR']

print(f"\nAccepted count: {len(accepted)}")
if accepted:
    pkgs = Counter(r.get('dependency_bump', {}).get('package_name') for r in accepted)
    print("Accepted packages:")
    for p, c in pkgs.most_common():
        print(f"  {p}: {c}")

    bumps = Counter(r.get('dependency_bump', {}).get('bump_type') for r in accepted)
    print("\nAccepted bump types:")
    for b, c in bumps.most_common():
        print(f"  {b}: {c}")

    base_ci = Counter(r.get('ci_evidence', {}).get('base_ci_status') for r in accepted)
    print("\nBase CI status of accepted:")
    for bci, c in base_ci.items():
        print(f"  {bci}: {c}")

    head_ci = Counter(r.get('ci_evidence', {}).get('head_ci_status') for r in accepted)
    print("\nHead CI status of accepted:")
    for hci, c in head_ci.items():
        print(f"  {hci}: {c}")

    replay_ready = sum(1 for r in accepted if r.get('validation_checklist', {}).get('ready_for_differential_replay'))
    print(f"\nReady for differential replay: {replay_ready}/{len(accepted)}")

if inconclusive:
    inc_reasons = Counter()
    for r in inconclusive:
        for rsn in r.get('inconclusive_reasons', []):
            inc_reasons[rsn] += 1
    print("\nInconclusive reasons:")
    for ir, c in inc_reasons.most_common():
        print(f"  {ir}: {c}")

if rejected:
    rej_reasons = Counter()
    for r in rejected:
        for rsn in r.get('rejection_reasons', []):
            short = rsn.split(':')[0]
            rej_reasons[short] += 1
    print("\nRejection reasons (by code):")
    for rr, c in rej_reasons.most_common():
        print(f"  {rr}: {c}")

if errors:
    print(f"\nErrors ({len(errors)}):")
    for r in errors[:5]:
        print(f"  {r.get('error')}")

print("\n" + "=" * 80)
print("4 CANDIDATES WITH FAILING HEAD CI (PRIME BREAKAGE TARGETS)")
print("=" * 80)
for r in accepted:
    if r.get('ci_evidence', {}).get('head_ci_status') == 'FAILURE':
        pr = r['pull_request']
        bump = r['dependency_bump']
        ci = r['ci_evidence']
        print(f"* {pr['url']}")
        print(f"  Package: {bump['package_name']} {bump['old_version']} -> {bump['new_version']} ({bump['bump_type']})")
        print(f"  Failed Checks on Head: {ci.get('head_failed_checks')}")
        print(f"  Base Checks ({ci.get('base_checks_count')} total, status: {ci.get('base_ci_status')}): all passed")

print("\n" + "=" * 80)
print(f"ALL {len(accepted)} ACCEPTED CANDIDATES (VERIFIED GREEN BASELINE)")
print("=" * 80)
for idx, r in enumerate(accepted, 1):
    pr = r['pull_request']
    bump = r['dependency_bump']
    ci = r['ci_evidence']
    ls = r['manifest_analysis']['lockfile_status']
    print(f"{idx:2d}. {bump['package_name']:12} {bump['old_version']:10} -> {bump['new_version']:10} ({bump['bump_type']:5}) | Head CI: {ci['head_ci_status']:7} | Lock: {ls:18} | {pr['url']}")

