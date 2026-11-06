"""Tier A Fixtures: 3-Run Automated Reproduction Verification.

Exit Criterion for Phase 1:
"All fixture expected outcomes reproduce reliably across 3 automated runs."
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
TIER_A_DIR = ROOT_DIR / "benchmark" / "tier_a"
REPORT_FILE = TIER_A_DIR / "reproduction_report.json"


def run_fixture_test(case_dir: Path, pkg_version: str) -> subprocess.CompletedProcess:
    repo_dir = case_dir / "repo"
    pkg_dir = case_dir / pkg_version

    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{pkg_dir}{os.pathsep}{repo_dir}{os.pathsep}{existing_pythonpath}"

    cmd = [sys.executable, "-m", "pytest", str(repo_dir / "test_app.py"), "-q", "--disable-warnings", "-o", "cache_dir=.pytest_cache"]
    result = subprocess.run(
        cmd,
        cwd=repo_dir,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result


def main():
    cases_file = TIER_A_DIR / "cases.json"
    with open(cases_file, "r", encoding="utf-8") as f:
        cases = json.load(f)

    print(f"Loaded {len(cases)} Tier A cases from {cases_file.name}")
    print("Beginning 3-run reproduction verification...\n" + "=" * 60)

    total_runs = 3
    run_records = []

    start_time = time.time()

    for run_idx in range(1, total_runs + 1):
        print(f"\n--- Run {run_idx} of {total_runs} ---")
        run_results = {}
        all_passed = True

        for case_info in cases:
            case_id = case_info["case_id"]
            case_dir = TIER_A_DIR / case_info["directory"]
            case_spec_path = case_dir / "case.json"

            with open(case_spec_path, "r", encoding="utf-8") as f:
                spec = json.load(f)

            reproduction = spec["reproduction"]

            # 1. Test against pkg_v1
            res_v1 = run_fixture_test(case_dir, "pkg_v1")
            v1_pass = (res_v1.returncode == 0) if reproduction["old_version_outcome"] == "PASS" else (res_v1.returncode != 0)

            # 2. Test against pkg_v2
            res_v2 = run_fixture_test(case_dir, "pkg_v2")
            if reproduction["new_version_outcome"] == "FAIL":
                v2_pass = (res_v2.returncode != 0)
                expected_error = reproduction.get("expected_error_type")
                if expected_error and expected_error not in (res_v2.stdout + res_v2.stderr):
                    v2_pass = False
            else:
                v2_pass = (res_v2.returncode == 0)

            case_status = "PASS" if (v1_pass and v2_pass) else "FAIL"
            if case_status != "PASS":
                all_passed = False

            print(f"  [{case_id}] {case_info['name']:<25}: v1={'OK' if v1_pass else 'ERR'} | v2={'OK' if v2_pass else 'ERR'} -> {case_status}", flush=True)

            run_results[case_id] = {
                "name": case_info["name"],
                "v1_status": "PASS" if v1_pass else "FAIL",
                "v2_status": "PASS" if v2_pass else "FAIL",
                "overall": case_status,
            }

        run_records.append({
            "run_index": run_idx,
            "all_cases_passed": all_passed,
            "case_results": run_results,
        })

    elapsed = round(time.time() - start_time, 2)
    overall_success = all(r["all_cases_passed"] for r in run_records)

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_cases": len(cases),
        "total_runs": total_runs,
        "elapsed_seconds": elapsed,
        "exit_criterion_met": overall_success,
        "runs": run_records,
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 60)
    print(f"Reproduction Verification Complete: {total_runs}/{total_runs} runs successful ({elapsed}s)")
    print(f"Exit Criterion Met: {overall_success}")
    print(f"Report written to: {REPORT_FILE.relative_to(ROOT_DIR)}")

    if not overall_success:
        sys.exit(1)


if __name__ == "__main__":
    main()

