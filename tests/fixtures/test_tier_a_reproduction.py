"""Automated reproduction verification for Tier A ground-truth fixtures.

Ensures that every fixture case reproduces its expected outcome:
- Passes against pkg_v1
- Produces the exact expected failure or success against pkg_v2
"""

import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

TIER_A_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "tier_a"


def load_tier_a_cases():
    """Loads all Tier A case specifications from cases.json."""
    index_file = TIER_A_DIR / "cases.json"
    if not index_file.exists():
        pytest.skip(f"Tier A cases index not found at {index_file}")
    with open(index_file, "r", encoding="utf-8") as f:
        return json.load(f)


TIER_A_CASES = load_tier_a_cases()


def run_fixture_test(case_dir: Path, pkg_version: str) -> subprocess.CompletedProcess:
    """Executes repo/test_app.py with the specified package version in PYTHONPATH."""
    repo_dir = case_dir / "repo"
    pkg_dir = case_dir / pkg_version

    env = os.environ.copy()
    # Prepend pkg_dir and repo_dir to PYTHONPATH
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{pkg_dir}{os.pathsep}{repo_dir}{os.pathsep}{existing_pythonpath}"

    cmd = [sys.executable, "-m", "pytest", str(repo_dir / "test_app.py"), "-q", "--disable-warnings"]
    result = subprocess.run(
        cmd,
        cwd=repo_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result


@pytest.mark.parametrize("case_info", TIER_A_CASES, ids=[c["case_id"] for c in TIER_A_CASES])
def test_tier_a_fixture_reproduction(case_info):
    """Verifies that the fixture deterministically reproduces expected outcomes on v1 and v2."""
    case_dir = TIER_A_DIR / case_info["directory"]
    case_spec_path = case_dir / "case.json"
    assert case_spec_path.exists(), f"case.json missing in {case_dir}"

    with open(case_spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)

    reproduction = spec["reproduction"]

    # 1. Test against pkg_v1
    res_v1 = run_fixture_test(case_dir, "pkg_v1")
    if reproduction["old_version_outcome"] == "PASS":
        assert res_v1.returncode == 0, (
            f"Expected PASS on pkg_v1 for {spec['case_id']}, but got code {res_v1.returncode}.\n"
            f"STDOUT:\n{res_v1.stdout}\nSTDERR:\n{res_v1.stderr}"
        )

    # 2. Test against pkg_v2
    res_v2 = run_fixture_test(case_dir, "pkg_v2")
    if reproduction["new_version_outcome"] == "FAIL":
        assert res_v2.returncode != 0, (
            f"Expected FAIL on pkg_v2 for {spec['case_id']}, but test unexpectedly PASSED.\n"
            f"STDOUT:\n{res_v2.stdout}"
        )
        expected_error = reproduction.get("expected_error_type")
        if expected_error:
            combined_output = res_v2.stdout + res_v2.stderr
            assert expected_error in combined_output, (
                f"Expected error '{expected_error}' not found in output for {spec['case_id']}.\n"
                f"Output:\n{combined_output}"
            )
    elif reproduction["new_version_outcome"] == "PASS":
        assert res_v2.returncode == 0, (
            f"Expected PASS on pkg_v2 for {spec['case_id']}, but got code {res_v2.returncode}.\n"
            f"STDOUT:\n{res_v2.stdout}\nSTDERR:\n{res_v2.stderr}"
        )

