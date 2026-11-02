"""
Local Test Runner for the Cloud Run Job Collector
Tests batch processing and validation of PRs into a local JSONL dataset.
"""

import os
import sys
import subprocess

# Path to Cloud Run Job main.py
job_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "infra", "collector", "job", "main.py"))

test_prs = [
    "https://github.com/openai/openai-python/pull/4068",
    "https://github.com/JanEricNitschke/HanserDownloader/pull/166",
    "https://github.com/ActivityWatch/aw-server/pull/192",
    "https://github.com/Slyfti/TP06-Secure-Code/pull/2"
]

def main():
    print("Testing Cloud Run Job Batch Validator Locally...")
    output_file = "test_tier_b_output.jsonl"
    if os.path.exists(output_file):
        os.remove(output_file)

    env = os.environ.copy()
    env["OUTPUT_FILE_PATH"] = output_file

    cmd = [sys.executable, job_script, "--pr-urls"] + test_prs
    res = subprocess.run(cmd, env=env, text=True, capture_output=True)
    
    print(res.stdout)
    if res.stderr:
        print("STDERR:", res.stderr)

    if os.path.exists(output_file):
        print("\n" + "=" * 70)
        print(f"Generated JSONL Output ({output_file}):")
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                import json
                rec = json.loads(line)
                print(f"\nCase ID: {rec['case_id']}")
                print(f"  Label: {rec['label']} (Provisional: {rec['provisional_signal']})")
                print(f"  Package: {rec['dependency_bump']['package_name']} ({rec['dependency_bump']['old_version']} -> {rec['dependency_bump']['new_version']})")
                print(f"  Checklist: {rec['validation_checklist']}")
        os.remove(output_file)
        print("\n" + "=" * 70)
        print("Local validation test completed successfully.")

if __name__ == "__main__":
    main()
