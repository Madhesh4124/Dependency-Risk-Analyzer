import os
import shutil
import subprocess
import tempfile
import sys

candidates = [
    {
        "name": "python_markdown_environments",
        "url": "https://github.com/AnonymousRand/python_markdown_environments.git",
        "pr_num": 41,
        "base_sha": "f10beea0b91e7790b4bf7ee2418e285d8848d88e",
        "pkg": "cryptography",
        "old_v": "50.0.0",
        "new_v": "50.0.2"
    },
    {
        "name": "ha_holos_tts",
        "url": "https://github.com/ALERTua/ha-holos-tts.git",
        "pr_num": 35,
        "base_sha": "eb48e89f78310ba0e7a17726487eec82f50f2832",
        "pkg": "fastapi",
        "old_v": "0.143.0",
        "new_v": "0.156.8"
    },
    {
        "name": "ai_engineering",
        "url": "https://github.com/EVanderSchel/ai-engineering.git",
        "pr_num": 134,
        "base_sha": "865bc99f8a74a5f731c6b92e28d395352a3d36f7",
        "pkg": "fastapi",
        "old_v": "0.161.1",
        "new_v": "0.162.0"
    },
    {
        "name": "canonical_jubilant",
        "url": "https://github.com/canonical/jubilant.git",
        "pr_num": 446,
        "base_sha": "4b325255470d0577dae8125cf3f5ce6f962b8004",
        "pkg": "cryptography",
        "old_v": "50.0.1",
        "new_v": "50.0.2"
    }
]

for cand in candidates:
    print(f"\n=======================================================")
    print(f"Evaluating {cand['name']} (PR #{cand['pr_num']})")
    td = tempfile.mkdtemp(prefix=f"test_{cand['name']}_")
    try:
        res = subprocess.run(["git", "clone", cand["url"], td], capture_output=True, text=True)
        if res.returncode != 0:
            print("Clone failed:", res.stderr)
            continue
        # fetch PR ref
        subprocess.run(["git", "fetch", "origin", f"pull/{cand['pr_num']}/head:pr-{cand['pr_num']}"], cwd=td, capture_output=True)
        
        # checkout base
        subprocess.run(["git", "checkout", cand["base_sha"]], cwd=td, capture_output=True)
        
        # check test files
        test_files = []
        for root, dirs, fnames in os.walk(td):
            if ".git" in root or ".venv" in root:
                continue
            for f in fnames:
                if f.startswith("test_") or f.endswith("_test.py"):
                    test_files.append(os.path.relpath(os.path.join(root, f), td))
        print(f"Discovered test files ({len(test_files)}): {test_files[:5]}")
        
        # Test base
        print("Running tests on base...")
        res_base = subprocess.run(["uv", "run", "--with", "pytest", "pytest", "-q"], cwd=td, capture_output=True, text=True)
        print("Base test returncode:", res_base.returncode)
        print("Base test output:\n", (res_base.stdout + res_base.stderr)[:400])
        
        # Test head
        subprocess.run(["git", "checkout", f"pr-{cand['pr_num']}"], cwd=td, capture_output=True)
        print("Running tests on head...")
        res_head = subprocess.run(["uv", "run", "--with", "pytest", "pytest", "-q"], cwd=td, capture_output=True, text=True)
        print("Head test returncode:", res_head.returncode)
        print("Head test output:\n", (res_head.stdout + res_head.stderr)[:400])
    finally:
        shutil.rmtree(td, ignore_errors=True)

