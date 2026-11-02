import os
import shutil
import subprocess
import tempfile

candidates = [
    {
        "name": "cmccomb_scrape",
        "url": "https://github.com/cmccomb/scrape-my-publications.git",
        "pr_num": 27,
        "base_sha": "52ba440da31c440a7cf49a05a5a1f6534e79391d",
        "pkg": "pandas",
        "old_v": "3.0.6",
        "new_v": "3.1.0"
    },
    {
        "name": "dmpinero_gestor",
        "url": "https://github.com/dmpinero/gestor-gastos-personal.git",
        "pr_num": 162,
        "base_sha": "d0be13d6a9787ffdafa9959600a943a4e92ebfce",
        "pkg": "pandas",
        "old_v": "3.0.5",
        "new_v": "3.0.6"
    },
    {
        "name": "cloudblue_librql",
        "url": "https://github.com/cloudblue/lib-rql.git",
        "pr_num": 25,
        "base_sha": "f1cfb350616a246aa1d62c1404c0bcbf5614eb58",
        "pkg": "click",
        "old_v": "8.1.3",
        "new_v": "8.5.0"
    },
    {
        "name": "urlshrink",
        "url": "https://github.com/moveeeax/urlshrink.git",
        "pr_num": 29,
        "base_sha": "5e13ee3fa48cb644bc4032c5896a60db2fa955f2",
        "pkg": "sqlalchemy",
        "old_v": "2.0.51",
        "new_v": "2.1.6"
    },
    {
        "name": "espinoso_mentorship",
        "url": "https://github.com/espinoso/mentorshipMatchingApp.git",
        "pr_num": 4,
        "base_sha": "9e69e1c6409fdc44ccc39dbb1ed2edd81597bb7d",
        "pkg": "numpy",
        "old_v": "2.4.6",
        "new_v": "2.5.4"
    },
    {
        "name": "sebiweise_homeward",
        "url": "https://github.com/sebiweise/homeward.git",
        "pr_num": 61,
        "base_sha": "8e272910bc593db1b07fcbb337fc20dae522e35c",
        "pkg": "cryptography",
        "old_v": "48.0.1",
        "new_v": "50.0.0"
    }
]

for cand in candidates:
    print(f"\n=======================================================")
    print(f"Evaluating {cand['name']} ({cand['pkg']} {cand['old_v']}->{cand['new_v']})")
    td = tempfile.mkdtemp(prefix=f"test_{cand['name']}_")
    try:
        res = subprocess.run(["git", "clone", "--depth", "50", cand["url"], td], capture_output=True, text=True)
        if res.returncode != 0:
            print("Clone failed:", res.stderr)
            continue
        
        # Checkout base
        res = subprocess.run(["git", "checkout", cand["base_sha"]], cwd=td, capture_output=True, text=True)
        if res.returncode != 0:
            subprocess.run(["git", "fetch", "--depth", "100", "origin", cand["base_sha"]], cwd=td, capture_output=True)
            subprocess.run(["git", "checkout", cand["base_sha"]], cwd=td, capture_output=True)

        # Look for test files
        test_files = []
        for root, dirs, fnames in os.walk(td):
            if ".git" in root or ".venv" in root:
                continue
            for f in fnames:
                if f.startswith("test_") or f.endswith("_test.py"):
                    test_files.append(os.path.relpath(os.path.join(root, f), td))
        print(f"Found {len(test_files)} test files: {test_files[:5]}")
        if not test_files:
            print("No test files found, skipping.")
            continue

        # Try base test
        res_base = subprocess.run(["uv", "run", "--with", "pytest", "python", "-m", "pytest", "-q"], cwd=td, capture_output=True, text=True)
        print(f"Base exit code: {res_base.returncode}")
        print(f"Base output: {(res_base.stdout + res_base.stderr)[:300]}")
    finally:
        shutil.rmtree(td, ignore_errors=True)

