import os
import subprocess
import tempfile
import shutil
import sys

def inspect_repo(name, git_url, base_sha, head_sha, pkg, old_v, new_v):
    print(f"\n=======================================================")
    print(f"Testing Candidate: {name}")
    print(f"URL: {git_url}")
    print(f"Package: {pkg} {old_v} -> {new_v}")
    print(f"Base SHA: {base_sha}")
    
    td = tempfile.mkdtemp(prefix=f"test_{name}_")
    try:
        # Clone
        res = subprocess.run(["git", "clone", "--depth", "50", git_url, td], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"Clone failed: {res.stderr}")
            return False
            
        # Checkout base
        res = subprocess.run(["git", "checkout", base_sha], cwd=td, capture_output=True, text=True)
        if res.returncode != 0:
            # fetch base_sha specifically if shallow clone missed it
            subprocess.run(["git", "fetch", "--depth", "100", "origin", base_sha], cwd=td, capture_output=True)
            res = subprocess.run(["git", "checkout", base_sha], cwd=td, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"Checkout base failed: {res.stderr}")
                return False

        # List files
        files = os.listdir(td)
        print("Root files:", [f for f in files if not f.startswith(".")][:15])
        
        # Check tests
        test_indicators = []
        for root, dirs, fnames in os.walk(td):
            if ".git" in root or ".venv" in root:
                continue
            for f in fnames:
                if f.startswith("test_") or f.endswith("_test.py"):
                    test_indicators.append(os.path.relpath(os.path.join(root, f), td))
        print(f"Discovered {len(test_indicators)} test files: {test_indicators[:5]}")
        
        # Check manifest
        for m in ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock"]:
            mp = os.path.join(td, m)
            if os.path.exists(mp):
                print(f"Found manifest: {m}")

        return True
    finally:
        shutil.rmtree(td, ignore_errors=True)

if __name__ == "__main__":
    targets = [
        ("duckbot", "https://github.com/duck-dynasty/duckbot.git", "1318eb7a90c6dad31af9c21cd9efd6009d6795d7", "a702d3adec658d59d3d2ef5cc234f343a82c11fe", "sqlalchemy", "2.1.1", "2.1.6"),
        ("synthetic_control", "https://github.com/Maar10Herr/Synthetic-Control-Robustness-Envelopes-Public.git", "938d255f3ba199f5f6b7170b0e039cd18484b7cd", "18fe812ca33f28b0f91d9640d2f347736d0567f0", "numpy", "2.5.2", "2.5.3"),
        ("credit_arena", "https://github.com/shaikn6/credit-arena.git", "f9d0bddea4b3eadef41150edb3e76f25aa7d20d4", "375f87a7246ee48a5132c84bcc849be63bc248fe", "pandas", "3.0.6", "3.1.0"),
        ("datacommons_mcp", "https://github.com/cfdude/datacommons-mcp.git", "7708db64d124f853e1771a676f1c362d794144bd", "05bc0fc18b797e1b73395bc0d5a9495a3317dbdc", "cryptography", "46.0.7", "50.0.0"),
        ("markten", "https://github.com/COMP1010UNSW/Markten.git", "19cf39ba67b848c9096ce1019672ebdd92e10696", "40f31641fca4e8df5e8c156f8f7004f14bfba52c", "click", "8.4.2", "8.5.0"),
        ("siganalysis", "https://github.com/questrail/siganalysis.git", "619cf310f85fa71516fecf9bc367469a914da761", "102830f30c9f13458fae72dc0da0d1e57c66cb1e", "numpy", "2.5.2", "2.5.3"),
        ("jubilant", "https://github.com/canonical/jubilant.git", "4b325255470d0577dae8125cf3f5ce6f962b8004", "a4a35cf91d8bbd52e50cf6aa1ff76baec11d61c6", "cryptography", "50.0.1", "50.0.2"),
    ]
    for t in targets:
        inspect_repo(*t)

