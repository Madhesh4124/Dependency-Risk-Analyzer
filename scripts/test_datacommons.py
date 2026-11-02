import os
import shutil
import subprocess
import tempfile

td = tempfile.mkdtemp(prefix='dc_')
try:
    print("Cloning datacommons-mcp...")
    subprocess.run(['git', 'clone', 'https://github.com/cfdude/datacommons-mcp.git', td], check=True, capture_output=True)
    subprocess.run(['git', 'fetch', 'origin', 'pull/62/head:pr-62'], cwd=td, check=True, capture_output=True)
    subprocess.run(['git', 'checkout', '7708db64d124f853e1771a676f1c362d794144bd'], cwd=td, check=True, capture_output=True)
    
    with open(os.path.join(td, 'pyproject.toml')) as f:
        print("pyproject.toml content:")
        print(f.read()[:600])

    # Check diff
    res_diff = subprocess.run(['git', 'diff', '7708db64d124f853e1771a676f1c362d794144bd', 'pr-62', '--', 'pyproject.toml'], cwd=td, capture_output=True, text=True)
    print("pyproject diff:\n", res_diff.stdout)

    print("\n--- Running tests with uv run pytest (baseline) ---")
    res_base = subprocess.run(['uv', 'run', '--with', 'pytest', 'pytest', '-q'], cwd=td, capture_output=True, text=True)
    print("Base exit:", res_base.returncode)
    print("Base stdout:\n", res_base.stdout[:1000])

    # Checkout pr-62
    subprocess.run(['git', 'checkout', 'pr-62'], cwd=td, check=True, capture_output=True)
    print("\n--- Running tests with uv run pytest (upgraded pr-62) ---")
    res_head = subprocess.run(['uv', 'run', '--with', 'pytest', 'pytest', '-q'], cwd=td, capture_output=True, text=True)
    print("Head exit:", res_head.returncode)
    print("Head stdout:\n", res_head.stdout[:1000])
finally:
    shutil.rmtree(td, ignore_errors=True)

