import subprocess
import tempfile
import shutil
import os

td = tempfile.mkdtemp()
try:
    venv_path = os.path.join(td, ".venv")
    subprocess.run(["uv", "venv", "--python", "3.11", venv_path], check=True, capture_output=True)
    
    # Try old numpy 2.4.6
    print("Testing old numpy 2.4.6:")
    res_old = subprocess.run([
        "uv", "pip", "install", "--dry-run", "--python", os.path.join(venv_path, "Scripts", "python.exe"),
        "streamlit==1.66.1", "pandas==3.1.0", "numpy==2.4.6", "openpyxl==3.1.5",
        "anthropic==2.3.0", "scipy==1.17.1", "plotly==7.1.0"
    ], capture_output=True, text=True)
    print("Old exit:", res_old.returncode)
    print("Old stderr:\n", res_old.stderr[:500])

    # Try new numpy 2.5.4
    print("Testing new numpy 2.5.4:")
    res_new = subprocess.run([
        "uv", "pip", "install", "--dry-run", "--python", os.path.join(venv_path, "Scripts", "python.exe"),
        "streamlit==1.66.1", "pandas==3.1.0", "numpy==2.5.4", "openpyxl==3.1.5",
        "anthropic==2.3.0", "scipy==1.17.1", "plotly==7.1.0"
    ], capture_output=True, text=True)
    print("New exit:", res_new.returncode)
    print("New stderr:\n", res_new.stderr[:500])

finally:
    shutil.rmtree(td, ignore_errors=True)
