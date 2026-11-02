import os
import shutil
import subprocess
import sys
import tempfile

td = tempfile.mkdtemp(prefix='credit_')
try:
    print("Cloning credit-arena...")
    subprocess.run(['git', 'clone', 'https://github.com/shaikn6/credit-arena.git', td], check=True, capture_output=True)
    subprocess.run(['git', 'fetch', 'origin', 'pull/11/head:pr-11'], cwd=td, check=True, capture_output=True)
    subprocess.run(['git', 'checkout', 'f9d0bddea4b3eadef41150edb3e76f25aa7d20d4'], cwd=td, check=True, capture_output=True)
    
    print("Generating data.csv...")
    gen_code = """
from sklearn.datasets import fetch_openml
d = fetch_openml(data_id=42477, as_frame=True, parser='auto')
d.data.assign(target=d.target).to_csv('data.csv', index=False)
"""
    with open(os.path.join(td, 'make_data.py'), 'w') as f:
        f.write(gen_code)

    res_gen = subprocess.run(['uv', 'run', '--with', 'scikit-learn', '--with', 'pandas==3.0.6', 'python', 'make_data.py'], cwd=td, capture_output=True, text=True)
    print("Data gen exit code:", res_gen.returncode)
    if res_gen.returncode != 0:
        print("Data gen stderr:", res_gen.stderr)

    print("\n--- Running tests with pandas==3.0.6 (baseline) ---")
    env = os.environ.copy()
    env["PYTHONPATH"] = td
    res_old = subprocess.run([
        'uv', 'run', '--with', 'pytest', '--with', 'pandas==3.0.6', '--with', 'numpy==2.5.4',
        '--with', 'scikit-learn==1.9.1', '--with', 'scipy==1.18.1', 'python', '-m', 'pytest', '-v'
    ], cwd=td, env=env, capture_output=True, text=True)
    print("Old pandas return code:", res_old.returncode)
    print("Old pandas stdout:\n", res_old.stdout)
    if res_old.stderr:
        print("Old pandas stderr:\n", res_old.stderr)

    print("\n--- Running tests with pandas==3.1.0 (PR upgrade) ---")
    res_new = subprocess.run([
        'uv', 'run', '--with', 'pytest', '--with', 'pandas==3.1.0', '--with', 'numpy==2.5.4',
        '--with', 'scikit-learn==1.9.1', '--with', 'scipy==1.18.1', 'python', '-m', 'pytest', '-v'
    ], cwd=td, env=env, capture_output=True, text=True)
    print("New pandas return code:", res_new.returncode)
    print("New pandas stdout:\n", res_new.stdout)
    if res_new.stderr:
        print("New pandas stderr:\n", res_new.stderr)

finally:
    shutil.rmtree(td, ignore_errors=True)

