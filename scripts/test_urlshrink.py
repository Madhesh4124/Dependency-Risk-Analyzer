import os
import shutil
import subprocess
import tempfile

td = tempfile.mkdtemp(prefix='urlshrink_')
try:
    print("Cloning urlshrink...")
    subprocess.run(['git', 'clone', 'https://github.com/moveeeax/urlshrink.git', td], check=True, capture_output=True)
    subprocess.run(['git', 'fetch', 'origin', 'pull/29/head:pr-29'], cwd=td, check=True, capture_output=True)
    subprocess.run(['git', 'checkout', 'f065cdee49a70d9e894ffd528ccf99180e3d20c6'], cwd=td, check=True, capture_output=True)

    env = os.environ.copy()
    env["PYTHONPATH"] = td

    print("\n--- Testing base commit with SQLAlchemy==2.0.51 ---")
    res_base = subprocess.run([
        'uv', 'run',
        '--with', 'fastapi==0.162.0',
        '--with', 'starlette==1.3.1',
        '--with', 'pydantic==2.14.1',
        '--with', 'uvicorn==0.51.0',
        '--with', 'SQLAlchemy==2.0.51',
        '--with', 'pytest==9.1.1',
        '--with', 'httpx==0.28.1',
        'python', '-m', 'pytest', '-v'
    ], cwd=td, env=env, capture_output=True, text=True)
    print("Base exit code:", res_base.returncode)
    print("Base stdout:\n", res_base.stdout)
    if res_base.stderr:
        print("Base stderr:\n", res_base.stderr)

    print("\n--- Testing upgraded commit (pr-29) with SQLAlchemy==2.1.6 ---")
    subprocess.run(['git', 'checkout', 'pr-29'], cwd=td, check=True, capture_output=True)
    res_head = subprocess.run([
        'uv', 'run',
        '--with', 'fastapi==0.162.0',
        '--with', 'starlette==1.3.1',
        '--with', 'pydantic==2.14.1',
        '--with', 'uvicorn==0.51.0',
        '--with', 'SQLAlchemy==2.1.6',
        '--with', 'pytest==9.1.1',
        '--with', 'httpx==0.28.1',
        'python', '-m', 'pytest', '-v'
    ], cwd=td, env=env, capture_output=True, text=True)
    print("Head exit code:", res_head.returncode)
    print("Head stdout:\n", res_head.stdout)
    if res_head.stderr:
        print("Head stderr:\n", res_head.stderr)

finally:
    shutil.rmtree(td, ignore_errors=True)

