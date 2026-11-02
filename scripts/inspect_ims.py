import os
import shutil
import subprocess
import tempfile

td = tempfile.mkdtemp(prefix='ims_')
try:
    print("Cloning ims...")
    subprocess.run(['git', 'clone', 'https://github.com/sinan-can-demir/ims.git', td], check=True, capture_output=True)
    subprocess.run(['git', 'fetch', 'origin', 'pull/352/head:pr-352'], cwd=td, check=True, capture_output=True)
    subprocess.run(['git', 'checkout', '12e048f3b81911218910fa902b1295ffa01f5cfd'], cwd=td, check=True, capture_output=True)
    
    with open(os.path.join(td, 'requirements.txt')) as f:
        print("requirements.txt:\n", f.read()[:500])

    if os.path.exists(os.path.join(td, 'Makefile')):
        with open(os.path.join(td, 'Makefile')) as f:
            print("Makefile:\n", f.read()[:500])

    diff_res = subprocess.run(['git', 'diff', '12e048f3b81911218910fa902b1295ffa01f5cfd', 'pr-352'], cwd=td, capture_output=True, text=True)
    print("PR diff:\n", diff_res.stdout)

finally:
    shutil.rmtree(td, ignore_errors=True)

