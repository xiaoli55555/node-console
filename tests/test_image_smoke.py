"""Import the runtime from exactly the files declared in the Docker image."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

class ImageManifestSmoke(unittest.TestCase):
    def test_packaged_runtime_starts_and_serves_probe(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            dest=Path(folder)
            for line in (root/'Dockerfile').read_text().splitlines():
                if not line.startswith('COPY '):continue
                words=shlex.split(line)[1:];target=words[-1]
                for name in words[:-1]:
                    src=root/name
                    output=dest/(src.name if target in ('.','./') else target.lstrip('./'))
                    if src.is_dir():shutil.copytree(src,output,dirs_exist_ok=True)
                    else:shutil.copy2(src,output)
            env=dict(os.environ,DATA_DIR=str(dest/'data'),COOKIE_SECURE='0');env.pop('PYTHONPATH',None)
            result=subprocess.run([sys.executable,'-c',"import server; c=server.app.test_client(); assert c.get('/health').status_code==200; assert c.get('/dns-observer.py').status_code==200"],cwd=dest,env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
