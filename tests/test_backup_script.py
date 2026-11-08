"""Exercise the real backup shell script with Docker transport simulated locally."""
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest


class BackupScript(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name);(self.root/'scripts').mkdir()
        source=Path(__file__).resolve().parents[1]/'scripts/backup.sh'
        shutil.copy2(source,self.root/'scripts/backup.sh')
        self.data=self.root/'data';self.data.mkdir()
        self.db=sqlite3.connect(self.data/'panel.db');self.addCleanup(self.db.close)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE evidence(value TEXT)')
        self.db.execute("INSERT INTO evidence VALUES('committed WAL data')");self.db.commit()
        (self.data/'credential.key').write_bytes(b'k'*44)
        self.bin=self.root/'bin';self.bin.mkdir()
        docker=self.bin/'docker'
        docker.write_text('#!/bin/bash\nset -euo pipefail\n[[ "$1 $2 $3 $4 $5" == "compose exec -T app python" ]]\nshift 5\nexec "$BACKUP_TEST_PYTHON" "$@"\n')
        docker.chmod(0o700)
        # A controlled /tmp-capacity guard: only data-volume temp files fit.
        # This affects the subprocess only, without mounting or filling a disk.
        (self.bin/'sitecustomize.py').write_text('''import os, tempfile, sqlite3
from pathlib import Path
original=tempfile.TemporaryDirectory
def guarded(*args, **kwargs):
    if str(kwargs.get('dir')) != os.environ['DATA_DIR']:
        raise OSError(28, 'simulated /tmp capacity exceeded')
    return original(*args, **kwargs)
tempfile.TemporaryDirectory=guarded
if os.environ.get('BACKUP_TEST_FAIL'):
    connect=sqlite3.connect
    def fail_destination(database, *args, **kwargs):
        if str(database).endswith('/snapshot.db'):
            Path(database).touch()
            raise sqlite3.OperationalError('database or disk is full')
        return connect(database,*args,**kwargs)
    sqlite3.connect=fail_destination
''')
        self.env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                      PYTHONPATH=str(self.bin),DATA_DIR=str(self.data),BACKUP_TEST_PYTHON=sys.executable)

    def run_backup(self,fail=False):
        return subprocess.run(['bash','scripts/backup.sh'],cwd=self.root,
                              env=dict(self.env,**({'BACKUP_TEST_FAIL':'1'} if fail else {})),
                              capture_output=True,text=True,timeout=20)

    def test_backup_uses_data_volume_and_preserves_live_wal_and_key(self):
        result=self.run_backup();self.assertEqual(result.returncode,0,result.stderr)
        backups=list((self.root/'backups').glob('*.db'));self.assertEqual(len(backups),1)
        with sqlite3.connect(backups[0]) as restored:
            self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            self.assertEqual(restored.execute('SELECT value FROM evidence').fetchall(),[('committed WAL data',)])
        key=Path(str(backups[0])+'.key');self.assertEqual(key.read_bytes(),b'k'*44)
        for file in (backups[0],key):self.assertEqual(file.stat().st_mode & 0o777,0o600)
        self.assertFalse(list(self.data.glob('console-backup-*')))
        self.assertFalse(list((self.root/'backups').glob('*.partial')))
        self.assertEqual(self.db.execute('SELECT value FROM evidence').fetchone()[0],'committed WAL data')

    def test_failure_cleans_temporary_files_without_touching_database(self):
        result=self.run_backup(fail=True);self.assertNotEqual(result.returncode,0)
        self.assertIn('database or disk is full',result.stderr)
        self.assertFalse(list(self.data.glob('console-backup-*')))
        self.assertFalse(list((self.root/'backups').iterdir()))
        self.assertEqual(self.db.execute('SELECT value FROM evidence').fetchone()[0],'committed WAL data')
