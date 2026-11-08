#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p backups
BACKUP_FILE="backups/panel-$(date +%Y%m%d-%H%M%S)-$$.db"
PARTIAL_FILE="$BACKUP_FILE.partial"
KEY_PARTIAL="$BACKUP_FILE.key.partial"
trap 'rm -f "$PARTIAL_FILE" "$KEY_PARTIAL"' EXIT
# Stream a consistent SQLite backup through stdout. docker cp cannot reliably
# retrieve files from the container's tmpfs /tmp on all storage drivers.
# Use the persistent data filesystem: a database may exceed the /tmp tmpfs limit.
docker compose exec -T app python -c '
import os, sqlite3, tempfile, shutil, sys
from pathlib import Path
source_path = Path(os.environ.get("DATA_DIR", "/data")) / "panel.db"
with tempfile.TemporaryDirectory(prefix="console-backup-", dir=source_path.parent) as folder:
    destination = Path(folder) / "snapshot.db"
    with sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, timeout=20) as source, sqlite3.connect(destination) as target:
        source.backup(target)
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Database backup integrity check failed")
    with destination.open("rb") as snapshot:
        shutil.copyfileobj(snapshot, sys.stdout.buffer)
    sys.stdout.buffer.flush()
' > "$PARTIAL_FILE"
[[ -s "$PARTIAL_FILE" ]] || { echo '备份为空，已停止更新'; exit 1; }
[[ "$(head -c 15 "$PARTIAL_FILE")" == 'SQLite format 3' ]] || { echo '备份格式错误，已停止更新'; exit 1; }
chmod 600 "$PARTIAL_FILE"
mv "$PARTIAL_FILE" "$BACKUP_FILE"
# Back up the independent encryption key when present (old images have none).
docker compose exec -T app python -c 'from pathlib import Path; import os,sys; p=Path(os.environ.get("DATA_DIR","/data"))/"credential.key"; sys.stdout.buffer.write(p.read_bytes() if p.exists() else b"")' > "$KEY_PARTIAL"
if [[ -s "$KEY_PARTIAL" ]]; then
  [[ $(wc -c < "$KEY_PARTIAL") -eq 44 ]] || { echo '密码加密密钥备份格式异常，已停止更新'; exit 1; }
  chmod 600 "$KEY_PARTIAL"
  mv "$KEY_PARTIAL" "$BACKUP_FILE.key"
fi
echo "数据库已备份：$BACKUP_FILE（包含密码哈希和会话等敏感数据，请妥善保存）"

