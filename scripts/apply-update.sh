#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
OLD_COMMIT=${1:?Missing previous commit}
[[ "$OLD_COMMIT" =~ ^[0-9a-f]{40}$ ]] || exit 1
APP_COMMIT=$(git rev-parse HEAD)
export APP_COMMIT
if ! docker compose build --pull; then
  echo "构建失败，运行中的旧容器未替换。旧源码版本：$OLD_COMMIT"
  echo "处理构建错误后执行：bash scripts/apply-update.sh $OLD_COMMIT"
  exit 1
fi
docker compose up -d
for attempt in $(seq 1 30); do
  if docker compose exec -T app python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)" >/dev/null 2>&1; then
    echo "更新完成。更新前版本：$OLD_COMMIT；数据库备份位于 backups/";exit 0
  fi
  sleep 2
done
echo "健康检查未通过，请查看 docker compose logs --tail=100。更新前版本：$OLD_COMMIT"
echo '不自动回滚数据库，避免覆盖更新后的数据；请参阅 README 的恢复章节。'
exit 1
