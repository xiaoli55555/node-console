#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo '请以 root 运行'; exit 1; }
source /etc/os-release
[[ "$ID" == debian ]] || { echo '此安装脚本面向 Debian'; exit 1; }
if [[ -f .env ]]; then
  echo '检测到已有配置。更新请执行 bash scripts/update.sh；重设管理员请执行 bash scripts/admin.sh。'
  exit 1
fi
read -rp '面板域名（先解析到本机 IP，例如 panel.example.com，不含 https://）: ' PANEL_DOMAIN
[[ "$PANEL_DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]] || { echo '域名格式不正确'; exit 1; }
if ! command -v docker >/dev/null; then
  apt-get update
  apt-get install -y curl ca-certificates
  DOCKER_INSTALL=$(mktemp); trap 'rm -f "$DOCKER_INSTALL"' EXIT
  curl -fsS --proto '=https' https://get.docker.com -o "$DOCKER_INSTALL"
  sh "$DOCKER_INSTALL"
  systemctl enable --now docker
fi
docker compose version >/dev/null || { echo '请安装 Docker Compose v2 后重试'; exit 1; }
if command -v ss >/dev/null && ss -H -ltn | awk '{print $4}' | grep -Eq ':(80|443|8080)$'; then
  echo '80、443 或 8080 端口被占用，请检查后重试。'; exit 1
fi
umask 077
printf 'PANEL_DOMAIN=%s\n' "$PANEL_DOMAIN" > .env
echo '构建服务（首次需要下载镜像和依赖）……'
APP_COMMIT=$(git rev-parse HEAD)
export APP_COMMIT
docker compose build --pull
echo '配置管理员账号：'
docker compose run --rm app python server.py admin
docker compose up -d
for attempt in $(seq 1 30); do
  if docker compose exec -T app python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)" >/dev/null 2>&1; then
    echo "安装完成，面板地址：https://$PANEL_DOMAIN"
    echo 'HTTPS 证书首次申请可能需等待 1～2 分钟；请确保域名正确解析且 80/443 可访问。'
    exit 0
  fi
  sleep 2
done
echo '服务未通过健康检查，请执行 docker compose logs --tail=100'; exit 1
