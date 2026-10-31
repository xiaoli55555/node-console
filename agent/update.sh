#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo '请以 root 运行'; exit 1; }
[[ -f /etc/hk-sdan-agent/config.json ]] || { echo '请先安装客户端'; exit 1; }
PANEL_URL=$(python3 - <<'PY'
import json
from urllib.parse import urlsplit
c=json.load(open('/etc/hk-sdan-agent/config.json'));u=c['url'].rstrip('/');p=urlsplit(u)
if p.scheme!='https' or p.username or p.password or p.query or p.fragment or p.path:raise SystemExit('面板地址格式不正确')
print(u)
PY
)
apt-get update
apt-get install -y python3 curl ca-certificates conntrack iproute2
TEMP_AGENT=$(mktemp); trap 'rm -f "$TEMP_AGENT"' EXIT
curl -fsS --proto '=https' --tlsv1.2 "$PANEL_URL/agent.py" -o "$TEMP_AGENT"
python3 -m py_compile "$TEMP_AGENT"
install -m 700 "$TEMP_AGENT" /opt/hk-sdan-agent/agent.py
mkdir -p /etc/systemd/system/hk-sdan-agent.service.d
cat > /etc/systemd/system/hk-sdan-agent.service.d/capabilities.conf <<'EOF'
[Service]
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_BOOT
EOF
systemctl daemon-reload
systemctl restart hk-sdan-agent
echo '客户端已更新，原接入密钥和配置已保留。'
