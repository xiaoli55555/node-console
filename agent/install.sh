#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo '请以 root 运行'; exit 1; }
command -v systemctl >/dev/null || { echo '需要 systemd'; exit 1; }
# Quick enrollment uses an expiring single-use ticket from the environment.
# Interactive mode remains available as a fallback.
PANEL_URL=${PANEL_URL:-}
INSTALL_TICKET=${HK_SDAN_TICKET:-}
if [[ -z "$PANEL_URL" ]]; then
  read -rp '面板 HTTPS 地址（例如 https://panel.example.com）: ' PANEL_URL
fi
[[ "$PANEL_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]] || { echo '请输入不含路径的 HTTPS 域名'; exit 1; }
if [[ -z "$INSTALL_TICKET" ]]; then
  read -rsp '服务器专属接入密钥: ' AGENT_TOKEN; echo
  [[ ${#AGENT_TOKEN} -ge 40 ]] || { echo '密钥不正确'; exit 1; }
else
  [[ "$INSTALL_TICKET" =~ ^[A-Za-z0-9_-]{40,128}$ ]] || { echo '一次性接入凭证格式错误'; exit 1; }
fi
apt-get update
apt-get install -y python3 curl ca-certificates conntrack iproute2

umask 077
mkdir -p /opt/hk-sdan-agent /etc/hk-sdan-agent
TMP_AGENT=$(mktemp); trap 'rm -f "$TMP_AGENT"' EXIT
curl --fail --silent --show-error --proto '=https' --tlsv1.2 "${PANEL_URL%/}/agent.py" -o "$TMP_AGENT"
python3 -m py_compile "$TMP_AGENT"
if [[ -n "$INSTALL_TICKET" ]]; then
  export PANEL_URL INSTALL_TICKET
  AGENT_TOKEN=$(python3 - <<'ENROLL_PY'
import os,json,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
request=urllib.request.Request(os.environ['PANEL_URL'].rstrip('/')+'/api/agent/enroll',
    data=json.dumps({'ticket':os.environ['INSTALL_TICKET']}).encode(),headers={'Content-Type':'application/json'},method='POST')
try:
    with urllib.request.build_opener(NoRedirect).open(request,timeout=20) as response:
        result=json.loads(response.read(4096))
    if not isinstance(result.get('token'),str) or len(result['token'])<40:raise ValueError()
    print(result['token'])
except Exception:
    raise SystemExit('一次性接入失败，请检查面板连通性或重新生成接入命令')
ENROLL_PY
  )
  unset INSTALL_TICKET HK_SDAN_TICKET
fi
install -m 700 "$TMP_AGENT" /opt/hk-sdan-agent/agent.py
export PANEL_URL AGENT_TOKEN
python3 - <<'PY'
import os,json
from pathlib import Path
p=Path('/etc/hk-sdan-agent/config.json.tmp')
p.write_text(json.dumps({'url':os.environ['PANEL_URL'],'token':os.environ['AGENT_TOKEN']}));p.chmod(0o600);p.replace(p.with_name('config.json'))
PY
unset AGENT_TOKEN
cat > /etc/systemd/system/hk-sdan-agent.service <<'EOF'
[Unit]
Description=Node Console monitoring and reboot agent
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/hk-sdan-agent/agent.py
Restart=always
RestartSec=15
User=root
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_BOOT
StateDirectory=hk-sdan-agent
StateDirectoryMode=0700
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now hk-sdan-agent
systemctl restart hk-sdan-agent
echo '客户端已安装，资源每 5 秒上报，TCP／UDP 每 15 秒采集；查看状态：systemctl status hk-sdan-agent'
