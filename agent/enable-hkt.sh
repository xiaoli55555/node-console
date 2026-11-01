#!/bin/bash
set -euo pipefail
export LC_ALL=C
[[ $EUID -eq 0 ]] || { echo '请以 root 运行'; exit 1; }
IFACE=${1:-ens18}
[[ "$IFACE" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$ && -d "/sys/class/net/$IFACE" ]] || { echo '网卡不存在'; exit 1; }
[[ -f /etc/hk-sdan-agent/config.json ]] || { echo '请先安装面板 agent'; exit 1; }
MANAGER=$(python3 /opt/hk-sdan-agent/agent.py --dhcp-detect "$IFACE") || { echo '请先更新 agent，并检查目标网卡的实际 DHCP 管理方式'; exit 1; }
[[ "$MANAGER" == dhclient || "$MANAGER" == dhcpcd ]] || { echo '无法确认 DHCP 管理器'; exit 1; }
# Do not run a second manager on a networkd/NetworkManager-owned NIC.
if systemctl is-active --quiet NetworkManager; then
  echo 'NetworkManager 正在运行，需先确认网卡归属，拒绝自动授权'; exit 1
fi
if systemctl is-active --quiet systemd-networkd; then
  STATE=$(networkctl status "$IFACE" --no-pager 2>/dev/null) || { echo '无法确认网卡管理方式'; exit 1; }
  if ! grep -Eq 'Network File:[[:space:]]+n/a' <<<"$STATE" || ! grep -Eq 'State:.*unmanaged' <<<"$STATE"; then
    echo '网卡由 systemd-networkd 管理，拒绝启用外部 DHCP 操作'; exit 1
  fi
fi
export IFACE MANAGER
umask 077
python3 - <<'PY'
import json,os
from pathlib import Path
p=Path('/etc/hk-sdan-agent/hkt-dhcp.json')
p.write_text(json.dumps({'enabled':True,'interface':os.environ['IFACE'],'cleanup_unscoped':True,'manager':os.environ['MANAGER']}));p.chmod(0o600)
PY
mkdir -p /etc/systemd/system/hk-sdan-agent.service.d
cat > /etc/systemd/system/hk-sdan-agent.service.d/hkt-dhcp.conf <<'EOF'
[Service]
StateDirectory=hk-sdan-agent
StateDirectoryMode=0700
EOF
systemctl daemon-reload
systemctl restart hk-sdan-agent
echo "HKT DHCP 动作已在本机授权：$IFACE（$MANAGER）；本次没有换 IP。请回面板生成 API。"
