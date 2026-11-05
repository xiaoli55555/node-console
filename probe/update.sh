#!/bin/bash
# Run as root on each probe server after the panel has been updated.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo '请使用 root 执行'; exit 1; }
[[ -f /etc/hksdan-probe.json ]] || { echo '缺少 /etc/hksdan-probe.json，请先配置节点密钥'; exit 1; }
install -d -m 755 /opt/hksdan-probe
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT
curl -fL --connect-timeout 15 --max-time 120 --retry 2 \
  https://raw.githubusercontent.com/xiaoli55555/node-console/main/probe/probe.py \
  -o "$task_tmp/probe.py"
python3 -m py_compile "$task_tmp/probe.py"
# Download and validate before stopping the existing worker.
if [[ -f /opt/hksdan-probe/probe.py ]]; then
  cp -p /opt/hksdan-probe/probe.py /opt/hksdan-probe/probe.py.backup
fi
install -d -m 755 /etc/systemd/system/hksdan-probe.service.d
printf '[Service]\nStateDirectory=hksdan-probe\n' > /etc/systemd/system/hksdan-probe.service.d/state.conf
chmod 644 /etc/systemd/system/hksdan-probe.service.d/state.conf
systemctl stop hksdan-probe
install -m 644 "$task_tmp/probe.py" /opt/hksdan-probe/probe.py
systemctl daemon-reload
systemctl reset-failed hksdan-probe
systemctl start hksdan-probe
systemctl status hksdan-probe --no-pager
