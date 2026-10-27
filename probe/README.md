# 自建检测点

在国内 Linux 设备安装 Python 3。每个“自建探针”来源仅部署一个进程；地区和运营商在来源名称中标注。该探针只检测 TCP 连接，不判断封锁、不执行重启。

将 `probe.py` 放到 `/opt/hksdan-probe/probe.py`。创建 `/etc/hksdan-probe.json`，权限设为 `600`：

```json
{"panel_url":"https://你的面板域名","token":"创建自建探针时显示的密钥"}
```

使用 systemd 服务（按实际 Python 路径调整，不需要 root 运行）：

```ini
[Unit]
Description=HKSDAN TCP Probe
After=network-online.target
Wants=network-online.target

[Service]
Restart=always
RestartSec=10
DynamicUser=yes
LoadCredential=probe-config:/etc/hksdan-probe.json
ExecStart=/usr/bin/python3 /opt/hksdan-probe/probe.py %d/probe-config
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

保存为 `/etc/systemd/system/hksdan-probe.service`，执行 `systemctl daemon-reload` 和 `systemctl enable --now hksdan-probe`。查看状态：`systemctl status hksdan-probe`。密钥丢失时新建来源、切换计划，再删除旧来源。面板需要具有有效证书的 HTTPS 地址。探针绕过系统代理环境变量，直接从本机网络检测。
