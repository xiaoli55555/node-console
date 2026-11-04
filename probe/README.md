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

## 快速响应与手动测试

探针默认每 2 秒领取任务；可在配置增加 `"poll_interval_s":2`（1–10 秒）。TCP 每次超时 5 秒，首次不通立即再测一次；任一次握手成功即上报可达，两次都失败才上报不通。仍不据此断言 IP 被封锁。

无需面板密钥即可在探针机器随时运行独立诊断：

```bash
python3 /opt/hksdan-probe/probe.py --test 42.98.101.203 59218
```

输出包含每次尝试的 reachable / refused / timeout / network_error 状态，退出码 0 表示可达，1 表示不通。独立诊断不上传结果，也不触发面板自动操作。

接入步骤：面板“检测来源”添加“自建探针”，将其独立密钥写入配置；在“配置 VPS 检测点”选择该来源及实际业务端口，先设为“只记录结果”和关闭定时检测。保存后使用“立即检测”，面板会下发该 VPS 当前公网 IP。手动检测不会触发重启或换 IP。

先在探针机器验证面板通道：

```bash
curl --connect-timeout 5 --max-time 10 -sS -o /dev/null -w 'HTTP %{http_code}\n' https://hksdan.top/
```

HTTP 响应表明 HTTPS 通道已建立（不代表密钥正确）；连接超时应先解决探针到面板的网络问题。探测目标成功不意味着能连到面板。无需开放探针入站端口。

上报网络异常时保留结果重试，遇已完成/过期的 409 则丢弃，不把上报失败当成目标不通。日志不输出密钥。
