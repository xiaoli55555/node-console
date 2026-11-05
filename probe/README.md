# 自建检测点

在国内 Linux 设备安装 Python 3。每个“自建探针”来源可包含多个节点；每个节点仅部署一个进程，地区和运营商在节点名称中标注。该探针只检测 TCP 连接，不判断封锁、不执行重启。

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

保存为 `/etc/systemd/system/hksdan-probe.service`，执行 `systemctl daemon-reload` 和 `systemctl enable --now hksdan-probe`。查看状态：`systemctl status hksdan-probe`。新增节点的密钥丢失时，可在同一来源新建节点、切换所选节点后删除旧节点；默认节点继续兼容原密钥。面板需要具有有效证书的 HTTPS 地址。探针绕过系统代理环境变量，直接从本机网络检测。

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

## 跨来源复检

在管理员“VPS 独立探测配置”中，首轮来源与复检来源可分别选择。选择“复检来源”，点击“获取复检节点”，再选一个节点保存。支持另一个自建探针来源、BOCE、宝塔及仅记录模式的阿里云来源；相同来源内必须选择不同节点。每个自建节点只部署一台探针，建议节点名称标明地区和网络。

只有定时首轮全部不通，才针对同一 IP 和端口复检。复检可达、未知、离线、超时或配置已变化均不触发故障动作。涉及第三方时继续校验参照站；两台自建探针互相复检时，不虚构参照站结果，会明确标注未执行参照站校验。不同探针不一定处于不同网络，部署时应自行选择不同运营商或出口。

旧探针可直接领取跨来源复检任务，无需更换密钥。任务的负数 ID 属于独立复检，仍使用原有领取与上报接口；每个结果严格绑定探针、目标和当前配置。自动故障转移会同时继承首轮及复检配置。

检测周期最低可设置 60 秒，默认仍为 600 秒；不会自动修改已有周期。每台 VPS 同时只允许一轮检测或复检，额外付费复检计入原计划的每日额度。多台 VPS 可以排队提交，一台自建探针仍逐个执行，不因周期缩短而无限叠加任务。

## 一个自建来源包含多个节点

来源卡片新增“管理自建节点”。原探针自动作为 `self` 默认节点保留，原配置和密钥不变。点击“添加节点”并填写“上海腾讯云”等名称，面板只在创建时显示该节点独立密钥；把这把密钥写到上海服务器的探针配置。无需给探针额外配置节点 ID，身份由密钥确定。不要在不同服务器共用同一节点密钥。

在 VPS 检测配置选择这个来源，即可勾选广州、上海等多个节点；“获取国内节点”刷新每个节点的在线状态。所有所选节点每轮各领取同一目标 IP 和端口的独立任务，全部明确不通才按原连续失败阈值处理。某节点可达、离线、缺失、超时或上报失败都不确认故障。新 IP 自动解析等待全部所选节点通过。

同组的未选节点也可作为独立复检点，不能选与首轮重复的节点。各节点可独立暂停；变更配置会取消旧在途轮次，正在被计划选择的节点不能直接删除。客户个人 BOCE 来源与管理员自建组隔离。
