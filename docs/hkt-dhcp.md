# HKT DHCP 换 IP

适用：Debian 12，独立公网 IPv4 的 `ens18`，`networkctl status ens18` 显示 unmanaged，使用 ISC dhclient。运营商可能重新分配原地址，本功能不能保证换到不同 IP。

## 接入

1. 在面板宿主机更新代码：`cd /opt/hk-sdan && bash scripts/update.sh`。
2. 管理员可为未分配或已分配给客户的 VPS 生成后台专属 API；不改变服务器归属，也不向客户暴露令牌。在后台“IP 监控与解析”点击“生成 HKT DHCP 换 IP API”，选择正确的 HKT VPS。
3. 在 HKT 机器执行弹窗中的 agent 更新命令及本机授权命令。授权脚本仅写配置并重启 agent，不立即释放租约；确认网卡为 ens18。
4. 等待在线上报后生成 API。面板保存一个绑定此 VPS 的 HKT 换 IP API；在后台检测计划中选择该连接。生成/重置本身不换 IP。
5. 外部调用格式为 `POST https://面板域名/api/hkt-dhcp/VPS编号`，请求头 `Authorization: Bearer 专属令牌`。不需额外端口，不把密钥写进 URL。202 只代表排队成功，不代表换 IP 成功。

任务状态可在弹窗中“刷新任务状态”查看。令牌重新生成后旧令牌失效。它只可排队此 VPS 的固定 DHCP 操作，不能传命令、修改网卡、变更 DNS。已加入轮换的机器不能通过外部 API 绕过排空；由轮换内部使用已保存连接执行。

## 执行与限制

- 任务通过 agent 主动上报通道下发，无需 SSH/API 监听 HKT 公网地址。
- 先确认唯一公网 IPv4，再操作指定网卡。每轮释放 IPv4 租约、停止相同网卡及明确授权清理的无网卡 `dhclient -v` 残留，只备份/删除该网卡 IPv4 租约并重新获取。不修改 MAC、不清理 IPv6、不使用 `rm -rf`、不杀其他网卡明确绑定的客户端。
- 任务持续尝试，直到得到稳定且与旧地址不同的 42 开头 IPv4，无次数上限；执行错误后仍停止，核对后重新生成 API 解除失败锁定。
- systemd 独立任务不依赖 SSH 会话或 agent 持续联网；运行最长 240 秒。预先设置 300 秒后的恢复任务，缺少地址/默认路由时尝试后台 DHCP。恢复是尽力而为，DHCP 服务器拒绝服务等情况仍可能需要供应商控制台。
- 持久化命令编号防止同一任务重放；面板拒绝 DHCP 与重启并发。任务结果未知时不自动重复。
- “IP 已变化”和“IP 国内可用”不同。现有 Agent 新鲜上报、所选检测点复检、DNS 身份和旧值校验继续生效，不凭命令退出码改 DNS。
- 固定 A 模式正常只给退出承载的 B 换 IP；API 绑定机器校验防止错用于 A。A 确认故障时仍按原协调流程修复。

## 停用

在 HKT 本机移走 `/etc/hk-sdan-agent/hkt-dhcp.json` 并重启 `hk-sdan-agent` 即停止上报 DHCP 能力；同时暂停面板相关动作。已经执行的网络动作无法撤回。不要在任务执行中人为启动更多 dhclient。

## 验证边界

自动化测试模拟进程列表、DHCP 返回、状态文件、IP 变化、认证、单次下发、失败锁定和权限隔离；不实际释放测试环境或线上机器的租约。实际换 IP 仍需在可使用供应商控制台的情况下进行首次验证。


### 换后续租进程修复

换 IP 动作使用独立的 `hksdan-dhcp-client-<网卡>.service` 托管前台 dhclient，
通过 systemd 自动重启维持续租，不再让 dhclient 跟随临时换 IP / 恢复任务退出。
启动时显式使用现有 `/etc/dhcp/dhclient.conf`，保留上游配置的 Client ID 与 MAC。
新地址、默认路由及 DHCP 进程需连续约 12 秒正常才报告 changed；这不代表国内探测通过。
新 IP 是否可用于解析仍由面板所选探测点检查。

先更新面板，再在 HKT VPS 更新 agent；仅更新面板不会替换远端 agent。
agent 更新本身不释放租约、不换 IP。下一次受控换 IP 测试后，检查：

```bash
systemctl status hksdan-dhcp-client-ens18 --no-pager
journalctl -u hksdan-dhcp-client-ens18 --no-pager -n 40
```

必须继续观察到一次 DHCPREQUEST / DHCPACK 续租，才能确认实际环境下续租恢复。


### HKT 优选 IP 段

HKT DHCP agent 仅将 `42.0.0.0/8`（42 开头）的新公网 IPv4 标记为换 IP 成功。
非 42 地址、原地址或稳定性检查未通过时，持续在同一任务内重试，不设次数与总运行时限。
恢复任务与换 IP 任务共享互斥锁，避免并行干扰。非合格地址不允许进入轮换。
面板对已注册 HKT DHCP API 的 VPS 另设轮换准入检查，即使旧版 agent、
上游手动换 IP 或探测显示可达，也不会把非 42 地址新切入轮换解析。
该限制不强制移走已在承载的解析，不绕过固定 A 的故障判定或连接排空条件，
并且不会影响其他提供商。42 开头并不代表业务可达，仍须通过所选检测点与业务端口检查。
部署需要更新面板及 HKT agent；更新操作本身不换 IP。


### Debian 13 / dhcpcd 10.x

授权脚本通过实际接口主进程识别 dhclient 或 dhcpcd，拒绝两个管理器同时运行、
未知主进程或未核对的 dhcpcd 版本，不再要求 Debian 13 额外安装 dhclient。

针对 dhcpcd，只向现有 ens18 主进程发送 IPv4 release，再以新的 DHCPv4 Client ID
重新申请地址。不会停止整个 dhcpcd、杀死其辅助进程、删除 DUID 或 DHCPv6 租约，
也不会修改 MAC / 系统全局配置。IPv4 release 使用 `-4 -k ens18`；
双栈接口 rebind 不传 `-4`，避免把现有双栈接口重配为 IPv4-only。
双栈 rebind 可能触发 DHCPv6 正常重新确认，不保证 IPv6 地址永远不变。
重新获取只使用现有管理进程；主进程消失时报告错误，不猜测启动第二个管理器。

该实现只覆盖 VM 内 DHCP；没有 PVE / 母机凭证，不执行母机随机 MAC 或伙伴对换。
保留持续申请直到不同于原 IP、42 开头且地址/路由/续租进程稳定的条件。
更新面板后，在目标 HKT 更新 agent 并重新运行 agent-enable-hkt.sh ens18。
更新和授权不换 IP；真正换 IP 仍由受保护的测试或轮换动作触发。
本地模拟测试不代表 Debian 13 实机验证；首次使用须检查 IPv4/IPv6、默认路由、
agent 上报以及后续续租日志。
