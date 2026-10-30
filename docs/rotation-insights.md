# 轮换实测与只读分析接口

更新后，在客户「自动换 IP 服务 → 主 VPS → 双 VPS 定时轮换」中选择「查看统计与建议」。管理员可从「IP 监控与解析 → 轮换统计与优化建议」打开汇总，在每组轮换下直接生成、复制或撤销只读分析接口，无需切换客户账号。

## 已收集与未收集的数据

- IP：用现有 `ip_events` 和 BOCE 记录统计近 30 天的 IP 时段、首次全节点不通和此前最后成功时间。IP 起点是 agent 观察变化的时间，不是供应商确认分配时间；首个保留 IP 起点未知，不进入周期推导。只有 IPv6 变化而 IPv4 未变时，不重置 IPv4 年龄。
- 未观察到失败就换走的 IP 为右删失样本，不当成故障寿命，也不当成永久可用。BOCE 缺失、未知、超时不算已证实不通；全节点不通也不是被墙的独立证明。
- DNS：新版本开始记录 DNS 提交和供应商回读的时间。此前的文字日志不能还原全国生效时间，不会伪造历史传播样本。
- 外部 DNS：需要部署观察节点。节点每 5 秒查询本地递归 DNS，记录旧值、首次新值和连续 3 次只返回新值的时间。时间按面板收到报告的时刻记录，含 5 秒采样粒度和上报延迟。这里的稳定只表示这三次观察，不是所有客户或全国已经生效。没有观察数据、超时及未稳定样本单独显示。
- 恢复：记录换 IP 请求、发现新 IP、BOCE/业务端口验证完成时间。未完成尝试不会作为零秒恢复。
- 建议：仅为候选值。两台 VPS 各至少 5 次起点可观测且有失效前成功记录的样本，以及至少 5 份旧值到新值稳定的 DNS 观察、3 个地区/运营商组合后才尝试推导。组合标签由操作者声明，并不构成实际地域证明。算法取失效前成功年龄 P10，考虑备用和承载两个周期，并扣除 DNS、恢复和安全裕量；不会自动应用。不需要为了凑样本故意让客户使用已经不可用的 IP。

## 部署 DNS 观察节点

1. 在主 VPS 的轮换统计区填写节点名称、实际地区、实际运营商，生成安装命令。
2. 在该真实网络的 Debian VPS 上以 root 执行命令。脚本只使用 Python 标准库和系统 DNS，不需要 BOCE Key、DNS 提供商密钥或面板管理员密码。
3. 配置位于 `/opt/dns-observer/config.json`，权限 600；默认使用 `/etc/resolv.conf` 的第一个 nameserver，也可设置 `resolver` 为该网络实际使用的 DNS IP。服务为 `dns-observer.service`。
4. 回到统计页面刷新查看节点最后上报时间和传播结果。无任务时查询同一域名保持缓存观察，发生 DNS 切换后自动领取观察任务。可在页面停用节点使其令牌立即失效。

同一个域名按运营商线路返回不同 IP 时，观察节点必须位于这一条绑定线路对应的网络。返回其他线路 IP 会记为未匹配，不会触发生产换 IP 或判定该 IP 被墙。Cloudflare 橙云代理记录对外返回代理地址，无法用公共 A 记录变化衡量源站 IP 更新；这类变更标记为不可观测。

## 接口与权限

客户接口沿用登录会话及 CSRF，且必须拥有轮换涉及的 VPS：

| 接口 | 作用 |
| --- | --- |
| `GET /api/client/servers/{sid}/rotation/insights` | 读取最近 30 天统计和候选建议 |
| `POST /api/client/servers/{sid}/rotation/analysis-token` | 生成一次显示的只读分析令牌，替换旧令牌 |
| `DELETE /api/client/servers/{sid}/rotation/analysis-token` | 撤销只读分析令牌 |
| `POST /api/client/servers/{sid}/rotation/observers` | 创建观察节点；JSON 为 label、region、isp |
| `DELETE /api/client/servers/{sid}/rotation/observers/{oid}` | 停用该轮换的观察节点 |
| `GET /api/admin/rotation-insights` | 管理员查看轮换统计汇总 |
| `POST /api/admin/rotation-insights/{rid}/analysis-token` | 管理员生成该组专用只读令牌 |
| `DELETE /api/admin/rotation-insights/{rid}/analysis-token` | 管理员撤销该组令牌 |

外部分析只允许：

```http
GET /api/rotation-insights/{rotation_id}
Authorization: Bearer <只读分析令牌>
```

它可以读取该组轮换的 IP 历史、DNS 观察和建议，不能读取 BOCE、阿里云、Cloudflare、换 IP API 密钥；不能修改 DNS、策略、重启或换 IP。令牌不放 URL 参数中。服务器转交客户或轮换删除后，关联令牌级联失效。

观察节点使用另一种令牌，只允许 `GET /api/rotation-observer/jobs` 和 `POST /api/rotation-observer/results`。观察令牌不能读取分析接口，分析令牌不能提交观察结果；观察结果也不参与生产控制。

数据采集由面板 worker 与已部署观察节点持续执行；统计读取时自动按最新数据重新计算。外部 AI 不会因此自动获得永久运行能力或自动修改权限。需要在实际站点生成只读令牌并配置外部调用方后，才能按需或定时拉取分析。

## 后台管理轮换

管理员侧栏新增「双 VPS 轮换」，也可在「IP 监控与解析」点击「双 VPS 轮换管理」。支持创建、配置预检、编辑周期/提前量/无心跳阈值/连接阈值、启停、删除。新建后台计划使用后台 DNS 绑定及后台检测计划指定的换 IP API，不自动选择共享 API，以免错换机器。已有客户计划可以在后台管理，但原归属和凭证范围保持不变；客户不能修改管理员创建的计划。未暂停或仍在恢复的计划不能直接删除。
