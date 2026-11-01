# 阿里云一次性 TCP 拨测接入（待真实账号验证）

本实现增加管理员检测来源 aliyun，复用现有检测计划和结果展示。没有数据库结构变化，也不需要在国内部署探针。只使用用户明确选择的中国大陆 PC / IDC 节点，不随机选择，也不使用 LASTMILE / MOBILE。

## 配置

1. 阿里云国际账号开通网络分析与监控。在 RAM 创建程序访问用户及 AccessKey，只授予以下权限；不需要管理员权限，也不需要 DNS 修改权限。
2. 面板「检测点配置 → 添加阿里云拨测」填写 ID 和 Secret；密钥加密保存在来源中，编辑和列表不回显。
3. 测试来源、获取国内节点，选择所需地区的移动、联通、电信节点。此步只查节点列表，不创建目标探测。
4. 配置 VPS 当前公网 IPv4、业务 TCP 端口、检测间隔 120 秒。初次只发起一次手动探测，核实返回值后再开定时检测。
5. 每日节点次数上限按所选节点数累计；手动任务也计入。三节点每 120 秒，理论每天 2160 节点次，默认 1000 上限不足全天运行。不要在验证期间直接提高上限。

RAM 自定义权限：

```json
{"Version":"1","Statement":[{"Effect":"Allow","Action":["cms:DescribeSiteMonitorISPCityList","cms:CreateInstantSiteMonitor","cms:DescribeSiteMonitorLog"],"Resource":"*"}]}
```

## 验证范围和限制

本地用模拟阿里云响应验证了签名请求、节点列表、创建任务、异步结果、权限隔离、密钥隐藏及用量累计。尚未用真实账号验证授权、日志落库时延、TCP 成功日志字段、时延单位和实际扣费。不能把本地通过当成已上线可用。

仅 errorCode=0 记为成功，611（连接失败）记为本次不通。接收超时 610、节点资源异常 550、未知代码、缺失结果均保守处理；不把未知转为不通。日志按任务 ID、城市和运营商、结束时间匹配；结果缺失继续等候，120 秒整体超时后记未知。原始 tcpConnectTime 留作诊断，不展示为毫秒；单位需真实日志确认。

首次版本在保存计划时禁止阿里云自动重启/换 IP，只开放记录和定时探测。真实日志语义验证后再接自动动作。阿里云的 TCP 探测并非本地探针的“两次、每次五秒”实现；此版本不宣称支持同一任务双次连接。

一次性探测真实收费需要在账号用量/账单验证；此前按定时 PC / IDC 单价测算不能代替一次性接口实际账单。

## 部署补丁

上传 hksdan-aliyun.patch 到面板服务器 /root。进入实际仓库目录（常见 /opt/hk-sdan），先执行 git apply --check /root/hksdan-aliyun.patch。若提示冲突，停止，不要覆盖现有文件。

检查通过后备份 Dockerfile、detectors.py、web/detectors.js，应用补丁，执行 docker compose up -d --build app dns-worker。刷新浏览器查看新增入口。Dockerfile 必须包含 aliyun_probe.py；只替换 Python 文件但不重建容器不会生效。

官方接口文档：
- https://www.alibabacloud.com/help/en/cms/cloudmonitor-1-0/developer-reference/api-cms-2019-01-01-createinstantsitemonitor
- https://www.alibabacloud.com/help/zh/cms/cloudmonitor-1-0/developer-reference/api-cms-2019-01-01-describesitemonitorlog
- https://www.alibabacloud.com/help/zh/cms/cloudmonitor-1-0/developer-reference/api-cms-2019-01-01-describesitemonitorispcitylist
