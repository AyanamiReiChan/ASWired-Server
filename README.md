# ASWired Server

ASWired 的主控后端，独立 Go 模块。网站仓库为 ASWired，节点程序为 ASWired-Agent。采用 MIT 许可，不设置 PRO 授权或付费功能门槛。项目自行实现行为，不宣称与妙妙屋私有协议、证书信任链、备份格式完全兼容。

## 1.0 部署与更新

完整部署请使用 [ASWired-Release](https://github.com/AyanamiReiChan/ASWired-Release)。设置中的版本检查、Agent 更新和 CLI 升级均从该仓库读取固定版本制品与 SHA256。首次管理员由安装者在网页登录时自行创建。

v1.0.3 的流量统计优化、一致性保证及可复现本地基准见 [流量统计性能](docs/traffic-performance.md)。

## 本地启动

当前代码使用 Go 1.27.1 构建和测试，模块最低版本为 Go 1.26。

```sh
go mod download
go build -o bin/aswired-server ./cmd/aswired-server
./bin/aswired-server serve
```

Windows 的输出文件改为 `bin/aswired-server.exe`。默认监听 `127.0.0.1:12889`，数据库和持久密钥保存在当前目录的 `data`。首次创建管理员需要本机 `data/setup-token` 文件内容；不会预置演示账户或默认密码。

开发前端可访问 `http://localhost:5174`，通过前端代理请求主控。正式部署设置公网 HTTPS 地址和允许来源，详见 [部署与运维](docs/deployment.md)。

实际服务器 IP、个人域名、管理员及节点身份、安装令牌和恢复记录应保存在被忽略的 `.deployment/` 或仓库外。只提交使用示例地址的配置模板；不要提交运行配置、数据库、密钥、SSH 记录或备份。推送前检查暂存内容并扫描 Git 历史；`.gitignore` 不会清除已经提交的文件。

## 能力与合同

- SQLite 默认持久化，PostgreSQL 可选；敏感 JSON 用独立数据密钥加密。
- JWT 登录、用户和套餐、独立订阅凭据、流量台账、任务与节点配合。
- 管理协议包括 VLESS、VMess、Trojan、传统 Shadowsocks、Hysteria2、SOCKS5、HTTP，以及受校验 Mihomo 提供的 AnyTLS、Snell。具体传输、动态账户和计量边界见 [协议说明](docs/managed-protocols.md)。
- Clash/Mihomo、sing-box、Egern、V2Ray 和 Shadowrocket 订阅输出，模板与 JavaScript 覆写；导入、分发、联邦和测速验证实际传输及 REALITY 参数。不兼容节点返回跳过数量和原因，全不兼容时明确失败。
- 主机监控仅使用修改版 Komari 1.2.5-fix2；ASWired Agent 保留代理管理、任务与计量。
- 服务器仅通过 ASWired Agent 接入；支持 WebSocket、HTTP 直连、Pull（轮询）及自动回退，配置模式与实际通道分别显示。HTTP 需开放 Agent 管理端口给主控；三种方式均使用身份验证和加密。
- ACME 证书、Cloudflare DDNS；核心配置、用户同步、计量和节点任务统一由 Agent 执行。
- TOTP、Passkey、备份/恢复及其他主控业务由实际接口执行；失败不模拟成功。
- REALITY 目标扫描与待审核导入；验证实际 TLS 1.3、h2、X25519、证书信任及 SNI，保持原目的地址和端口。

详细行为：[套餐/流量](docs/subscriptions-and-accounting.md)、[证书/DDNS](docs/certificates-ddns-xui.md)、[节点协议](contracts/agent/v1/README.md)、[REALITY 目标池与扫描](docs/reality-targets.md)。

旧版非 Agent 接入记录不会被删除或自动转成 Agent，界面显示“需重新接入”。此类记录停止接入、上报及任务投递；管理员须编辑记录，明确选择 Agent 通道后重新接入。旧接入凭据继续加密保存且不会从服务器接口返回。旧适配器实现、轮询及专用动作已移除。

## 验证

```sh
go test ./...
go vet ./...
```

Linux CI 另执行 `go test -race ./...`，PostgreSQL CI 运行独立数据库验收。当前 Windows 开发环境已运行 SQLite、JWT、协议 fixture 和业务测试；没有安装 PostgreSQL 或 Docker，PostgreSQL 集成、容器启动、systemd 安装及 Linux race 检测未在该开发机实跑。它们不能因为已提交 CI 配置就被称为已通过。

没有发布制品时，安装和升级命令会明确失败；不会下载未知“最新版本”或改写数据库来模拟成功。
## 参考来源

本项目参考的公开资料及链接见 [参考来源](REFERENCES.md)。

## 日志保留

任务执行日志与审计日志默认保留 7 天，主控启动时及每小时自动清理一次。任务按最后完成更新时间计算；排队、运行中及结果未明的任务始终保留，正在被转发链消费的结果暂缓清理。管理员也可在页面手动删除已结束任务日志和审计记录。

清理任务会移除输入、结果和错误正文，并从列表、详情及重试入口隐藏。内部仅保留任务身份与最终状态等最小执行凭据，用于同步去重、策略历史和联邦幂等，防止已完成操作再次执行。联邦已清理结果返回 HTTP 410。订阅抓取和联邦身份任务完成后的一分钟内暂不允许手动删除，以保护关联结果读取。此策略不清理流量账本、订阅记录或探针历史。

管理员可按创建日期批量删除任务或审计日志。日期使用北京时间（UTC+08），包含开始与结束整日；任务的创建日期筛选与自动保留按完成更新时间计算是两个独立规则。先调用 `POST /api/logs/tasks/preview` 或 `/api/logs/audit/preview`，提交 `startDate`、`endDate`（`YYYY-MM-DD`），返回匹配总数、可删除数、受保护数和 `fingerprint`。确认时向对应 `/delete` 接口提交相同日期与指纹；集合或可删除状态变化返回 `409 preview_changed`，需要重新预览。整批事务只删除已确认且可删除的日志，受保护任务保留，内部最小执行凭据仍保留。单次最多 10000 条匹配日志，超出返回 `422 range_too_large`，请缩小日期范围；接口不会按页面数量截断。

## 运维访问权限

流量统计、限速状态及事件、任务执行记录、证书、通知、审计日志、扩展与定时任务仅管理员可查看。普通成员及其 API Token 访问对应读取接口返回 `403 forbidden`，工作区 `/api/state` 不下发运维集合或任务详情；MCP 的资源读取使用相同权限校验。

个人套餐用量、订阅配置、临时订阅和有效订阅中的节点继续可用。成员发起的节点测速不授予查看内部执行日志的权限，结果通过节点状态展示。公开探针仅返回管理员配置为公开的字段，不受此管理工作区限制影响。

## 节点延迟测速

`node.health.check` 从主控测量节点地址的 TCP 连接延迟，单位为毫秒；它不验证 REALITY 代理握手，也不测下载带宽。每个节点的 DNS 解析和全部连接尝试共用 5 秒超时。管理员可测试节点，普通成员仅可测试有效订阅包含的节点。成员测速禁止访问私网、回环、链路本地及保留地址，也不会改变节点的启停状态。

测速成功保存 `latency`；失败清除旧延迟并保存 `latencyStatus`、`latencyError` 与 `testedAt`，避免继续显示过期成功值。测试不会启用已停用的节点。自建入站节点刷新和外部订阅同步会保留相同地址、端口的测试结果，目的地址或端口改变后清除旧结果。

## 外部订阅访问权限

外部订阅源仅管理员可查看、创建、编辑、删除和同步。普通成员即使拥有旧订阅源，也不能访问 `sources` 集合或执行 `source.sync`；JWT、API Token 和 MCP 使用相同校验，成员的 `/api/state` 不返回订阅源，MCP 工具列表不展示订阅源工具。

已有订阅源和已导入节点保留，订阅源的归属字段不授予成员管理权限。管理员仍可管理这些源，既有自动同步按原配置继续执行；需要停用时由管理员关闭同步或禁用该源。个人订阅和临时订阅继续可用。成员节点库只显示有效订阅允许分发的节点，历史归属不绕过套餐或实例的节点选择；成员只可查看节点列表和测速，节点详情、新增、编辑和删除均需管理员权限。JWT、API Token 和 MCP 均禁止成员读取单个节点详情，MCP 工具列表不展示节点详情工具。成员列表仅下发名称、地区、协议、来源、标签、状态和延迟，不返回地址、端口、配置、原始凭据、时间戳或内部错误；测速失败只返回简短提示。订阅配置下载继续按有效订阅提供客户端所需配置。

## Agent 安装命令

新增服务器可先配置再生成 Linux systemd 一键安装命令，固定内嵌 Xray。主控须准备 amd64 / arm64 安装包；票据 30 分钟有效，凭据轮换即撤销。详见 [安装包准备与接入流程](deploy/agent-installation.md)。外部核心管理和运行模式迁移已删除。

## 路由编辑 API

管理员通过 `/api/actions` 使用 `routing.get`、`routing.preview`、`routing.update`，目标为服务器 ID。更新参数为 `routing` 对象、`defaultOutbound`、读取时的 `revision` 和 `apply`。并发配置变化拒绝旧版本；预览不写数据库。API 规则保留在首位，服务器配置优先于旧 policy；默认出站编译为 `outbounds[0]`。均衡探测按策略自动生成，混合 leastPing / leastLoad 共享 burstObservatory。保存与 Agent 应用结果分开，排队不代表已经生效。

## 注册邀请与 Agent REALITY 扫描

管理员通过 `GET/POST /api/registration-invites` 管理一次性注册邀请，`DELETE /api/registration-invites/{id}` 撤销；访客使用 `POST /api/register` 提交 username、password、inviteCode 和可选 turnstileToken，仅能创建普通用户。默认有效期 7 天，可设 1–90 天；原文只返回一次。注册与邀请码消耗原子提交，普通用户不能管理邀请，注册遵循隐藏入口和人机验证。注册邀请与套餐兑换码互相独立。

管理员 `POST /api/reality-targets/scan` 可传 serverId，从在线且支持 reality_scan 的 Agent 扫描。结果通过现有任务通道回传并绑定真实服务器。手动创建目标接口已删除；只允许管理员导入本人发起扫描的合格结果，审核后使用。
