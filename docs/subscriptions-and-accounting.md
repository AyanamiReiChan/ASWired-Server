# ASWired 套餐、订阅与流量实现规范

本文件描述本仓实际实现，不声明与妙妙屋私有报文、客户端信任链或备份格式兼容。对应普通和原 PRO 能力统一开放，没有许可证检查。

## 套餐实例

- `subscriptions` 每条记录对应一个用户的一份套餐实例。`memberId` 是真实账户 ID，`planId` 是套餐 ID；数据库的 `subscription_bindings` 唯一约束保证同一用户同一套餐只有一份，包含并发请求。
- 每份实例有独立 UUID、密码、订阅 Token、短链接标识、周期和到期时间。修改实例不能通过客户端提交覆盖凭据、已计用量或周期。
- 订阅链接 Token 轮换同时废止旧短链接；代理 UUID/密码不随链接轮换改变，已安装客户端不因此意外中断。
- `plan.nodeIds` 为空表示全部有效节点；实例 `nodeIds` 非空时进一步缩小范围。成员节点库只显示有效订阅实际允许分发的节点；历史私有节点同样受套餐与实例的节点选择约束，不能因归属绕过限制。
- 到期、账户停用、套餐停用和实例停用均阻止订阅分发，并重新同步实际 Agent 用户。额度耗尽默认停用；明确配置超额降速时，具备真实限速 Hook 的节点继续以指定速度提供服务。
- 配置里的日期使用 Asia/Shanghai 的当日结束时间；精确 RFC3339 时间保留时区。周期默认 30 天，支持 `cycleDays` 与每月重置；周期重置只改变统计边界，不清空 Xray 累计计数。
- 合并订阅是 ASWired 的独立实现：只接受同一账户的当前有效实例。重复物理节点按套餐分别输出并加套餐名前缀，各自注入 UUID/密码，额度和周期不合并。合并输出采用标准路由配置，不把某一个套餐的模板或脚本套用到所有套餐；原有单套餐订阅保留原模板。
- 兑换码核销和套餐创建、人工核对和续期更新通过 `Store.CompareAndSaveRecords` 在同一事务提交，任意旧版本或重复套餐绑定使整批回滚。

## Agent 配合与限制

网站保存、任务排队、节点执行结果分别记录。`core.users.sync` 是单个入站的完整用户集合，用户管理入站仅支持 VLESS TCP REALITY，用户凭据由主控生成与同步。配置文件的完整应用仍由主控编译后通过 Agent 检查、保存并重启核心。

实例 UUID/密码在选中节点中复用；Xray 邮箱标识为 `credentialEmail + "." + inboundId`，使每条入站的流量倍率可以准确归属同一套餐实例。

`core.policy.apply` 对物理节点下发完整策略。每名用户的全部活动实例邮箱共用一个速率桶、连接数和在线 IP 集合。继承次序如下：

1. 成员 `nodeLimits[nodeId或serverId]` 中的明确值。
2. 成员全局明确值。
3. 套餐 `nodeLimits[nodeId或serverId]` 中的明确值。
4. 套餐全局值。

缺失表示继承，明确的 `0` 表示不限。多个活动套餐覆盖同一物理节点时，采用其中最高有效权益；任何不限权益令该项不限。速度单位是 Mbps，Agent 接收 bytes/second，换算为 `Mbps × 1,000,000 ÷ 8`。主控明确下发 `direction:download`，只限制下载；连接/IP/禁用检查仍覆盖双向。设备标识数量不当作连接数。

### 行为规则与超额降速

这些规则是用户已许可的 ASWired 原创行为实现，不声明未知的上游私有处罚状态机与每个边界完全一致。

`settings.behaviorLimits` 为全局默认，`plans.behaviorLimits` 覆盖对应套餐，`members.behaviorLimits` 优先覆盖用户的全部套餐；`enabled:false` 明确关闭此来源。对象字段是 `enabled`、`maxGapSeconds`（默认 15 秒）和 `rules` 数组。规则格式如下：

```json
{
  "enabled": true,
  "maxGapSeconds": 15,
  "rules": [
    {"id":"sustained-download","type":"sustained","thresholdMbps":100,"durationSeconds":30,"limitMbps":10,"penaltySeconds":600,"priority":10,"notify":true},
    {"id":"burst-download","type":"burst","thresholdMbps":200,"windowSeconds":60,"hits":5,"limitMbps":20,"penaltySeconds":300,"priority":20,"notify":false}
  ]
}
```

- 输入仅为 Xray 累计 `downlink` 计数，按用户和物理节点合并凭据。连续两份有效样本计算该间隔的实际平均下载 Mbps；网卡流量、计费倍率不会进入规则速度。
- 大于等于阈值算命中。持续规则要求连续有效采样间隔累计达到时长；低于阈值即断开持续证据。突发规则计算 `(当前时刻−窗口, 当前时刻]` 中命中的独立样本次数。
- 第一次观察、核心世代改变、计数下降、已观察计数集合变化、间隔超过 `maxGapSeconds` 都不能构造速率证据，清空持续和突发进度。不会用缺样补零或伪造超速。处罚本身保留到既定截止时间。
- 处罚期间新样本不延长截止。到期按时间释放；配置改变可立即释放旧策略并重建证据，用户关闭规则不需等待新流量。状态和独立触发/释放事件在同一事务保存，重启继续使用明确的截止时间。
- 多套餐规则合并后按 `priority` 升序，再按带来源的规则 ID 排序；多条同时处罚时选最前一条。它是明确的原创优先级规则，不暗中改成最严规则。
- `quotaMode` 为 `stop`（默认）或 `throttle`，`quotaSpeedMbps` 必须为正值；可由实例覆盖套餐。超额先降低该实例的可用速度，再按原来的多套餐最高权益形成物理节点基础速度，行为规则最后对它施加上限。另一个未超额套餐的权益不会被误合并成已超额。扩额或账期重置后恢复该实例的正常基础权益，其他行为处罚继续独立计时。
- 只有实际 Agent 上报 `shared_rate_limit:true` 的节点可以提供超额降速。external 或未确认能力的节点停止该超额实例，不放行无限速流量。额外私人节点同样不能绕过这个检查。

`GET /api/limits/effective` 返回当前配置解释、基础/超额/行为来源、有效速度、样本可信度、节点任务 ID 和实际执行状态；`GET /api/limits/events` 返回独立事件。普通成员只能读取自身记录，管理员可按 `serverId` 过滤。事件开启 `notify:true`（套餐另用 `quotaNotify`）才进入通知 outbox，外送还要独立启用 `settings.notificationEvents["limit.trigger"|"limit.release"]`，不会影响到期通知开关。

过期或删除实例的旧邮箱被保留到 `userId#revoked` 禁用策略中，阻止已建立连接继续传输；其他有效实例继续属于原来的用户共享桶。对用户连接数/IP 上限的下降只阻止新增连接。尚未下发的旧完整同步任务标记为 `superseded`，防止旧内容在新内容后覆盖回来。 没有当前策略且没有历史策略任务的服务器不生成初始空策略任务。维护过程只撤回可由首版同步记录、空策略摘要、任务归属和完整历史共同证明无用途的初始空任务；历史清空、手动任务和无法确认的任务保留。撤回任务显示“已撤回”且不可重试，服务器身份和记录保持不变。

## 流量

- 输入是 Xray `reset:false` 累计计数，按物理服务器和完整 counter 名保存游标。
- 游标推进和不可变台账写入处于同一数据库事务。重复时间戳、乱序样本不重复入账。
- 首次观察记录当前累计值；新核心世代或计数下降时记录缺口，并仅记重新开始后确实观察到的字节。没有恢复到的旧进程尾量不会伪造。
- 每笔记录冻结当时的入站/服务器倍率与套餐方向系数。方向系数为 1 或 2，均基于实际上传、下载；调整倍率不会重算旧记录。
- 额度判断直接汇总不可变台账。实例行的 `used` 是可重建显示值，不接受客户端修改。
- 台账持久保存 `owner_id`，删除实例后也不会把成员历史变成他人可见。
- 管理员趋势和服务器表使用 Xray 代理原始流量，成员表使用加权流量；主机网卡观测仍只是探针指标，不能替代用户账目或整机容量。
- 周期边界跨越两次采样时，增量记入后一次采样所在周期。不可恢复的时间拆分没有伪造为精确秒级分摊，缺口数会在统计响应中显示。

### 内部中转分类

管理员可以为落地服务器的内部 Xray 账号登记线路名称。分类严格匹配 `serverId + email`，不按账号前缀、服务器名称或流量大小自动推断。同名账号在另一台服务器上仍保持原来的归属。

- `GET /api/traffic/internal-transfers` 返回 `{ "items": [...] }`。
- `POST /api/traffic/internal-transfers` 接受 `serverId`、`email`、`name` 和可选的 `sourceServerId`，返回该分类对象。重复提交同一个服务器和账号会更新原分类，不产生重复记录。`email` 是 Xray 统计标识，不要求是互联网邮箱地址。
- `DELETE /api/traffic/internal-transfers/{id}` 删除分类，历史统计中的该账号重新显示为未归属。以上接口仅限管理员，API 令牌写操作还需要 `write` 权限。

分类存入加密实体集合 `_trafficInternalTransfers`。服务器必须存在且为原生服务器；当前成员订阅使用的账号、对应入站账号，以及已有成员/订阅归属的台账账号不能登记为内部中转。

`GET /api/traffic` 的 `internal` 和 `unassigned` 分别提供按服务器、账号汇总的内部中转和未知流量。行字段为 `id`、`name`、`serverId`、`serverName`、`email`、`up`、`down`、`used`、`limit:null` 和 `source`；内部中转另有 `classificationId`，登记来源服务器时还有 `sourceServerId`、`sourceServerName`。上传/下载为原始字节，`used` 为 GiB。`sync=1` 时这两个集合与原有集合一样按 `id` 索引，分类变更和删除会进入增量响应。

分类只投影 `owner_id='' AND subscription_id=''` 的台账，不重写原始记录、冻结倍率或成员额度。确认后的内部账号不再混入成员表的“未归属流量”；其余未知账号仍保留该汇总行，同时列出明细。服务器表和总趋势继续包含所有实际代理流量，因此串联线路的不同服务器仍分别保留各自观察到的字节，不应把这份原始总量当作成员计费用量。

登记之后的新内部账号计数使用原始倍率 1，不再因缺少成员归属产生 `unassigned_email` 缺口，零增量仍推进游标而不写台账。核心重启、计数下降等真实缺口继续记录。历史缺口全部保留：旧版本的未归属原因可能覆盖过同一次采样的核心变化，无法仅凭新分类证明历史采样完整。

## 客户端与模板

当前可分发的节点统一为 VLESS TCP REALITY，支持 Clash/Mihomo、sing-box、Egern、V2Ray 和 Shadowrocket 格式。V2Ray/Shadowrocket 使用 Base64 URI 订阅；sing-box 是 JSON；Clash/Mihomo 和 Egern 是 YAML。其他客户端格式不能保留当前 REALITY 配置时明确拒绝；格式名称并不代表允许其他节点协议。

所有输出均检查实际协议、传输和安全组合，不支持的节点计入 `X-ASWired-Skipped-Nodes`。全部节点不可输出时返回 422 和原因，不返回空壳成功。普通、合并和临时订阅共同使用这一限制。

成员历史自有节点与共享节点一样，必须符合套餐和实例的节点选择，不再默认追加。`includePrivateNodes:false` 仍可进一步排除该成员的私有节点。其他成员节点及停用来源下的节点均被排除。套餐到期、停用、超额停止或无法实际执行超额降速的节点限制仍然生效。

手动节点与订阅源导入要求 VLESS、TCP（接受 raw 别名）和 REALITY。完整 URI 是配置来源，替换 URI 时清除旧协议和传输字段；重复关键查询参数或非 none 的 encryption 被拒绝。节点必须提供合法地址、端口、UUID、SNI 和32字节 Base64URL 公钥；Short ID可为空，否则须为最多16位偶数长度十六进制；Flow为空或 xtls-rprx-vision。订阅源的 URI、Base64 和 Clash 导入跳过不合规节点并报告 `skipped`、`reasons`；全部无效时保留上次节点和源信息。

旧不兼容节点保持原记录与凭据，可停用或删除；重新启用或替换须提供完整合法配置。联邦发布、接收、订阅分发和测速同样检查实际配置，已有不兼容记录不会仅修改协议标签后继续使用。

用户管理入站固定为 VLESS TCP REALITY。旧不兼容入站保持原记录，可停用或删除；启用、编译发布和用户同步会明确拒绝。其派生节点不再出现在订阅输出中，管理员需明确转换并补全 REALITY 设置后重新发布。高级 `settings` 不允许覆盖用户、解密方式或 fallback；`streamSettings` 不允许更改协议、传输、安全层或覆盖 REALITY 专用字段。

管理代理出站仅支持 VLESS TCP REALITY，直连 freedom、阻断 blackhole 和独立转发功能保留。管理编译任务和可识别的旧管理出站任务在下发、重试时再次校验。独立的手动底层核心配置与内部 API 监听不属于管理页面的配置范围，不会整体裁剪其内部协议实现。

结构化模板从 `policies` 的 `content` 读取 YAML/JSON，合并到基础配置；动态代理列表由主控保留。Clash 输出随后执行模板展开和 DNS/规则/规则集覆写，再执行 `rules` 的纯 JavaScript `main(config)`。运行时没有文件、网络或 Go 主机对象，250 ms 中断限制。脚本和模板仅由管理员维护，输出必须为配置对象；最终代理列表再次校验 VLESS TCP REALITY，模板或脚本不能重新加入其他代理协议。模板远程 proxy-providers 无法预先验证，须改为通过订阅源导入。直连、阻断与选择器继续可用。文本客户端暂不应用结构化模板，配置会明确报错。

基础字段参考：[Mihomo](https://wiki.metacubex.one/config/proxies/vless/)、[sing-box](https://sing-box.sagernet.org/configuration/outbound/vless/)、[Surge](https://manual.nssurge.com/policies/overview.html)、[Loon](https://github.com/Loon0x00/LoonManual/blob/master/docs/cn/node.md)、[Quantumult X](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf)、[Surfboard](https://getsurfboard.com/docs/profile-format/proxy/external-proxy/shadowsocks/)、[Egern](https://egernapp.com/docs/configuration/proxies/)。

## 数据安全

实体 JSON、设置、任务输入/结果、审计详情和观测数据通过主控独立持久数据密钥加密。查询索引保留必要 ID、归属和时间字段。用户密码使用 bcrypt；JWT 密钥与数据密钥独立，轮换 JWT 不会毁损节点凭据。

HTTP 用户认证使用 ASWired 明确实现的 HS256 JWT，校验签名算法、issuer、subject、到期和签发时间，并从数据库核对用户停用状态和 tokenVersion。密码、角色和停用变化会撤销旧版本 JWT；并发旧资料更新不能回退版本。
