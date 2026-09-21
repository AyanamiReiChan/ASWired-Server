# 证书与 DDNS

本文件描述 ASWired 当前代码的真实合同。测试使用本地协议服务器；没有连接用户的公网 CA或 Cloudflare 账户做验收。

## ACME 证书

证书资产位于 `certificates`，操作是 `certificate.issue`、`certificate.renew`、`certificate.upload`、`certificate.deploy`。也可 `POST /api/certificates/{id}/issue|renew|upload|deploy`。

| 字段 | 行为 |
| --- | --- |
| `domains` / `name` | 域名数组；未提供数组时从名称读取域名，支持 IDNA 与通配符 |
| `email`、`termsAgreed` | ACME 联系邮箱与用户明确接受 CA 条款 |
| `staging`、`acmeDirectory` | 默认 Let's Encrypt 正式环境；可选测试环境或自建 HTTPS ACME 目录 |
| `caCertificatePEM` | 自建 CA 的受信任证书；不会关闭 TLS 验证 |
| `eabKid`、`eabHmacKey` | 可选外部账户绑定；ZeroSSL 使用其账户提供的 ID 和 base64url HMAC 密钥，私钥不在列表或详情回显 |
| `challenge` | `DNS-01` 或 `HTTP-01` |
| `provider`、`dnsProviderId` | DNS 验证适配 Cloudflare、阿里云、腾讯 DNSPod、Namesilo；可引用保存的提供商记录 |
| `httpChallengeHost`、`httpChallengePort` | HTTP 验证在主控监听的明确 IP/端口；需把域名公网 80 转发到它，通配符不能使用 HTTP 验证 |
| `autoRenew`、`autoDeploy`、`serverIds` | 开启时距到期 30 天内自动续期，每 6 小时最多尝试一次；可把签发结果排队部署到指定 Agent |

使用 lego ACME 客户端和 ECDSA P-256 账户/证书密钥。账户按 CA 目录和邮箱持久化；签发结果必须通过证书/私钥配对、有效期、全部域名覆盖校验，证书材料和资产元数据在同一加密事务保存。上传参数是 `certificate` 和 `privateKey`。仅完成 CA 签发或实际验证上传后显示已签发。

部署向 Agent 发送 `certificate.deploy {name, certificate, private_key}`。Agent 回执包含不可变证书版本目录、指纹和实际文件路径；部署文件成功不等于 Nginx 已引用它。配置站点并执行 `site.apply` 后，才以真实检查和重载结果认定站点应用成功。

本地测试 CA 验证 ES256 JWS 签名、nonce 和 URL，真实请求 HTTP-01 验证文件，检查 CSR 签名并签出可解析 X.509 证书；覆盖重新签发、错误私钥、错误域名和伪通配符覆盖拒绝。

### 工作区证书管理

`/certificates` 提供独立证书列表与 DNS 提供商页签，支持申请、上传、配置编辑、续期、多服务器部署和 ZIP 下载。列表根据证书有效期展示状态，并关联部署任务的真实回执；自动任务失败读取主控已有记录。浏览列表、切换页签和刷新不会向 Agent 请求信息。

自动部署对手动 ACME 签发、手动续期和定时续期均生效；更新指定证书材料时也遵循该证书的自动部署设置。多目标部署分别返回已排队任务和错误，重复服务器 ID 只下发一次。自动续期与部署不会替代外部反向代理的 HTTPS 配置。

DNS 提供商的详情仅返回凭据是否已配置，留空更新保留原凭据。被证书或 DDNS 引用的提供商不能删除；被入站或站点引用的证书不能删除。删除未引用证书时，主控材料及自动任务记录在同一事务删除，已部署的远端文件不会被自动撤回。

### DNS 提供商凭据

凭据保存在加密的 `dnsProviders` 记录中，也可以直接保存在证书配置。每次创建独立 lego provider Config，不向进程环境注入凭据，也不使用环境中的默认账号。

| provider | 必填字段 | 库适配 |
| --- | --- | --- |
| `cloudflare` | `apiToken`，可选独立 `zoneToken` | Cloudflare DNS API |
| `alidns` | `accessKeyId`、`accessKeySecret` | 阿里云 DNS，允许可选 `securityToken`/`region` |
| `dnspodcn` | `secretId`、`secretKey` | lego `tencentcloud`，腾讯云 DNSPod API；不是旧 Token 形式 DNSPod |
| `namesilo` | `apiKey` | Namesilo DNS API |

四家的独立构造与缺凭据拒绝已经测试；没有用户云凭据，因此未向真实云 DNS 创建 TXT。公开 API 参考：[阿里云适配](https://go-acme.github.io/lego/dns/alidns/)、[腾讯云适配](https://go-acme.github.io/lego/dns/tencentcloud/)、[Namesilo 适配](https://go-acme.github.io/lego/dns/namesilo/)。

### 外部证书管理器推送与下载

`POST /api/admin/certificates/upload` 使用管理员 JWT（`MM-Authorization`），请求 `{domain,cert_pem,key_pem}`；证书与密钥分别支持裸 PEM 或 Base64 编码 PEM。主域名相同则更新原记录，否则创建稳定 ID 的 manual 证书；先验证配对、有效期和域名覆盖，再原子保存材料及元数据。响应包含 `certificate_id`。同主域名存在多个资产时拒绝歧义，避免替换错误证书。

上传后向资产 `serverIds` 及 `inbounds/sites.certificateId` 引用的服务器排队 `certificate.deploy`，返回 `deployments` 与 `deployment_errors`。任务入队不冒充节点部署或服务重载成功，最终以任务结果为准。manual 资产关闭 ACME 自动续期，由外部管理器继续推送。

可传入 `deploy:false` 明确仅保存材料；工作区顶部“上传证书”使用此选项，用户随后选择服务器部署。省略此字段保留外部管理器原有的推送并部署行为。

`GET /api/certificates/{id}/download` 仅管理员可用，返回含 `fullchain.pem` 和 `privkey.pem` 的 ZIP（文件权限 0600），禁用缓存并写独立下载审计。此接口允许取回管理员管理的私钥，普通成员和匿名访问被拒绝。

## Cloudflare DDNS

服务器 `ddns` 对象接受 `enabled`、`provider:"cloudflare"`、`zoneId`、`name`、`type:"A"|"AAAA"`、`apiToken` / `dnsProviderId`、`ttl`、`proxied`、`interval`（秒）。操作是 `ddns.sync` 或 `POST /api/servers/{id}/ddns`。

地址来源是本次明确提交的 `address`，其次服务器已配置的 `publicAddress` 或 `address`；必须是真实 IPv4/IPv6 字面地址，不猜测第三方查询结果。按精确名称和类型查询，重复记录拒绝；内容一致不重复写入，改变时更新原记录，不存在时新增。检查 HTTP 状态和 Cloudflare `success`，并核对返回地址。

自动同步默认每 5 分钟，配置不得小于 60 秒。`_operationSchedule` 保存尝试时间、下次时间及实际结果；进程重启不会导致失败请求每 5 秒重试。

## 服务器接入

当前服务器只支持 ASWired Agent，节点操作经 Agent 通道执行。旧独立面板执行适配器及其操作已移除。历史服务器记录保留，管理员须明确选择 Agent 通道后重新接入。

参考：[lego Cloudflare](https://go-acme.github.io/lego/dns/cloudflare/)、[Cloudflare DNS 更新 API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/update/)。
