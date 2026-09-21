# 部署与运维

ASWired + Komari 组合安装请使用 [完整 1.0 教程](https://github.com/AyanamiReiChan/ASWired-Release)。本页保留主控单组件和高级数据库运维说明。

## 1. 数据与权限

服务默认只监听本机 `127.0.0.1:12889`。正式访问通过 HTTPS 反向代理，WebSocket `/api/agent/ws` 也需支持升级。`ASWIRED_PUBLIC_URL` 必须是浏览器和节点能访问的真实主控地址；公网地址必须使用 HTTPS，只有 localhost 或回环地址允许 HTTP 开发配置。设置 `ASWIRED_ALLOWED_ORIGINS` 为前端的来源地址。

数据目录需要保留完整内容，尤其是：

- `aswired.db` 及运行中的 SQLite WAL/SHM。
- `data-encryption.key`：数据库敏感字段的唯一解密密钥。
- `master-identity.key`：Agent 信任的主控身份。
- `jwt.key`：用户 JWT 签名密钥。
- `setup-token`：首次初始化所需本机秘密。

程序生成的秘密文件使用 `0600`，目录使用 `0700`。Windows 上还应通过目录 ACL 限制访问。更换数据密钥会使旧密文不可读取；升级不会轮换这些文件。HTTPS、域名解析和网络端口需按部署环境实际配置，不把本地运行等同公网就绪。

## 2. Linux systemd

尚无正式发布制品时，先从源码构建，并把 `bin/aswired-server` 安装到 `/usr/local/bin/aswired-server`。使用 [systemd 单元](../deploy/aswired-server.service) 和 [配置示例](../deploy/aswired.env.example)。创建 `aswired` 系统账户，将 `/var/lib/aswired` 设为它所有，配置文件 `/etc/aswired/server.env` 保持仅 root 可读。

发布后，下载并审阅仓库内 `scripts/install.sh`，再执行：

```sh
sudo bash scripts/install.sh v1.0.0
sudo systemctl status aswired-server
sudo cat /var/lib/aswired/setup-token
```

版本号只是用法示例，不表示它已经发布。安装器请求该固定版本的 GitHub 发布包及 `SHA256SUMS`，校验后才安装可执行文件和服务。仓库私有、版本不存在或校验失败时退出；现有数据和环境文件不变。脚本不会自动修改防火墙或开放公网。

HTTP-01 在低于 1024 的端口监听通常需要额外权限。推荐配置一个明确的高位 `httpChallengePort`，由公网 80 的反向代理转发 `/.well-known/acme-challenge/`；默认 systemd 单元不授予额外网络能力。Cloudflare DNS-01 无需该监听端口。

## 3. 容器

```sh
docker compose -f deploy/compose.yaml up -d --build
```

映射为主机 `127.0.0.1:12889`；容器内部监听 `0.0.0.0:12889` 以接收映射流量。镜像使用 UID 10001，命名卷 `/data` 持久保存数据库和密钥。使用宿主机目录绑定时，先为 UID 10001 准备目录权限。正式部署修改 Compose 中的公网地址和来源设置。

镜像包含主控程序。若由主控托管前端静态构建，把独立网站仓库的构建输出只读挂载到例如 `/frontend`，并设置 `ASWIRED_FRONTEND_DIR=/frontend`；也可以单独部署前端。

## 4. 升级与回退

升级前通过主控创建逻辑备份，下载到独立安全位置；它包含加密数据及恢复密钥，按秘密材料保存。然后更新固定发布版本：

```sh
sudo /usr/local/bin/aswired-server upgrade --version v1.0.0
sudo systemctl restart aswired-server
```

升级先获取官方同版本发布包和 SHA256 清单、核对哈希，再解压精确名称的普通可执行文件，最终原子替换程序路径。失败时保留原程序。不会自动重启、迁移/删除数据目录、清空账户或改密钥。版本私有或没有发布时明确失败。

Windows 不能替换正在运行的 EXE：使用 `upgrade --version v1.0.0 --output C:\ASWired\aswired-server-next.exe` 暂存核验后的文件，停止服务后再由管理员替换旧 EXE。

回退前核对数据库兼容性。保留上一版本程序和升级前备份；不同数据库结构的版本不能只换二进制就声称恢复成功。当前逻辑备份只接受完全匹配的 ASWired v1 表结构，不把上游私有备份当作兼容输入。

## 5. 本机重置账户

命令仅在有数据文件/数据库权限的本机进程执行，没有无认证的远程重置 API。目标账户必须已存在。建议先停止服务，避免同时发生用户资料修改。

```sh
sudo systemctl stop aswired-server
read -r -s -p 'New password: ' ASWIRED_NEW_PASSWORD
printf '\n'
printf '%s' "$ASWIRED_NEW_PASSWORD" | sudo -u aswired /usr/local/bin/aswired-server reset-password --data-dir /var/lib/aswired --username admin --password-stdin
unset ASWIRED_NEW_PASSWORD
sudo systemctl start aswired-server
```

新密码必须为 12–72 个 UTF-8 字节，不放在命令行参数或日志中。操作真实更新 bcrypt 密码并递增会话版本，旧 JWT 立即失效；数据库和持久密钥不变。如同时遗失 TOTP/Passkey，可由本机运维明确加 `--clear-mfa`，它在同一数据库事务移除该账户的 TOTP 和 Passkeys，随后重新注册。其他账户不会改变。

PostgreSQL 部署要为该命令提供与服务相同的受保护 `ASWIRED_DATABASE_DRIVER/DSN` 环境，不能只给数据目录后误操作另一套 SQLite 数据。

## 6. PostgreSQL

配置 `ASWIRED_DATABASE_DRIVER=postgres`，指定连接 DSN；公网数据库必须正确验证 TLS 服务端证书。主控仍需保留本机数据目录内的密钥和备份材料。SQLite 与 PG 使用共同结构：计数/版本 BIGINT、布尔 INTEGER、加密 JSON TEXT、UTC 固定位数时间 TEXT，查询参数按驱动转换。

2026-09-21 已在本机独立 PostgreSQL 18.4 实例完成真实迁移与存储集成测试。可在独立测试数据库运行：

```sh
ASWIRED_TEST_POSTGRES_DSN='postgres://test:TEST_PASSWORD@127.0.0.1:5432/test?sslmode=disable' go test -v ./internal/store -run TestPostgresIntegration -count=1
```

仅此示例的本机测试库关闭 TLS。测试创建随机独立 schema，覆盖并发初始化、64 位版本、批量事务/CAS回滚、加密、任务及一致快照；不改 public schema。CI 另启动 PostgreSQL 16 服务执行它。正式多实例/高可用部署尚未完成完整验收：计量有数据库锁，但任务调度、WebSocket 在线状态等仍按单主控进程设计。

### 设置中的数据库管理

管理员网页登录后，在「设置 → 数据库」查看当前数据库类型、大小、SQLite WAL 和连接池。进入页面及手动刷新才读取状态，不向 Agent 请求数据。PostgreSQL 的 WAL 由数据库服务管理，不把整个实例的 WAL 用量当成本工作区用量。

填写 PostgreSQL 主机、端口、数据库名、用户名、密码、SSL 模式和连接池上限后可测试连接；测试不保存配置。迁移要求目标当前 schema 没有任何业务表，并要求确认输入「迁移到 PostgreSQL」。只支持单主控进程从 SQLite 迁移；不要同时运行多个访问同一 SQLite 的主控。

确认后主控关闭并等待 HTTP、WebSocket 和后台任务结束，在重新监听前生成逻辑备份，事务创建目标结构、复制全部业务表，再逐表核对行数及内容摘要。主控身份、JWT 和数据加密密钥仍留在同一数据目录，64 位计数、账户和加密凭据原样保留。成功后自动重新加载 PostgreSQL，所填连接池限制一起生效。无需修改环境变量或手动重启。原 SQLite 文件和 `backups/<id>.zip` 保留，页面可下载迁移前备份；日志文件仍位于原数据目录。

迁移配置以 AES-GCM 保存为 `database-pending.enc` / `database-active.enc`，使用独立 `database-config.key`。激活配置优先于数据库环境变量；状态接口不返回密码或 DSN。这三份材料必须按密钥保护，搬迁部署时保留整个主控数据目录。普通逻辑备份不包括 PostgreSQL 连接配置，只包含业务数据及原有数据/身份密钥。

复制或校验失败会回滚目标事务、记录失败并继续使用 SQLite。若数据库提交结果不确定或提交后激活文件写入失败，主控停止启动，保留同一备份与迁移 ID；再次启动会校验目标后继续激活，避免直接切回过时的 SQLite。成功迁移后不要直接移除激活文件切回旧 SQLite，否则会丢失迁移后的更新。

迁移复用现有备份限制（压缩包 256 MiB、清单 384 MiB），超限将拒绝迁移；启动迁移最长 10 分钟。大型数据库需另外安排离线迁移。迁移测试需要测试 PostgreSQL 用户具有创建和删除独立测试数据库的权限：

```sh
ASWIRED_TEST_POSTGRES_DSN='postgres://test:TEST_PASSWORD@127.0.0.1:5432/test?sslmode=disable' go test -v ./internal/httpapi -run TestDatabaseMigrationPostgres -count=1
```

## 7. 发布 CI

CI 在 Linux/Windows 执行测试与 vet，在 Linux执行 race、安装脚本语法检查和 Docker 构建，另跑实际 PostgreSQL 服务。版本标签触发五个目标架构构建和 SHA256 清单，最终创建草稿发布，需维护者检查后发布。创建 CI 文件不表示流水线或这些运行环境已经通过验收。

## 8. Komari 监控

系统监控固定使用本项目 fork 的 Komari 1.2.5-fix2。每台服务器安装 Komari Agent，在主控设置中填写 Komari 面板地址和具有读取权限的 API Key，并通过 `komariUUID` 绑定服务器。绑定可在新增服务器或编辑服务器时完成。地址建议使用主控与 Komari 之间的内网或本机地址；API Key 不下发到 Agent 或浏览器。

主控约每 30 秒读取 Komari 已采集的最新数据，历史图表按需查询 Komari，单次最多 4000 点。CPU、内存、磁盘、负载、系统信息、网卡计数及周期网络监测均由 Komari 提供。周期 TCP/ICMP 任务在 Komari 中配置；ASWired 的手动网络诊断仍可使用管理 Agent。旧 `networkQualityTargets` 不再触发周期任务。

Native 主机采集已移除。旧设置中的 `native` 在读取及保存时按 Komari 处理；未绑定显示未绑定，Komari 不可用时显示离线或过期数据，不回退到管理 Agent。换绑 UUID 或更改 Komari 地址会使旧缓存失效。升级已有 Agent 后才会停止旧二进制的主机数据上传。

ASWired Agent 继续负责 Xray/Mihomo、配置下发、任务执行、手动日志和用户流量计费，管理通道在线状态与 Komari 探针在线状态独立。Komari 网卡用量用于主机监控及服务器账期，不能代替 Xray 用户账本。切换来源时服务器账期建立新采样基线，既有账单保留，历史覆盖不足需按商家账单校准。

Native 删除只减少重复主机采集，不改变管理通道的 5 秒上报、全量 Xray 计数及配置同步频率。这些通信开销需要另行优化。
