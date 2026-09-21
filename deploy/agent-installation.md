# Agent 一键接入

网站的「新增服务器」先保存名称、地址、WebSocket / Pull 通道和可选资产信息，再生成安装命令。仅支持内嵌 Xray。创建记录不代表 Agent 已上线；页面根据真实上报显示连接状态。

## 为主控准备安装包

由管理员从受信任的 ASWired-Agent 源码构建，放入主控数据目录。没有包时页面明确提示不可安装，不会猜测 GitHub 下载地址或下载未知 latest。

```sh
# 在 ASWired-Agent 仓库执行，输出目录按本机主控数据位置替换。
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o /path/to/controller-data/agent-releases/linux-amd64/aswired-agent ./cmd/aswired-agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '-s -w' -o /path/to/controller-data/agent-releases/linux-arm64/aswired-agent ./cmd/aswired-agent
```

包目录应仅允许主控管理员写入，主控进程可读。安装包应来自经过检查的固定源码版本，发布时记录 commit 和摘要；更新文件应采用原子替换。界面只列出已配置的架构。Linux 机器需要 root、运行中的 systemd、curl、sha256sum、base64、install、mktemp 与 flock。

`ASWIRED_PUBLIC_URL` 是目标机器可访问的 HTTPS 主控地址，同源代理必须转发 `/api/agent/install/` 和 Agent 通信路径。localhost 仅用于本机开发，远程机器不能使用这个地址。

## 凭据与执行

`GET /api/servers/{id}/enrollment` 仅管理员可读。返回 Agent 配置和 `installation` 对象：available、platforms、command、expiresAt、localOnly、note。临时安装票据有效 30 分钟，仅允许下载对应服务器的脚本和两种固定路径的 Linux 二进制，不能调用管理 API。凭据轮换、删除或停用服务器后失效。静默入口模式不拦截安装路径，但每个下载都单独验证安装票据。

不要公开命令或保留 URL 查询参数日志；反向代理应对安装路径隐藏查询参数并禁用缓存。返回响应也设置 `Cache-Control: no-store`。脚本中的配置包含该节点长期凭据，按密码管理。

安装命令先完整下载脚本，再执行。脚本自动选择 amd64 / arm64，以脚本中的 SHA-256 校验下载的包，并运行 Agent `-check` 验证配置。校验通过后才创建：

- `/usr/local/bin/aswired-agent`
- `/etc/aswired-agent/agent.json`（0600）
- `/var/lib/aswired-agent`（0700）
- `/etc/systemd/system/aswired-agent.service`

新安装使用 flock 避免并发，拒绝覆盖已有服务、程序、配置或数据。启动失败会撤销本次新安装；成功后提示返回主控确认上报，不以 systemd 启动成功代替联网成功。现有安装升级/重装请使用 Agent 仓库的版本化维护脚本。

## 模式边界

外部 Xray 服务控制、外部 gRPC 和模式迁移实现已删除，API 不再发布迁移动作。旧 external 配置、旧 runtime-mode.json 或旧模式上报会被明确拒绝。主控不自动停用旧 Xray，也不自动转换旧运行进程；由管理员维护旧服务后使用新的内嵌 Agent 接入。

本地验证覆盖接口鉴权、票据到期/轮换/隔离、配置内容、校验和、实际下载及内嵌 Agent 连接。Windows 环境不能替代 Linux systemd 实机安装验收。
