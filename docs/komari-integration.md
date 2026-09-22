# Komari 统一账户集成

基于 Komari `1.2.5-fix2`（`2f70b440405c4ea70ff3bcbd87361bbb39dc6f60`）和 komari-web `1.2.5-fix2`（`3e76c4c26c55fc3eaa2a8210322e1b2cacb57e52`）。保留 MIT 许可证和上游版权；我们的修改同时发布于 [fork](https://github.com/AyanamiReiChan/komari)。部署和升级使用 [ASWired-Release](https://github.com/AyanamiReiChan/ASWired-Release)，不要使用上游 Komari 安装脚本覆盖整合版。

## 账户

ASWired `users` 是唯一密码账户库。首次初始化由管理员选择用户名和密码，不预设账户。用户名不授予角色；可选 `ASWIRED_ADMIN_USERNAMES` 仅用于限制已有管理员，默认留空。

| 类型 | 角色与用途 |
| --- | --- |
| ASWired 管理员 | `application=aswired, role=admin`，统一管理 ASWired 与 Komari |
| ASWired 成员 | `application=aswired, role=user`，成员自助 |
| 旧独立 Komari 账户 | 保留历史记录，不再授予后台访问权限，也不自动提升为管理员 |

使用同一个 ASWired 管理员账户。登录后点击侧栏「Komari 管理」，或访问 ASWired 的 `/komari` 页面，由已认证管理员请求 `POST /api/komari/login` 取得一分钟有效、单次使用的 POST 票据，进入 Komari 后台。此操作保留 ASWired 当前登录。普通成员没有 Komari 管理权限，不再创建独立 Komari 类型账户。

Komari 使用独立的 HttpOnly 会话 Cookie，但身份、角色、密码、两步验证和撤销代次都由 ASWired 决定。每次校验会话都会重新确认账户仍是获准的 ASWired 管理员；停用、降权、管理员名单变更、改密会使旧会话和未使用票据失效。从任一后台退出均撤销该账户现有登录。整合模式关闭 Komari 独立密码、SSO 和本地账户创建，不生成默认管理员。登录失败返回明确错误状态，不自动循环换票。

## 配置

ASWired：

```dotenv
ASWIRED_KOMARI_PUBLIC_URL=https://probe.example.com
# ASWIRED_KOMARI_BRIDGE_SECRET：至少 32 字节的随机服务密钥
# ASWIRED_ADMIN_USERNAMES 可选，通常不设置
```

Komari：

```dotenv
ASWIRED_IDENTITY_URL=http://127.0.0.1:12889
ASWIRED_LOGIN_URL=https://panel.example.com/komari
KOMARI_PUBLIC_URL=https://probe.example.com
# ASWIRED_BRIDGE_SECRET：与主控服务密钥相同
```

密钥由部署脚本在目标主机生成，仅写入受保护的环境文件。配置缺项时服务拒绝启动，不回退到本地默认登录。Nginx 必须阻止公网 `/api/internal/komari/` 访问，身份服务端口只监听回环地址。共享密钥是服务凭据，不是管理员密码。

## 构建

1. 在独立 `third_party/komari/frontend` 执行 `npm ci`、`npm run build`。
2. 将 `dist/` 的内容和 `komari-theme.json` 复制到 `web/public/defaultTheme/`，供 Go embed 嵌入。
3. 在 Komari 模块执行 `go test ./...` 和 `go vet ./...`，再启用 CGO 编译（SQLite 需要 C 编译器）。主控根模块测试不会递归覆盖此独立模块。
4. 发行版同时构建 ASWired 网站、主控、Agent 和修改版 Komari，记录每个源提交与制品摘要。

回归检查包括账户隔离、票据重放、Cookie/Origin、会话撤销、身份服务失败关闭，以及空数据库首次设置管理员。升级前备份两个服务的数据目录和环境配置。
