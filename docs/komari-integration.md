# Komari 统一账户集成

基于 Komari `1.2.5-fix2`（`2f70b440405c4ea70ff3bcbd87361bbb39dc6f60`）和 komari-web `1.2.5-fix2`（`3e76c4c26c55fc3eaa2a8210322e1b2cacb57e52`）。保留 MIT 许可证和上游版权；我们的修改同时发布于 [fork](https://github.com/AyanamiReiChan/komari)。部署和升级使用 [ASWired-Release](https://github.com/AyanamiReiChan/ASWired-Release)，不要使用上游 Komari 安装脚本覆盖整合版。

## 账户

ASWired `users` 是唯一密码账户库。首次初始化由管理员选择用户名和密码，不预设账户。用户名不授予角色；可选 `ASWIRED_ADMIN_USERNAMES` 仅用于限制已有管理员，默认留空。

| 类型 | 角色与用途 |
| --- | --- |
| ASWired 管理员 | `application=aswired, role=admin`，管理主控 |
| ASWired 成员 | `application=aswired, role=user`，成员自助 |
| Komari 管理账户 | `application=komari, role=user`，登录 Komari 原生后台，无 ASWired 管理权限 |

在 ASWired 用户管理创建 Komari 类型账户，设置独立用户名和密码。该账户从 ASWired 登录页登录后跳转 Komari。统一登录使用有效期一分钟的单次 POST 票据和独立 HttpOnly 会话 Cookie；账户停用、改密和撤销会话会生效。整合模式关闭 Komari 独立密码、SSO 和本地账户创建，不生成默认管理员。

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
ASWIRED_LOGIN_URL=https://panel.example.com
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
