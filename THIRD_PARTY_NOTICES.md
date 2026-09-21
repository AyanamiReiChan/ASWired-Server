# 第三方说明

ASWired Server 原创代码采用根目录 [MIT](LICENSE)。Go 依赖的固定版本见 `go.mod` / `go.sum`；分发时保留各依赖自己的许可证。

IP 数据库读取采用 `github.com/oschwald/maxminddb-golang`（ISC）。随测试保存的 `GeoIP2-City-Test.mmdb` 来自 MaxMind 官方 MaxMind-DB 测试资料，保留 [MIT 许可证](internal/httpapi/testdata/MAXMIND-LICENSE-MIT) 和 [来源、散列](internal/httpapi/testdata/README.md)。它只用于测试，不能当作正式地理数据库。部署者自行提供有权使用的生产数据库。

妙妙屋 X、Komari 和 3X-UI 的公开接口资料用于行为与适配设计；本项目不是这些产品的官方版本。ASWired Agent 通道、联邦加密及备份格式采用独立协议，不承诺与其未公开协议互通。

Xray 及 mihomo 不作为主控进程内的依赖；对应运行时和许可证由独立的 [ASWired-Agent 仓库](https://github.com/AyanamiReiChan/ASWired-Agent) 管理。
