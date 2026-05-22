# WireGuard WebUI v2.0.0

WireGuard WebUI 是一个给原生 WireGuard 部署使用的轻量级 Web 管理界面和运维入口。它不替代 WireGuard，也不改变 `wg` / `wg-quick` 的原生工作方式，而是在现有 WireGuard 服务外层提供更方便的页面化管理、配置生成、诊断和升级能力。

## 主要功能

- 为原生 WireGuard 提供 WebUI 管理界面。
- 创建用户客户端，分配 VPN 地址，下载配置文件和二维码。
- 创建站点接入配置，生成站点部署包，查看站点在线状态。
- 管理用户访问站点的权限，并同步 AllowedIPs。
- 提供 Web 运维工具：服务状态、WireGuard 状态、路由/转发/NAT、日志、Ping、TCP 端口检测、网段扫描。
- 通过一个入口脚本完成安装、升级、诊断、服务维护和卸载。
- 支持在线升级包，升级时保留已有配置和数据。

## 项目结构

发布包根目录保持简单，日常只需要使用 `wg-webui.sh`：

```text
wg-webui-v2.0.0/
|-- wg-webui.sh      # 统一操作入口
|-- README.md        # 使用说明
|-- VERSION          # 当前版本
|-- manifest.json    # 发布包清单
`-- bundle/          # WebUI 程序、脚本、配置、工具、文档和测试
```

`bundle/` 是核心目录：

```text
bundle/app/        WebUI 后端、页面模板、静态资源和核心逻辑
bundle/config/     默认配置样例
bundle/scripts/    安装、升级、诊断、卸载脚本
bundle/tools/      修复、同步、清理、打包和发布检查工具
bundle/docs/       安装、配置、运维文档
bundle/tests/      基础单元测试
```

一般使用时不要直接运行 `bundle/scripts/` 下的内部脚本，统一从根目录执行 `wg-webui.sh`。

## 快速开始

解压发布包：

```bash
tar -xzf wg-webui-v2.0.0.tar.gz
cd wg-webui-v2.0.0
```

打开统一菜单：

```bash
sudo bash wg-webui.sh
```

菜单入口：

```text
1) 安装 / 首次部署
2) 升级 WebUI
3) 运行诊断
4) 查看 WebUI 服务状态
5) 重启 WebUI 服务
6) 查看 WebUI 日志
7) 卸载 / 清理
0) 退出
```

新服务器首次部署选择 `1) 安装 / 首次部署`。

## 升级

把新版发布包放到服务器上，然后执行：

```bash
sudo bash wg-webui.sh
```

选择 `2) 升级 WebUI`，再输入升级包路径，例如：

```text
/tmp/wg-webui-v2.0.0.tar.gz
```

升级只替换 WebUI 程序和相关脚本，会保留：

- `/etc/wg-webui/config.json`
- 已有 WireGuard 配置
- 已生成的用户和站点配置
- 现有数据和运行参数

## 文档

面向使用和维护的文档位于 `bundle/docs/`：

- `INSTALL.md`：安装、升级、诊断、卸载流程。
- `CONFIGURATION.md`：配置项、账号安全和高级设置说明。
- `OPERATIONS.md`：日常运维和常见问题排查。

## 测试与打包

在开发或发布前可以运行：

```bash
cd bundle
python3 -m unittest discover -s tests
python3 tools/build_release.py
```

生成的发布包位于：

```text
bundle/release/wg-webui-v2.0.0.tar.gz
```
