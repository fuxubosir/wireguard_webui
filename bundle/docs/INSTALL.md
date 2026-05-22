# 安装与维护

本文说明 `wg-webui-v2.0.0.tar.gz` 发布包的安装、升级、诊断和卸载流程。

## 准备

建议在干净的 Linux 服务器上执行，且服务器已经具备正常的网络访问能力。安装脚本会处理 WebUI 程序目录、配置目录、Python 依赖和 systemd 服务。

发布包解压后，根目录只有一个日常入口：

```bash
sudo bash wg-webui.sh
```

不要直接运行 `bundle/scripts/` 下的内部脚本，除非你正在调试或排查问题。

## 首次安装

```bash
tar -xzf wg-webui-v2.0.0.tar.gz
cd wg-webui-v2.0.0
sudo bash wg-webui.sh
```

在菜单中选择：

```text
1) 安装 / 首次部署
```

安装完成后，按脚本提示访问 WebUI，并及时修改默认管理员密码。

## 升级

把新版发布包上传到服务器，例如：

```text
/tmp/wg-webui-v2.0.0.tar.gz
```

进入新版发布包目录并打开菜单：

```bash
sudo bash wg-webui.sh
```

选择：

```text
2) 升级 WebUI
```

输入升级包完整路径。升级过程会保留：

- `/etc/wg-webui/config.json`
- 已生成的用户配置
- 已生成的站点配置
- 当前 WireGuard 运行配置

升级 WebUI 不会主动重启 WireGuard 隧道。

## 诊断

执行：

```bash
sudo bash wg-webui.sh
```

选择：

```text
3) 运行诊断
```

诊断用于检查 WebUI 服务、WireGuard 相关文件、系统环境、NAT/FORWARD 配置和常见运行问题。

## 服务维护

同一个菜单中还可以执行：

```text
4) 查看 WebUI 服务状态
5) 重启 WebUI 服务
6) 查看 WebUI 日志
```

重启 WebUI 服务只影响管理后台，不会重启 WireGuard 隧道。

## 卸载

执行：

```bash
sudo bash wg-webui.sh
```

选择：

```text
7) 卸载 / 清理
```

卸载脚本会继续询问清理模式，避免误删生产 WireGuard 配置。
