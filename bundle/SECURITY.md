# 安全说明

- 首次安装后请立即修改默认管理员密码。
- 建议只在可信内网或 VPN 内访问 WebUI。
- 如需公网访问，请放在 HTTPS 反向代理后，并限制来源 IP。
- 不建议把 WebUI 管理端口直接暴露到公网。
- 升级前请备份 `/etc/wg-webui/config.json` 和现有 WireGuard 配置。
