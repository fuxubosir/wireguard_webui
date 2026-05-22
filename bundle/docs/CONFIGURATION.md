# 配置说明

主配置文件位于：

```text
/etc/wg-webui/config.json
```

WebUI 会优先读取该文件中的配置。升级 WebUI 时会保留这个配置文件。

## 常用配置

- `wg_if`：WebUI 管理的 WireGuard 接口，默认 `wg0`。
- `wg_cidr`：WireGuard VPN 地址池，例如 `10.6.0.0/24`。
- `server_endpoint`：客户端和站点连接服务器时使用的公网 IP/域名和端口。
- `client_dns`：写入用户客户端配置的 DNS，可为空。
- `reserved_client_allowed_ips`：固定下发给用户客户端的网段。
- `site_ip_start` / `site_ip_end`：站点地址池范围。
- `user_ip_start` / `user_ip_end`：用户地址池范围。
- `online_threshold_seconds`：在线状态判定时间。

这些配置可以在 WebUI 的系统管理/配置中心中维护。

## 用户和站点元数据

以下字段主要用于 WebUI 展示和权限管理，不直接改变 WireGuard 原生语义：

- `user_owners`：用户归属或备注。
- `site_remarks`：站点备注。
- `user_site_permissions`：用户访问站点的权限关系。

修改权限后，建议在 WebUI 中执行权限同步并应用配置。

## 账号安全

管理员账号和密码可以在 WebUI 中修改。新密码会以 PBKDF2-SHA256 哈希写入配置文件。

建议首次安装后立即完成：

1. 登录 WebUI。
2. 进入系统管理/安全账号。
3. 修改默认用户名或密码。
4. 保存后重新登录。

## 会话和登录限制

常见安全参数包括：

- `login_max_attempts`：登录失败次数限制。
- `login_window_seconds`：失败统计窗口。
- `login_lockout_seconds`：锁定时间。
- `session_ttl_seconds`：会话有效期。

一般场景保持默认即可。

## 高级配置

高级配置会影响 WireGuard 地址分配、接口名、服务端连接地址或站点路由。修改前请确认现场网络规划，保存后根据页面提示应用配置。
