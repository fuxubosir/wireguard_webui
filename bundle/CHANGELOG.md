## v2.0.0

- Promoted the latest verified WebUI iteration to the 2.0.0 release line.
- Synchronized root and bundled version metadata, package manifest names, runtime APP_VERSION, and static asset cache tags.
- Rebuilt the release archive as `wg-webui-v2.0.0.tar.gz` after the release checks passed.

## v1.12.69

- 重做运维工具里的网络检测逻辑：Ping / 端口检测只负责单个 IP/域名，不再混入网段扫描。
- 新增独立“网段快速扫描”模块：CIDR 网段使用并发扫描，每个地址只发 1 个 ICMP 包，默认 64 并发，最多限制 /24，避免页面卡死。
- 优化 Ping 检测：默认快速 1 包，可选 2 包或 4 包；TCP 端口检测保留在同一模块内。

## v1.12.68

- 运维工具移除网页受控 CLI 入口，减少 WebUI 命令执行风险面。
- 将 Ping 检测升级为“Ping / 端口检测”，支持单个 IP/域名 Ping、TCP 端口检测，以及小网段 CIDR 存活扫描。
- CIDR 模式限制为最多 256 个地址，端口检测限制为最多 40 个端口，避免网页检测任务过重。


## v1.12.67

- 运维工具移除与“路由 / 转发”重复的“连接 / ACL 快照”模块。
- 新增“受控 CLI”模块：支持在网页执行白名单内的只读排障命令，例如 wg show、ip route、iptables -L/-S、systemctl status、journalctl -n、ping、ss、sysctl 等。
- 受控 CLI 禁止 bash、管道、重定向、iptables 修改、systemctl restart 等危险操作，避免把 WebUI 变成开放 root Shell。

## v1.12.66

- 权限管理卡片模式改成和用户卡片一致的左上角两行：归属/备注在上、用户名在下。
- 运维工具“快捷指令”补全 WebUI ACL、FORWARD 命中计数、NAT 命中计数、热刷新 AllowedIPs、快速排故顺序等常用命令。
- 将原“WireGuard 状态”入口调整为“连接 / ACL 快照”，直接展示 Peer、运行 AllowedIPs、接口地址、ACL 入口和 ACL 链命中计数，更适合现场排障。

## v1.12.65

- 修复用户/站点卡片模式下操作按钮没有下拉箭头的问题。
- 卡片模式右下角操作按钮恢复为主按钮 + 下拉箭头，和列表模式保持一致。

## v1.12.63

- 修复用户卡片左上角备注和用户名不显示的问题。
- 用户卡片调整为：备注/归属人、用户名、在线状态、VPN IP、查看配置。
- 站点卡片调整为同款小卡片布局，中间仅显示运行网段，超出省略，不拉升卡片。
- 优化卡片字段兜底显示，避免备注或名称为空时出现空白行。

## v1.12.63

- 用户、站点卡片模式改为小卡片布局：左上显示备注/归属信息，下方显示名称，右上显示在线状态，中间左对齐显示 IP 或运行网段，右下保留主操作按钮。
- 站点卡片中的运行网段超出后自动省略，不再拉高卡片。
- 列表/卡片切换整合为一个按钮，点击后在两种显示方式之间切换。

## v1.12.63

- 站点管理取消单独“站点网段总览”板块，恢复在站点列表中以 `AllowedIPs = ...` 形式直观展示网段。
- 用户列表、站点列表、权限管理新增“列表 / 卡片”显示切换。
- 卡片显示复用站点网段卡片的清爽样式，同时保留原有操作按钮和搜索/展开逻辑。

# CHANGELOG

## v1.12.63

- 运维工具按钮增加选中状态，切换不同工具时底色会跟随当前工具变化。
- 顶部工具区取消重复的“连接快照”卡片，连接快照保留在必要日志中作为辅助查看。
- 新增 Ping 检测工具，可在网页内快速测试用户节点、站点节点、现场网关或内网设备是否可达。
- Ping 检测后端只允许固定 IP/域名目标，使用固定 ping 参数，不支持任意命令执行。

## v1.12.63

- 权限管理搜索框调整为与用户管理一致的样式。
- 搜索框位置左移，紧贴“权限管理”标题区域，右侧操作按钮保持独立对齐。
- 更新静态资源版本号，避免浏览器缓存旧样式。

# Changelog
## v1.12.63

- 站点部署包结构调整：根目录只保留 `site.sh`、README、CHECKLIST、manifest 等必要文件。
- `site.sh` 作为唯一入口，菜单内统一提供部署、状态查看、卸载/清理和日志查看。
- 站点包核心脚本移动到 `bundle/` 内部，避免根目录同时出现 install/uninstall 多个入口。
- 更新站点部署包 README 和生成逻辑，保持与系统部署包“根目录清爽、核心放 bundle”的结构一致。


## v1.12.63

- 高级设置保存后不再自动触发顶部“配置应用”待处理提示，避免和“保存高级设置”语义重复。
- 高级设置保存后保持解锁状态，方便继续修改或直接点击旁边的“重启 WebUI”。
- 删除高级设置标题区域里的重复“重启 WebUI”按钮，只保留“取消修改”旁边的重启按钮。

## v1.12.63

- Moved top-right toast notifications downward so they no longer block the top “配置应用” button after site, permission, or route-related changes.
- Reworked the system package download area into two aligned description cards with matching download buttons.
- Reworked log cleanup into two aligned action cards and removed the redundant small hint text under the cleanup actions.
- Updated README, bundled README, static asset versions, and manifests for the UI polish release.

## v1.12.63

- Root package now keeps `wg-webui.sh` as the only user operation entry.
- `bash wg-webui.sh` opens a simple interactive menu by default.
- Menu now includes install, upgrade, diagnosis, uninstall, service status, service restart, and log viewing.
- Root-level install/upgrade/doctor/uninstall entry scripts remain removed; those functions are accessed through the menu.
- Updated README, installation notes, generated package logic, and release builder to match the single-entry menu model.

## v1.12.63

- Root release layout now keeps only `wg-webui.sh`, README, CHANGELOG, VERSION, manifest, and `bundle/`.
- Removed root-level `install.sh`, `upgrade.sh`, `doctor.sh`, and `uninstall.sh`; all user operations now go through `wg-webui.sh`.
- Updated root `wg-webui.sh` to dispatch directly into `bundle/scripts/` while keeping `bundle/` as the clean core directory.
- Kept bundle-level compatibility wrappers for installed runtime, online upgrade, and internal script calls.
- Updated release builder, release checker, WebUI current-package generator, manifests, and documentation for the single-root-entry layout.

## v1.12.63

- Changed folded configuration-center sections to compact row-style panels so collapsed cards no longer leave large blank areas.
- Added a show-more/collapse control to permission management for long user lists.
- New installs no longer write the default WebUI account into systemd environment variables, so account changes can be saved from the WebUI.
- Account editing is locked only when custom `WEBUI_USER` or `WEBUI_PASSWORD` environment variables are explicitly configured.

## v1.12.63

- Removed the low-value refresh button from the configuration center header.
- Merged the visible “default client AllowedIPs” and “reserved/local networks” controls into one “fixed pushed routes” field.
- Hid the professional HTTPS Cookie Secure toggle from the normal UI while keeping config-file compatibility.
- Login protection and session duration settings now update the running WebUI process immediately instead of asking for a restart.
- Refined configuration-center copy and layout so daily settings stay simple and less technical.

## v1.12.63

- Unified generated site deployment packages to `*-site-package.tar.gz`, matching system deployment packages.
- Updated site package README instructions from `unzip` to `tar -xzf`.
- Removed the backend `zipfile` dependency from site package generation.
- Site package downloads now return `application/gzip` with executable script modes preserved in the tarball.

## v1.12.63

- Rebuilt the bundled userspace compatibility archive so the outer file name, inner top-level directory, app name, temporary directory, README, and release notes all use `wireguard-userspace-compat`.
- Removed the remaining hardware-specific fallback lookup from the generated site installer.
- Rewrote the compatibility archive README and release notes as clean UTF-8 Chinese documentation.

## v1.12.63

- Renamed the bundled userspace compatibility archive to `wireguard-userspace-compat-v0.5.0.tar.gz`.
- Updated site-package generation, site install script references, release builder, release checker, and documentation to use the neutral compatibility package name.

## v1.12.63

- Prepared the project as a GitHub-ready final baseline with simplified README and maintained docs.
- Added `tools/build_release.py` so release packages are reproducible and do not depend on manual packaging commands.
- Bumped WebUI/static asset/manifest versions to `v1.12.63`.
- Removed a duplicate frontend `logout()` definition and a stray console fallback.
- Updated release packaging to include the new build tool in generated full packages.
- Cleaned local release/cache expectations: historical tarballs, `release/build`, and Python caches are treated as generated artifacts.

## v1.12.63

- User list refresh controls now align to the right while preserving the search box size.
- User row primary action now opens the configuration view by default.
- Single-user access permission editing now uses the same multi-column card grid style as bulk authorization.
- System settings now keep common basic/security settings visible and fold maintenance/account settings.
- Runtime log page now shows only connection snapshot, WireGuard service, and WebUI service buttons.

## v1.12.63

- Removed site role badges from the site list.
- Standardized generated package names and file names: site package docs now use `README.md` and `CHECKLIST.md`.
- Full system packages now include a root `manifest.json` in addition to the bundled release manifest.
- Standalone cleanup package is now named `wg-webui-uninstaller-v*.tar.gz` and uses `uninstall.sh` as its entry script.

## v1.12.63

- Shortened common UI hints, placeholders, and confirmation text.
- Added site role badges: `站点网关` for sites with LAN ranges and `仅节点接入` for node-only sites.
- Added dashboard IP pool summaries for site and user address pools.
- Site LAN ranges can now be cleared to keep a site as node-only access.

## v1.12.63

- Dashboard online users, online sites, and recent handshakes now show owner or site remark before the node name.
- New site creation no longer requires site LAN CIDR or onsite NIC at creation time.
- Site package generation keeps onsite NIC detection in the deployment script, while WebUI still validates optional LAN/NIC values when provided.

## v1.12.63

- Simplified the standalone uninstall cleanup tool output.
- The tool now shows only a short purpose statement at startup, then lists concrete delete targets after the user chooses an uninstall mode.

## v1.12.63

- Added a system-management download button for a standalone uninstall cleanup tool.
- The cleanup tool can remove WebUI services, upgrade service leftovers, detected WireGuard interfaces/configs, WebUI data directories, site sysctl files, and matching iptables residue after confirmation.
- Package download API now supports `uninstaller` in addition to the full system deployment package.

## v1.12.63

- Permission management now shows readable site labels in user access ranges: site remark first, site name as fallback.
- Users with full access now display `全部站点` instead of a long list of site CIDRs.
- Permission modals and bulk authorization cards now prefer site remarks while keeping full site/network details in hover titles.

## v1.12.63

- Web online upgrade now extracts `bundle/upgrade.sh` and `bundle/scripts/upgrade.sh` from clean-layout packages before starting the background upgrade service.
- Upgrade precheck, upgrade start, and the shell upgrade script all support the `bundle/app/app.py` package layout.

## v1.12.63

- Site deployment packages now include root `site.sh` as a unified menu for deploy, status, and uninstall.
- Site package root remains clean: `site.sh`, compatible direct entries, README/checklist, manifest, and `bundle/` internals.
- Site package README and install docs now recommend `sudo ./site.sh`.

## v1.12.63

- Reorganized release packages so the root keeps only user-facing entry files and the application internals live under `bundle/`.
- Root `install.sh`, `upgrade.sh`, `doctor.sh`, and `uninstall.sh` now automatically dispatch to `bundle/scripts` when running from a release package, while still working from an installed runtime directory.
- Added root `wg-webui.sh` as a unified operation menu for install, upgrade, doctor, and uninstall.
- WebUI-generated current full packages now use the same clean `bundle/` layout.
- Site deployment packages now keep root-level entry scripts and move templates, compatibility tools, and standard installer internals into `bundle/`.

## v1.12.63

- Fixed uninstall cleanup for FORWARD rules by scanning live `iptables -S FORWARD` output and deleting exact matching rules for the WebUI interface, CIDR, and NAT outlet.
- Added legacy detection for v1.12.63-style WebUI-generated WireGuard configs without `install_state.env`, using `SaveConfig = false` plus generated PostUp rules as the ownership marker.
- Site package uninstall uses the same exact FORWARD scan approach for generated packages.

## v1.12.63

- System installer now records owned WireGuard resources in `/etc/wg-webui/install_state.env`.
- System full uninstall only removes WireGuard config and iptables rules when they were created by this WebUI install; it no longer deletes the whole `/etc/wireguard` directory.
- Site package uninstall now prints an explicit delete plan and only cleans the interface/config/rules recorded by that site package.
- Site package sysctl files are now interface-scoped, for example `/etc/sysctl.d/99-wireguard-site-wg-site.conf`.

## v1.12.63

- System installer no longer silently adopts an existing `/etc/wireguard/wg0.conf`.
- When an existing WireGuard config is found, installation now shows its interface, address, and peer count, then asks whether to use it as the WebUI server config.
- If the existing config is a site access config, the installer can create an independent WebUI server interface such as `wg-webui` instead of overwriting or hijacking `wg0`.

## v1.12.63

- Removed the duplicate WireGuard listen-port prompt from first-time system installation.
- The generated server `ListenPort` now defaults to the port already entered in `server_endpoint`; `WG_LISTEN_PORT` can still override it for advanced deployments.

## v1.12.63

- Removed `doctor.sh` from generated site deployment packages to keep the site package focused.
- Simplified first-time system installation prompts so the WireGuard address pool is derived from the service address step instead of being asked twice.
- Cleaned the system installer source selection message and moved reserved-network input into the later configuration step.

## v1.12.63

- Simplified the generated site installer menu: deployment now performs environment detection directly, so the separate check option is removed.
- Fixed custom WireGuard interface input in the site installer so names such as `wg-xaj` continue deployment instead of exiting.
- Added explicit validation and confirmation output for custom site interface names.

## v1.12.63

- Made the post-create site reminder explicit: new site peers do not enter the running WireGuard server until `应用配置` is clicked.
- The apply button now switches to an urgent state for newly added sites and the UI asks whether to apply immediately.
- The site creation API now returns a clearer pending-apply message for frontend prompts and diagnostics.

## v1.12.63

- Added `doctor.sh` to generated site deployment packages.
- The site doctor checks the actual deployed interface, service state, WireGuard handshake, Endpoint route, and common server-side omissions when traffic is sent but no packets are received.
- Site package README and checklist now point failed-connectivity cases to `sudo ./doctor.sh`.

## v1.12.63

- Added explicit dual-role server guidance for generated site deployment packages.
- The site installer now warns that an existing `wg0` will be preserved and the site access side will use an independent interface such as `wg-site`.
- Site package README and checklist now document the server-plus-site-client deployment pattern.

## v1.12.63

- Reworked generated site deployment packages with interactive `install.sh` and `uninstall.sh` menus.
- Site packages now auto-select a free WireGuard interface. If `wg0` already exists or is running, the installer uses `wg-site`, `wgsite`, `wg1`, and other safe candidates instead of overwriting it.
- Site uninstall now reads `.site-install-state` and cleans only the interface, config, logs, and rules created by that deployment.

## v1.12.63

- Hardened userspace-compatible site deployment command flow.
- The compatible branch now runs the bundled tool with `--no-start`, then stops and clears stale `wg0` state before starting `wg-quick@wg0` once through systemd.
- This avoids `wg-quick: 'wg0' already exists` when the interface was already created successfully during installation.

## v1.12.63

- Fixed userspace-compatible site deployment so `wg0` is not started twice.
- The compatible branch now installs config/runtime first, then starts `wg-quick@wg0` once through systemd.

## v1.12.63

- Reworked generated site deployment packages to use a single `install.sh` entrypoint.
- The site installer now auto-detects kernel WireGuard support and falls back to the embedded userspace tool when needed.
- Simplified site package user-facing documentation around standard versus compatible deployment.

## v1.12.63

- Integrated the userspace WireGuard fallback tool into generated site deployment packages.
- Added `install-userspace.sh` to site deployment packages so small hosts that lack kernel WireGuard can deploy without copying a second package.

## v1.12.63

- Centered Advanced Settings action button text.
- Added package metadata to generated site deployment packages.
- Made dynamically generated system deployment packages include release manifest and tests.

## v1.12.63

- Limited the default-password reminder to the login page only.
- Removed the in-app default-password banner and stopped displaying default credentials in reminder text.

## v1.12.63

- Changed Advanced Settings to a single unlock-to-edit workflow.
- Split Advanced Settings into runtime configuration and address-pool columns.
- Added a non-blocking default-password warning.

## v1.12.63

- Moved runtime-sensitive WireGuard settings into a collapsed Advanced Settings area.
- Restored the configuration center to a cleaner two-column layout.
- Kept per-item risk confirmation before changing Endpoint, interface, CIDR, or address pools.

## v1.12.63

- Replaced the global critical-settings unlock switch with per-item edit dialogs.
- Improved the system configuration center layout.
- Made the system deployment package download button more visually prominent.

## v1.12.63

- Removed advanced path and listener editing from the WebUI configuration center.
- Made critical runtime settings read-only by default and editable only after explicit risk confirmation.
- Added an account security module for changing the WebUI username and password.
- New passwords are stored as PBKDF2-SHA256 hashes in `config.json`.

## v1.12.63

- Added a System Management configuration center for common WebUI and WireGuard settings.
- Made install, upgrade, release, backup, session, and retention paths configurable through `config.json`.
- The UI now distinguishes settings that require applying WireGuard configuration from settings that require restarting WebUI.

## v1.12.63

- Reorganized repository documentation for future GitHub hosting.
- Added a standard root `README.md` and moved the changelog to `CHANGELOG.md`.
- Reduced `docs/` to focused user and maintainer documents.
- Kept `PROJECT_CONTEXT.md` as a short compatibility note for existing upgrade checks.
- Updated release checks, package generation, and upgrade validation to use the simplified document layout.

## v1.12.63

- Created the first v1.12.x baseline package.
- Cleaned historical Markdown copies from `release/build`.
- Synchronized version, static asset cache tags, and release manifest.
- Documented current UI behavior, site remarks, access permissions, and release checks.

## v1.11.72

- Added editable site remarks stored in WebUI metadata.
- Site search now matches remarks.
- Desktop and mobile site lists display remarks without writing them into WireGuard configuration.
- v1.12.63：彻底修复用户/站点卡片备注和名称不显示问题，卡片文字区改为独立显式结构并追加强制可见样式，避免与权限管理卡片样式冲突。
