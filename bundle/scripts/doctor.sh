#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${WG_WEBUI_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CONFIG=${WEBUI_CONFIG:-/etc/wg-webui/config.json}
echo "== WireGuard WebUI doctor =="
echo "Version: $(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo unknown)"
[ "$EUID" -eq 0 ] && echo "[OK] root" || echo "[WARN] 建议 root 执行"
command -v systemctl >/dev/null && echo "[OK] systemd" || echo "[FAIL] 未检测到 systemd"
[ -e /dev/net/tun ] && echo "[OK] /dev/net/tun" || echo "[FAIL] 未检测到 /dev/net/tun"
command -v python3 >/dev/null && echo "[OK] python3 $(python3 --version 2>&1)" || echo "[FAIL] 未安装 python3"
command -v wg >/dev/null && echo "[OK] wireguard-tools" || echo "[WARN] 未检测到 wg 命令"
[ -f "$CONFIG" ] && echo "[OK] 配置文件：$CONFIG" || echo "[WARN] 配置文件不存在：$CONFIG"
if [ -f "$CONFIG" ]; then python3 -m json.tool "$CONFIG" >/dev/null && echo "[OK] config.json 格式正确" || echo "[FAIL] config.json 格式错误"; fi
systemctl is-active --quiet wg-webui 2>/dev/null && echo "[OK] wg-webui 服务运行中" || echo "[WARN] wg-webui 服务未运行"

# v1.10.5 WireGuard server config check
wg_if="$(python3 - <<'PY' 2>/dev/null || echo wg0
import json
p='/etc/wg-webui/config.json'
try:
    print(json.load(open(p,encoding='utf-8')).get('wg_if') or 'wg0')
except Exception:
    print('wg0')
PY
)"
[ -f "/etc/wireguard/${wg_if}.conf" ] && echo "[OK] WireGuard 配置存在：/etc/wireguard/${wg_if}.conf" || echo "[FAIL] WireGuard 配置不存在：/etc/wireguard/${wg_if}.conf"
systemctl is-active --quiet "wg-quick@${wg_if}" 2>/dev/null && echo "[OK] wg-quick@${wg_if} 正在运行" || echo "[WARN] wg-quick@${wg_if} 未运行"

if [ -x /opt/wg-webui/tools/repair_wg_nat.py ]; then
  echo "[INFO] WireGuard NAT 网段检查：可运行 /opt/wg-webui/venv/bin/python /opt/wg-webui/tools/repair_wg_nat.py --dry-run"
else
  echo "[WARN] 未找到 tools/repair_wg_nat.py"
fi


echo "== WireGuard 转发规则提示 =="
if command -v iptables >/dev/null 2>&1; then
  iptables -S FORWARD 2>/dev/null | sed -n '1,8p' || true
  echo "[INFO] 如果 FORWARD 默认 DROP 或有 Docker 链，请确认 wg0 -> 内网网卡、内网网卡 -> wg0 RELATED,ESTABLISHED 放行规则存在。"
fi

echo "== 备份/日志/历史包清理检查 =="
if [ -x /opt/wg-webui/tools/cleanup.py ]; then
  /opt/wg-webui/venv/bin/python /opt/wg-webui/tools/cleanup.py --dry-run --json 2>/dev/null | python3 - <<'PY' || true
import json,sys
try:
    data=json.load(sys.stdin)
    mb=(data.get('bytes',0)/1024/1024)
    print(f"[INFO] 可清理项目：{data.get('count',0)} 项，约 {mb:.2f} MB")
    p=data.get('policy',{})
    if p:
        print(f"[INFO] 清理策略：升级备份 {p.get('backup_keep')} 个，配置备份 {p.get('config_backup_keep')} 个，日志 {p.get('log_keep_days')} 天，历史包 {p.get('package_keep')} 个")
    if mb > 1024:
        print("[WARN] 可清理内容超过 1GB，建议在 WebUI 部署与维护中执行安全清理。")
except Exception:
    pass
PY
else
  echo "[WARN] 未找到 /opt/wg-webui/tools/cleanup.py"
fi
