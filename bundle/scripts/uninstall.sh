#!/usr/bin/env bash
set -euo pipefail

APP_DIR=${WEBUI_INSTALL_DIR:-/opt/wg-webui}
CONFIG_DIR=${WEBUI_CONFIG_DIR:-/etc/wg-webui}
CONFIG_FILE=${WEBUI_CONFIG:-$CONFIG_DIR/config.json}
INSTALL_STATE_FILE=${WEBUI_INSTALL_STATE:-$CONFIG_DIR/install_state.env}
SERVICE=${SERVICE:-wg-webui}
WG_DIR=${WG_DIR:-/etc/wireguard}
VAR_DIR=${VAR_DIR:-/var/lib/wg-webui}
LOG_DIR=${LOG_DIR:-/var/log/wg-webui}
UPGRADE_ROOT=${UPGRADE_ROOT:-/opt/wg-webui-upgrade}
MODE=${1:-}

WG_IF="${WG_IF:-}"
WG_CONF=""
WG_CIDR=""
WEBUI_CREATED_WG="unknown"
NAT_ENABLED="0"
NAT_OUT_IF=""
LISTEN_PORT=""

require_root(){
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "请使用 root 执行卸载脚本。"
    exit 1
  fi
}

usage(){
  cat <<EOF
WireGuard WebUI 卸载工具

用法：
  sudo bash wg-webui.sh     打开交互式菜单后选择卸载
  sudo bash bundle/scripts/uninstall.sh --webui-only  仅卸载 WebUI，保留 WireGuard
  sudo bash bundle/scripts/uninstall.sh --purge       卸载 WebUI，并仅清理 WebUI 安装时创建的 WireGuard 配置和规则
  sudo bash bundle/scripts/uninstall.sh --help        显示帮助
EOF
}

read_config_value(){
  local key="$1" default="$2"
  python3 - "$CONFIG_FILE" "$key" "$default" <<'PY_CFG' 2>/dev/null || true
import json,sys
path,key,default=sys.argv[1],sys.argv[2],sys.argv[3]
try:
    data=json.load(open(path,encoding='utf-8'))
    val=data.get(key,default)
    print(val if val not in (None,'') else default)
except Exception:
    print(default)
PY_CFG
}

load_install_state(){
  if [ -f "$INSTALL_STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$INSTALL_STATE_FILE"
  fi
  if [ -z "${WG_IF:-}" ]; then
    WG_IF="$(read_config_value wg_if wg0)"
  fi
  WG_CONF="${WG_CONF:-$WG_DIR/${WG_IF}.conf}"
  WG_CIDR="${WG_CIDR:-$(read_config_value wg_cidr '')}"
  if [ ! -f "$INSTALL_STATE_FILE" ] && [ -f "$WG_CONF" ]; then
    if grep -Eq '^[[:space:]]*SaveConfig[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$WG_CONF" && grep -q 'PostUp = iptables' "$WG_CONF"; then
      WEBUI_CREATED_WG="legacy"
      NAT_ENABLED="1"
      NAT_OUT_IF="${NAT_OUT_IF:-$(grep -Eo -- '-o[[:space:]]+[^[:space:]]+[[:space:]]+-j[[:space:]]+MASQUERADE' "$WG_CONF" | awk 'NR==1{print $2}')}"
      LISTEN_PORT="${LISTEN_PORT:-$(awk -F= '/^[[:space:]]*ListenPort[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$WG_CONF")}"
    fi
  fi
}

menu(){
  cat <<EOF

WireGuard WebUI 卸载工具

1) 仅卸载 WebUI，保留 WireGuard 运行
2) 完全卸载 WebUI，并仅清理 WebUI 自己安装的 WireGuard 配置和规则
3) 退出
EOF
  read -r -p "请选择 [1-3]: " ans
  case "$ans" in
    1) MODE="--webui-only" ;;
    2) MODE="--purge" ;;
    3) echo "已退出。"; exit 0 ;;
    *) echo "无效选择。"; exit 1 ;;
  esac
}

stop_webui(){
  systemctl stop "$SERVICE" 2>/dev/null || true
  systemctl disable "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE.service"
  rm -f "/etc/systemd/system/wg-webui-upgrade.service"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "$SERVICE" 2>/dev/null || true
  systemctl reset-failed wg-webui-upgrade 2>/dev/null || true
}

remove_iptables_rule_repeated(){
  local table="$1"; shift
  while iptables ${table:+-t "$table"} -D "$@" 2>/dev/null; do :; done
}

remove_forward_rules_by_scan(){
  local line hay deleted=0
  while IFS= read -r line; do
    hay=" $line "
    [[ "$line" == "-A FORWARD "* ]] || continue
    [[ "$hay" == *" -j ACCEPT "* ]] || continue
    [[ "$hay" == *" -i $WG_IF "* || "$hay" == *" -o $WG_IF "* ]] || continue
    if [ -n "${WG_CIDR:-}" ]; then
      [[ "$hay" == *" -s $WG_CIDR "* || "$hay" == *" -d $WG_CIDR "* ]] || continue
    fi
    if [ -n "${NAT_OUT_IF:-}" ]; then
      [[ "$hay" == *" -i $NAT_OUT_IF "* || "$hay" == *" -o $NAT_OUT_IF "* ]] || continue
    fi
    echo "- ${line#-A }"
    while true; do
      read -r -a rule_parts <<< "$line"
      rule_parts[0]="-D"
      iptables "${rule_parts[@]}" 2>/dev/null || break
      deleted=$((deleted + 1))
    done
  done < <(iptables -S FORWARD 2>/dev/null || true)
  [ "$deleted" -gt 0 ] && echo "已删除 FORWARD 规则 $deleted 条"
}

extract_listen_port(){
  if [ -n "${LISTEN_PORT:-}" ]; then
    echo "$LISTEN_PORT"
    return
  fi
  if [ -f "$WG_CONF" ]; then
    awk -F= '/^[[:space:]]*ListenPort[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$WG_CONF"
  fi
}

cleanup_own_wg_rules(){
  if [ "${WEBUI_CREATED_WG:-unknown}" != "1" ] && [ "${WEBUI_CREATED_WG:-unknown}" != "legacy" ]; then
    echo "未记录为 WebUI 创建的 WireGuard 配置，跳过 NAT/FORWARD/INPUT 规则清理。"
    return 0
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    echo "未找到 iptables，跳过规则清理。"
    return 0
  fi
  local port
  port="$(extract_listen_port | head -1)"
  echo "清理 WebUI 安装时创建的 iptables 规则："
  if [ "${NAT_ENABLED:-0}" = "1" ] && [ -n "${WG_CIDR:-}" ] && [ -n "${NAT_OUT_IF:-}" ]; then
    echo "- nat POSTROUTING -s $WG_CIDR -o $NAT_OUT_IF -j MASQUERADE"
    echo "- FORWARD -i $WG_IF -o $NAT_OUT_IF -s $WG_CIDR -j ACCEPT"
    echo "- FORWARD -i $NAT_OUT_IF -o $WG_IF -d $WG_CIDR -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    remove_iptables_rule_repeated nat POSTROUTING -s "$WG_CIDR" -o "$NAT_OUT_IF" -j MASQUERADE || true
    remove_iptables_rule_repeated "" FORWARD -i "$WG_IF" -o "$NAT_OUT_IF" -s "$WG_CIDR" -j ACCEPT || true
    remove_iptables_rule_repeated "" FORWARD -i "$NAT_OUT_IF" -o "$WG_IF" -d "$WG_CIDR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true
    remove_iptables_rule_repeated "" FORWARD -i "$NAT_OUT_IF" -o "$WG_IF" -d "$WG_CIDR" -m state --state RELATED,ESTABLISHED -j ACCEPT || true
    remove_forward_rules_by_scan
  else
    echo "- 未记录 WebUI NAT 规则，跳过 NAT/FORWARD 清理"
  fi
  if [ -n "$port" ]; then
    echo "- INPUT -p udp --dport $port -j ACCEPT"
    remove_iptables_rule_repeated "" INPUT -p udp -m udp --dport "$port" -j ACCEPT || true
    remove_iptables_rule_repeated "" INPUT -p udp --dport "$port" -j ACCEPT || true
  fi
}

show_webui_delete_list(){
  cat <<EOF
将删除 WebUI 文件和服务：
- $APP_DIR
- $CONFIG_DIR
- $VAR_DIR
- $LOG_DIR
- $UPGRADE_ROOT
- /etc/systemd/system/$SERVICE.service
- /etc/systemd/system/wg-webui-upgrade.service
EOF
}

webui_only(){
  show_webui_delete_list
  cat <<EOF

将保留：
- $WG_DIR
- wg-quick@$WG_IF
- 当前 WireGuard 配置和 iptables 规则
EOF
  read -r -p "确认仅卸载 WebUI？[y/N]: " yn
  case "$yn" in y|Y|yes|YES) ;; *) echo "已取消。"; exit 0 ;; esac
  stop_webui
  rm -rf "$APP_DIR" "$CONFIG_DIR" "$VAR_DIR" "$LOG_DIR" "$UPGRADE_ROOT"
  echo "已卸载 WebUI。WireGuard 未停止，$WG_DIR 已保留。"
}

purge_all(){
  show_webui_delete_list
  cat <<EOF

WireGuard 清理范围：
- 当前 WebUI 记录的接口：$WG_IF
- 当前 WebUI 记录的配置：$WG_CONF
- WebUI 是否创建该配置：$WEBUI_CREATED_WG
- WebUI 记录的地址池：${WG_CIDR:-未记录}
- WebUI 记录的 NAT 出口：${NAT_OUT_IF:-未记录}
- WebUI 记录的监听端口：${LISTEN_PORT:-将从配置读取}

重要说明：
- 只在 WEBUI_CREATED_WG=1/legacy 时停止并删除 wg-quick@$WG_IF 和 $WG_CONF。
- 不删除整个 $WG_DIR 目录。
- 不清理其它接口的 NAT/FORWARD 规则，例如站点部署包创建的 wg0、wg-site、wg1 等。
- 如果安装时选择接管已有 WireGuard 配置，完整卸载只删除 WebUI，不删除该 WireGuard 配置和规则。
EOF
  read -r -p "请输入 DELETE-WG-WEBUI 确认继续: " confirm
  if [ "$confirm" != "DELETE-WG-WEBUI" ]; then
    echo "确认不匹配，已取消。"
    exit 1
  fi
  if [ "${WEBUI_CREATED_WG:-unknown}" = "1" ] || [ "${WEBUI_CREATED_WG:-unknown}" = "legacy" ]; then
    systemctl stop "wg-quick@$WG_IF" 2>/dev/null || true
    wg-quick down "$WG_IF" >/dev/null 2>&1 || true
    ip link delete "$WG_IF" 2>/dev/null || true
    systemctl disable "wg-quick@$WG_IF" 2>/dev/null || true
    cleanup_own_wg_rules
    rm -f "$WG_CONF"
    systemctl reset-failed "wg-quick@$WG_IF" 2>/dev/null || true
  else
    echo "该 WireGuard 配置不是本安装脚本创建的，跳过停止、删除配置和规则清理。"
  fi
  stop_webui
  rm -rf "$APP_DIR" "$CONFIG_DIR" "$VAR_DIR" "$LOG_DIR" "$UPGRADE_ROOT"
  systemctl daemon-reload 2>/dev/null || true
  echo "卸载完成。"
}

require_root
load_install_state
case "$MODE" in
  "") menu ;;
  --webui-only) ;;
  --purge) ;;
  -h|--help) usage; exit 0 ;;
  *) echo "未知参数：$MODE"; usage; exit 1 ;;
esac
case "$MODE" in
  --webui-only) webui_only ;;
  --purge) purge_all ;;
esac
