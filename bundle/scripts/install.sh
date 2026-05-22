#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="${WG_WEBUI_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
APP_PKG="${1:-}"
APP_DIR=${WEBUI_INSTALL_DIR:-/opt/wg-webui}
CONFIG_DIR=${WEBUI_CONFIG_DIR:-/etc/wg-webui}
CONFIG_FILE=${WEBUI_CONFIG:-$CONFIG_DIR/config.json}
INSTALL_STATE_FILE=${WEBUI_INSTALL_STATE:-$CONFIG_DIR/install_state.env}
SERVICE=${SERVICE:-wg-webui}
DEFAULT_PORT=${WEBUI_PORT:-8080}
LOG_DIR=${LOG_DIR:-/var/log/wg-webui}
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/install-$(date +%F-%H%M%S).log"
PKG_VERSION="$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo 1.11.1)"
ORIGINAL_SCRIPT_DIR="$SCRIPT_DIR"
SAFE_SCRIPT_DIR="/tmp/wg-webui-install-source-$$"
rm -rf "$SAFE_SCRIPT_DIR"
mkdir -p "$SAFE_SCRIPT_DIR"
cp -a "$ORIGINAL_SCRIPT_DIR/." "$SAFE_SCRIPT_DIR/"
SCRIPT_DIR="$SAFE_SCRIPT_DIR"
# 如果未显式传入应用包路径，默认直接使用当前完整包源码安装。
# 这样发布包不再需要内嵌 app/*.tar.gz，压缩包更清晰。
if [ $# -eq 0 ]; then
  APP_PKG=""
fi
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
need_cmd(){ command -v "$1" >/dev/null 2>&1; }
fail(){ log "❌ $*"; exit 1; }
cleanup_install_tmp(){
  rm -rf "${TMP:-}" "$SAFE_SCRIPT_DIR" 2>/dev/null || true
}
trap cleanup_install_tmp EXIT

pip_install_requirements(){
  local req="$1"
  local pip_bin="$APP_DIR/venv/bin/pip"
  local common_opts=(--disable-pip-version-check --no-cache-dir --retries 5 --timeout 120)
  local indexes=()
  log "安装 Python 依赖：$req"
  if [ -d "$SCRIPT_DIR/wheelhouse" ]; then
    log "检测到本地 wheelhouse，优先尝试离线安装..."
    if "$pip_bin" install --no-index --find-links "$SCRIPT_DIR/wheelhouse" -r "$req" | tee -a "$LOG_FILE"; then
      return 0
    fi
    log "离线依赖不完整，继续尝试在线安装。"
  fi
  if [ -n "${PIP_INDEX_URL:-}" ]; then
    indexes+=("$PIP_INDEX_URL|${PIP_TRUSTED_HOST:-}")
  fi
  # 国内网络环境优先使用国内镜像；全部失败后再尝试官方源。
  indexes+=(
    "https://pypi.tuna.tsinghua.edu.cn/simple|pypi.tuna.tsinghua.edu.cn"
    "https://mirrors.aliyun.com/pypi/simple|mirrors.aliyun.com"
    "https://pypi.mirrors.ustc.edu.cn/simple|pypi.mirrors.ustc.edu.cn"
    "https://repo.huaweicloud.com/repository/pypi/simple|repo.huaweicloud.com"
    "https://pypi.org/simple|pypi.org files.pythonhosted.org"
  )
  local item url trusted args h
  for item in "${indexes[@]}"; do
    url="${item%%|*}"
    trusted="${item#*|}"
    log "尝试 pip 源：$url"
    args=("${common_opts[@]}" -i "$url")
    for h in $trusted; do
      [ -n "$h" ] && args+=(--trusted-host "$h")
    done
    if "$pip_bin" install "${args[@]}" -r "$req" | tee -a "$LOG_FILE"; then
      log "Python 依赖安装成功：$url"
      return 0
    fi
    log "pip 源失败，继续切换下一个：$url"
  done
  fail "Python 依赖安装失败。可重新执行：PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple bash wg-webui.sh"
}


calc_wg_server_addr(){
  python3 - "$1" <<'PY_CALC'
import ipaddress,sys
net=ipaddress.ip_network(sys.argv[1], strict=False)
print(str(next(net.hosts())) + '/' + str(net.prefixlen))
PY_CALC
}
normalize_wg_cidr(){
  python3 - "$1" <<'PY_NET'
import ipaddress,sys
net=ipaddress.ip_network(sys.argv[1], strict=False)
print(str(net))
PY_NET
}
derive_wg_net(){
  python3 - "$1" <<'PY_NET'
import ipaddress,sys
net=ipaddress.ip_network(sys.argv[1], strict=False)
print('.'.join(str(net.network_address).split('.')[:3]))
PY_NET
}
update_config_wg_network(){
  local cidr="$1"
  local norm net_prefix
  norm="$(normalize_wg_cidr "$cidr")"
  net_prefix="$(derive_wg_net "$norm")"
  python3 - "$CONFIG_FILE" "$norm" "$net_prefix" <<'PY_UPD'
import json,sys,os
path,cidr,net=sys.argv[1],sys.argv[2],sys.argv[3]
try:
    data=json.load(open(path,encoding='utf-8'))
except Exception:
    data={}
data['wg_cidr']=cidr
data['wg_net']=net
os.makedirs(os.path.dirname(path),exist_ok=True)
open(path,'w',encoding='utf-8').write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
PY_UPD
  chmod 600 "$CONFIG_FILE" 2>/dev/null || true
  log "已同步 WireGuard 地址池到平台配置：wg_cidr=$norm，wg_net=$net_prefix"
}
parse_endpoint_port(){
  python3 - "$1" <<'PY_PORT'
import re,sys
m=re.search(r':(\d+)$', sys.argv[1].strip())
print(m.group(1) if m else '')
PY_PORT
}
read_config_value(){
  python3 - "$CONFIG_FILE" "$1" "$2" <<'PY_CFG' 2>/dev/null || true
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
auto_default_iface(){
  ip route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}'
}
valid_wg_if(){
  local iface="$1"
  case "$iface" in
    ""|*[!A-Za-z0-9_.-]*)
      return 1
      ;;
  esac
  [ "${#iface}" -le 15 ]
}
wg_conf_address(){
  local conf="$1"
  awk -F= '
    /^[[:space:]]*Address[[:space:]]*=/ {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2);
      split($2,a,",");
      print a[1];
      exit
    }
  ' "$conf" 2>/dev/null || true
}

set_config_value(){
  local key="$1" value="$2"
  python3 - "$CONFIG_FILE" "$key" "$value" <<'PY_SET'
import json,sys,os
path,key,value=sys.argv[1],sys.argv[2],sys.argv[3]
try:
    data=json.load(open(path,encoding='utf-8'))
except Exception:
    data={}
data[key]=value
os.makedirs(os.path.dirname(path),exist_ok=True)
open(path,'w',encoding='utf-8').write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
PY_SET
  chmod 600 "$CONFIG_FILE" 2>/dev/null || true
}
write_install_state(){
  local created_wg="$1" nat_enabled="${2:-0}" out_if="${3:-}" listen_port="${4:-}"
  mkdir -p "$CONFIG_DIR"
  cat > "$INSTALL_STATE_FILE" <<EOF
APP_DIR="$APP_DIR"
CONFIG_DIR="$CONFIG_DIR"
SERVICE="$SERVICE"
WG_DIR="/etc/wireguard"
WG_IF="$wg_if"
WG_CONF="$wg_conf"
WG_CIDR="$wg_cidr"
WEBUI_CREATED_WG="$created_wg"
NAT_ENABLED="$nat_enabled"
NAT_OUT_IF="$out_if"
LISTEN_PORT="$listen_port"
EOF
  chmod 600 "$INSTALL_STATE_FILE" 2>/dev/null || true
  log "已记录安装状态：$INSTALL_STATE_FILE"
}
endpoint_valid(){
  python3 - "$1" <<'PY_EP'
import re,sys
v=sys.argv[1].strip()
# 支持 常见域名/IP:端口；IPv6 请使用 [IPv6]:端口 的形式。
ok=bool(re.match(r'^(\[[0-9a-fA-F:]+\]|[^:\s]+):([0-9]{1,5})$', v))
if ok:
    port=int(v.rsplit(':',1)[1])
    ok=1 <= port <= 65535
sys.exit(0 if ok else 1)
PY_EP
}
ensure_endpoint_dns_config(){
  local endpoint dns input
  endpoint="$(read_config_value server_endpoint '')"
  dns="$(read_config_value client_dns '')"
  if [ -z "$endpoint" ] || [[ "$endpoint" == YOUR_PUBLIC_IP_OR_DOMAIN* ]]; then
    echo
    echo "需要填写 WireGuard 客户端连接 Endpoint。"
    echo "这个值会写入用户/站点配置里的 Endpoint，例如：公网IP:31820 或 vpn.example.com:31820。"
    while true; do
      read -r -p "服务器 Endpoint（公网IP/域名:端口）: " input || true
      input="${input:-}"
      if endpoint_valid "$input"; then
        endpoint="$input"
        set_config_value server_endpoint "$endpoint"
        log "已写入 server_endpoint：$endpoint"
        break
      fi
      echo "格式不正确，请按 公网IP/域名:端口 填写，例如 1.2.3.4:31820 或 vpn.example.com:31820。"
    done
  else
    log "server_endpoint 已配置：$endpoint"
  fi
  if [ -z "$dns" ]; then
    echo
    echo "客户端 DNS 可选。填写后会写入用户客户端配置的 DNS 行。"
    echo "例如：223.5.5.5 或 114.114.114.114；不需要可直接回车。"
    read -r -p "客户端 DNS [可空]: " input || true
    input="${input:-}"
    set_config_value client_dns "$input"
    if [ -n "$input" ]; then log "已写入 client_dns：$input"; else log "client_dns 留空，客户端配置将不写 DNS 行"; fi
  else
    log "client_dns 已配置：$dns"
  fi
}

ensure_reserved_networks(){
  local current input
  current="$(read_config_value reserved_client_allowed_ips '')"
  if [ -n "$current" ] && [ "$current" != "[]" ]; then
    log "reserved_client_allowed_ips 已配置：$current"
    return 0
  fi
  echo
  echo "本地/保留网段用于固定下发给用户客户端 AllowedIPs。"
  echo "例如公司本地 LAN、办公网、服务器所在内网；多个网段用英文逗号分隔。"
  echo "不需要下发额外本地网段时，直接回车即可。"
  read -r -p "本地/保留网段 [可空]: " input || true
  python3 - "$CONFIG_FILE" "$input" <<'PY_RESERVED'
import json,sys,ipaddress,os
path,raw=sys.argv[1],sys.argv[2]
try:
    data=json.load(open(path,encoding='utf-8'))
except Exception:
    data={}
out=[]
for item in raw.split(','):
    item=item.strip()
    if not item:
        continue
    try:
        net=ipaddress.ip_network(item,strict=False)
        if net.version==4 and str(net) not in out:
            out.append(str(net))
    except Exception:
        print(f"忽略格式错误的网段：{item}")
data['reserved_client_allowed_ips']=out
os.makedirs(os.path.dirname(path),exist_ok=True)
open(path,'w',encoding='utf-8').write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
PY_RESERVED
  chmod 600 "$CONFIG_FILE" 2>/dev/null || true
  if [ -n "$input" ]; then log "已写入本地/保留网段：$input"; else log "本地/保留网段留空"; fi
}

ensure_wireguard_server(){
  local wg_if wg_cidr wg_conf endpoint listen_port server_addr nat_default nat_answer out_if input_addr input_if gen_wg private_key
  local use_existing existing_addr existing_peers input_if_name default_new_if
  wg_if="$(read_config_value wg_if wg0)"
  wg_cidr="$(read_config_value wg_cidr 10.6.0.0/24)"
  endpoint="$(read_config_value server_endpoint '')"
  wg_conf="/etc/wireguard/${wg_if}.conf"
  mkdir -p /etc/wireguard
  if [ -f "$wg_conf" ]; then
    existing_addr="$(wg_conf_address "$wg_conf")"
    existing_peers="$(grep -c '^[[:space:]]*\[Peer\]' "$wg_conf" 2>/dev/null || true)"
    echo
    echo "检测到已有 WireGuard 配置：$wg_conf"
    echo "接口名称：$wg_if"
    [ -n "$existing_addr" ] && echo "接口地址：$existing_addr"
    echo "Peer 数量：${existing_peers:-0}"
    echo
    echo "注意：如果这个配置来自站点部署包，它通常是站点接入端配置，不应该作为 WebUI 服务端主配置。"
    read -r -p "是否将这个现有配置作为 WebUI 服务端主配置？[y/N]: " use_existing || true
    use_existing="${use_existing:-N}"
    if [[ "$use_existing" =~ ^[Yy]$ ]]; then
      set_config_value wg_if "$wg_if"
      if [ -n "$existing_addr" ]; then
        update_config_wg_network "$existing_addr"
      fi
      log "已确认使用现有 WireGuard 配置作为 WebUI 主配置：$wg_conf"
      systemctl enable --now "wg-quick@${wg_if}" >>"$LOG_FILE" 2>&1 || log "WARN: wg-quick@${wg_if} 启动失败，请手动检查 $wg_conf"
      wg_cidr="$(read_config_value wg_cidr "$wg_cidr")"
      write_install_state 0 0 "" ""
      return 0
    fi

    default_new_if="wg-webui"
    while true; do
      read -r -p "请输入 WebUI 服务端新接口名 [$default_new_if]: " input_if_name || true
      input_if_name="${input_if_name:-$default_new_if}"
      if ! valid_wg_if "$input_if_name"; then
        echo "接口名只能使用字母、数字、横线、下划线、点号，且长度不超过 15 个字符。"
        continue
      fi
      if [ -f "/etc/wireguard/${input_if_name}.conf" ]; then
        echo "/etc/wireguard/${input_if_name}.conf 已存在，请换一个接口名。"
        continue
      fi
      wg_if="$input_if_name"
      wg_conf="/etc/wireguard/${wg_if}.conf"
      set_config_value wg_if "$wg_if"
      gen_wg="Y"
      log "将为 WebUI 新建独立 WireGuard 服务端配置：$wg_conf"
      break
    done
  fi

  if [ -z "${gen_wg:-}" ]; then
    echo
    echo "未检测到 $wg_conf。"
    echo "这是新服务器首次部署时常见情况。WebUI 需要 WireGuard 服务端配置才能正常创建用户/站点。"
    read -r -p "是否现在生成 WireGuard 服务端配置 ${wg_conf}？[Y/n]: " gen_wg || true
    gen_wg="${gen_wg:-Y}"
  fi
  if [[ ! "$gen_wg" =~ ^[Yy]$ ]]; then
    log "跳过生成 $wg_conf。WebUI 会安装，但创建用户前你需要手动准备 WireGuard 配置。"
    write_install_state 0 0 "" ""
    return 0
  fi
  echo
  echo "开始配置 WireGuard 服务端。"
  echo "说明：服务端地址会同时决定 WebUI 的 VPN 地址池。"
  echo "示例：输入 10.7.0.1/24 后，平台地址池会自动记录为 10.7.0.0/24。"
  listen_port="${WG_LISTEN_PORT:-$(parse_endpoint_port "$endpoint")}"
  [ -n "$listen_port" ] || listen_port="51820"
  log "WireGuard 监听端口使用 Endpoint 中的端口：$listen_port"
  if [ -n "${WG_LISTEN_PORT:-}" ]; then
    log "检测到 WG_LISTEN_PORT，已使用手动指定监听端口：$listen_port"
  fi
  server_addr="$(calc_wg_server_addr "$wg_cidr")"
  read -r -p "WireGuard 服务端地址 [$server_addr]: " input_addr || true
  server_addr="${input_addr:-$server_addr}"
  # 用户常输入 10.8.0.1/24 作为服务端地址；这里必须反推出地址池并写入平台配置。
  wg_cidr="$(normalize_wg_cidr "$server_addr")"
  update_config_wg_network "$wg_cidr"
  out_if="$(auto_default_iface || true)"
  nat_default="n"
  [ -n "$out_if" ] && nat_default="y"
  echo "如果希望 VPN 用户访问本机所在内网，通常需要开启转发/NAT。"
  echo "如果内网网关已有回程路由，可不启用 NAT。"
  read -r -p "是否在 ${wg_conf} 中添加 MASQUERADE 规则？[${nat_default}/n]: " nat_answer || true
  nat_answer="${nat_answer:-$nat_default}"
  if [[ "$nat_answer" =~ ^[Yy]$ ]]; then
    read -r -p "NAT 出口网卡 [$out_if]: " input_if || true
    out_if="${input_if:-$out_if}"
  fi
  umask 077
  private_key="$(wg genkey)" || fail "生成 WireGuard 私钥失败"
  {
    echo "[Interface]"
    echo "PrivateKey = $private_key"
    echo "Address = $server_addr"
    echo "ListenPort = $listen_port"
    echo "SaveConfig = false"
    echo "PostUp = sysctl -w net.ipv4.ip_forward=1"
    if [[ "$nat_answer" =~ ^[Yy]$ ]] && [ -n "$out_if" ]; then
      echo "PostUp = iptables -t nat -C POSTROUTING -s $wg_cidr -o $out_if -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $wg_cidr -o $out_if -j MASQUERADE"
      echo "PostUp = iptables -C FORWARD -i $wg_if -o $out_if -s $wg_cidr -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i $wg_if -o $out_if -s $wg_cidr -j ACCEPT"
      echo "PostUp = iptables -C FORWARD -i $out_if -o $wg_if -d $wg_cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -i $out_if -o $wg_if -d $wg_cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
      echo "PostDown = iptables -t nat -D POSTROUTING -s $wg_cidr -o $out_if -j MASQUERADE 2>/dev/null || true"
      echo "PostDown = iptables -D FORWARD -i $wg_if -o $out_if -s $wg_cidr -j ACCEPT 2>/dev/null || true"
      echo "PostDown = iptables -D FORWARD -i $out_if -o $wg_if -d $wg_cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true"
    fi
  } > "$wg_conf"
  chmod 600 "$wg_conf"
  systemctl enable --now "wg-quick@${wg_if}" >>"$LOG_FILE" 2>&1 || fail "wg-quick@${wg_if} 启动失败，请检查 $wg_conf 和 journalctl -u wg-quick@${wg_if}"
  if [[ "$nat_answer" =~ ^[Yy]$ ]] && [ -n "$out_if" ]; then
    write_install_state 1 1 "$out_if" "$listen_port"
  else
    write_install_state 1 0 "" "$listen_port"
  fi
  log "已生成并启动 WireGuard：$wg_conf"
}

[ "$EUID" -eq 0 ] || fail "请使用 root 执行：sudo bash wg-webui.sh"
need_cmd systemctl || fail "未检测到 systemd，当前版本暂不支持自动创建服务"
[ -e /dev/net/tun ] || fail "未检测到 /dev/net/tun，WireGuard/TUN 环境不可用"
install_deps(){
  if need_cmd apt; then
    apt update | tee -a "$LOG_FILE"
    apt install -y python3 python3-venv python3-pip wireguard-tools qrencode iproute2 iptables curl tar gzip | tee -a "$LOG_FILE"
  elif need_cmd dnf; then
    dnf install -y python3 python3-pip wireguard-tools qrencode iproute iptables curl tar gzip | tee -a "$LOG_FILE" || true
  elif need_cmd yum; then
    yum install -y python3 python3-pip wireguard-tools qrencode iproute iptables curl tar gzip | tee -a "$LOG_FILE" || true
  else
    fail "未检测到 apt/dnf/yum，无法自动安装依赖。请手动安装 python3、venv、wireguard-tools 后重试。"
  fi
}
find_app_pkg(){
  [ -n "$APP_PKG" ] && [ -f "$APP_PKG" ] && { echo "$APP_PKG"; return; }
  for p in "$SCRIPT_DIR"/app/wg-webui-app-v*.tar.gz ./wg-webui-app-v*.tar.gz ../app/wg-webui-app-v*.tar.gz ../../app/wg-webui-app-v*.tar.gz; do
    [ -f "$p" ] && { echo "$p"; return; }
  done
  return 1
}
install_deps
TMP="/tmp/wg-webui-install-$$"
rm -rf "$TMP" && mkdir -p "$TMP"
APP_PKG="$(find_app_pkg || true)"
if [ -n "$APP_PKG" ]; then
  log "使用应用包：$APP_PKG"
  tar -xzf "$APP_PKG" -C "$TMP" || fail "应用包解压失败"
  APP_SRC=""
  for d in "$TMP"/*; do
    if [ -d "$d" ] && [ -f "$d/app/app.py" ]; then APP_SRC="$d"; break; fi
    if [ -d "$d" ] && [ -f "$d/app.py" ]; then APP_SRC="$d"; break; fi
  done
  if [ -z "$APP_SRC" ] && [ -f "$TMP/app/app.py" ]; then APP_SRC="$TMP"; fi
  if [ -z "$APP_SRC" ] && [ -f "$TMP/app.py" ]; then APP_SRC="$TMP"; fi
else
  log "使用当前完整安装包源码安装：$SCRIPT_DIR"
  APP_SRC="$SCRIPT_DIR"
fi
if [ -f "$APP_SRC/app/app.py" ]; then
  APP_ROOT="$APP_SRC"
elif [ -f "$APP_SRC/app.py" ]; then
  APP_ROOT="$APP_SRC"
else
  fail "应用源码结构错误：未找到 app/app.py 或 app.py"
fi
mkdir -p "$APP_DIR" "$CONFIG_DIR"
# 后续会 --delete 替换 $APP_DIR。必须先离开安装源目录，避免当前工作目录被删除后 pip/getcwd 报错。
cd /
rsync -a --delete --exclude venv --exclude __pycache__ "$APP_ROOT/" "$APP_DIR/" 2>/dev/null || cp -a "$APP_ROOT/." "$APP_DIR/"
if [ ! -f "$CONFIG_FILE" ]; then
  if [ -f "$APP_DIR/config/config.json.sample" ]; then
    cp "$APP_DIR/config/config.json.sample" "$CONFIG_FILE"
  else
    cp "$APP_DIR/config.json.sample" "$CONFIG_FILE"
  fi
  chmod 600 "$CONFIG_FILE" || true
  log "已创建配置：$CONFIG_FILE"
else
  log "保留已有配置：$CONFIG_FILE"
fi
ensure_endpoint_dns_config
ensure_wireguard_server
ensure_reserved_networks
if [ -x "$APP_DIR/tools/repair_wg_nat.py" ]; then
  log "校准 WireGuard NAT 网段与平台地址池..."
  python3 "$APP_DIR/tools/repair_wg_nat.py" --config "$CONFIG_FILE" --apply-live >>"$LOG_FILE" 2>&1 || log "WARN: NAT 网段校准失败，请运行：sudo bash wg-webui.sh 检查"
fi
if [ ! -d "$APP_DIR/venv" ]; then python3 -m venv "$APP_DIR/venv"; fi
pip_install_requirements "$APP_DIR/app/requirements.txt"
PORT="$(python3 - "$CONFIG_FILE" "$DEFAULT_PORT" <<'PY' 2>/dev/null || echo "$DEFAULT_PORT"
import json,sys
try: print(json.load(open(sys.argv[1],encoding='utf-8')).get('listen_port') or sys.argv[2])
except Exception: print(sys.argv[2])
PY
)"
HOST="$(python3 - "$CONFIG_FILE" <<'PY' 2>/dev/null || echo '0.0.0.0'
import json,sys
try: print(json.load(open(sys.argv[1],encoding='utf-8')).get('listen_host') or '0.0.0.0')
except Exception: print('0.0.0.0')
PY
)"
cat >"/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=WireGuard WebUI
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR/app
Environment=WEBUI_CONFIG=$CONFIG_FILE
ExecStart=$APP_DIR/venv/bin/uvicorn app:app --host $HOST --port $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
sleep 3
systemctl is-active --quiet "$SERVICE" || fail "服务启动失败，请查看 journalctl -u $SERVICE -n 80 --no-pager"

# 保存发布资源，供 WebUI“部署与维护”页面下载。
mkdir -p "$APP_DIR/release" "/var/lib/wg-webui/packages"
if [ -n "$APP_PKG" ] && [ -f "$APP_PKG" ]; then
  cp "$APP_PKG" "$APP_DIR/release/" 2>/dev/null || true
fi
if command -v tar >/dev/null 2>&1; then
  PKG_TMP="/tmp/wg-webui-current-package-$$"
  rm -rf "$PKG_TMP"
  mkdir -p "$PKG_TMP/wg-webui-v${PKG_VERSION}/bundle"
  cat > "$PKG_TMP/wg-webui-v${PKG_VERSION}/wg-webui.sh" <<'EOF_ROOT_ENTRY'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/bundle" ]; then
  CORE_DIR="$SCRIPT_DIR/bundle"
else
  CORE_DIR="$SCRIPT_DIR"
fi
export WG_WEBUI_SOURCE_DIR="$CORE_DIR"
SERVICE="wg-webui"

need_core(){
  [ -d "$CORE_DIR" ] || { echo "❌ 未找到核心目录，请在完整发布包根目录执行。"; exit 1; }
  [ -d "$CORE_DIR/scripts" ] || { echo "❌ 未找到 scripts/ 目录，发布包不完整。"; exit 1; }
}
need_root_hint(){
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "⚠️ 当前不是 root，安装/升级/卸载/诊断可能需要 sudo。"
  fi
}
run_install(){ need_core; exec bash "$CORE_DIR/scripts/install.sh" "$@"; }
run_upgrade(){ need_core; exec bash "$CORE_DIR/scripts/upgrade.sh" "$@"; }
run_doctor(){ need_core; exec bash "$CORE_DIR/scripts/doctor.sh" "$@"; }
run_uninstall(){ need_core; exec bash "$CORE_DIR/scripts/uninstall.sh" "$@"; }
service_status(){
  if command -v systemctl >/dev/null 2>&1; then
    systemctl status "$SERVICE" --no-pager || true
  else
    echo "当前系统未检测到 systemctl。"
  fi
}
service_restart(){
  if command -v systemctl >/dev/null 2>&1; then
    need_root_hint
    systemctl restart "$SERVICE"
    systemctl status "$SERVICE" --no-pager || true
  else
    echo "当前系统未检测到 systemctl。"
  fi
}
show_logs(){
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u "$SERVICE" -n 80 --no-pager || true
  else
    echo "当前系统未检测到 journalctl。"
  fi
}
show_help(){
  cat <<'HELP'
用法：
  bash wg-webui.sh

说明：
  直接执行后会打开交互菜单，通过数字选择安装、升级、诊断、卸载等操作。
HELP
}
menu(){
  need_core
  while true; do
    echo
    echo "========== WireGuard WebUI 管理 =========="
    echo "1) 安装 / 首次部署"
    echo "2) 升级 WebUI"
    echo "3) 运行诊断"
    echo "4) 卸载 / 清理"
    echo "5) 查看 WebUI 服务状态"
    echo "6) 重启 WebUI 服务"
    echo "7) 查看 WebUI 日志"
    echo "0) 退出"
    echo "========================================="
    read -r -p "请选择 [0-7]: " ans
    case "$ans" in
      1) need_root_hint; run_install ;;
      2)
        need_root_hint
        echo "请输入升级包路径，例如：/tmp/wg-webui-v1.12.42.tar.gz"
        read -r -p "升级包路径: " pkg
        [ -n "$pkg" ] || { echo "❌ 升级包路径不能为空"; continue; }
        run_upgrade "$pkg"
        ;;
      3) need_root_hint; run_doctor ;;
      4) need_root_hint; run_uninstall ;;
      5) service_status ;;
      6) service_restart ;;
      7) show_logs ;;
      0) exit 0 ;;
      *) echo "无效选择，请输入 0-7。" ;;
    esac
  done
}

case "${1:-}" in
  "") menu ;;
  install) shift; run_install "$@" ;;
  upgrade) shift; run_upgrade "$@" ;;
  doctor|check) shift; run_doctor "$@" ;;
  uninstall|remove) shift; run_uninstall "$@" ;;
  status) shift; service_status "$@" ;;
  restart) shift; service_restart "$@" ;;
  logs|log) shift; show_logs "$@" ;;
  -h|--help|help) show_help ;;
  *) echo "未知参数：$1"; show_help; exit 1 ;;
esac
EOF_ROOT_ENTRY
  chmod +x "$PKG_TMP/wg-webui-v${PKG_VERSION}/wg-webui.sh"
  for f in README.md CHANGELOG.md VERSION; do
    [ -f "$APP_DIR/$f" ] && cp -a "$APP_DIR/$f" "$PKG_TMP/wg-webui-v${PKG_VERSION}/$f" 2>/dev/null || true
  done
  [ -f "$APP_DIR/release/manifest.json" ] && cp -a "$APP_DIR/release/manifest.json" "$PKG_TMP/wg-webui-v${PKG_VERSION}/manifest.json" 2>/dev/null || true
  (cd "$APP_DIR" && tar --exclude='venv' --exclude='__pycache__' --exclude='*.pyc' --exclude='release/*.tar.gz' -cpf - .) | (cd "$PKG_TMP/wg-webui-v${PKG_VERSION}/bundle" && tar -xpf -) 2>/dev/null || true
  (cd "$PKG_TMP" && tar -czf "$APP_DIR/release/wg-webui-v${PKG_VERSION}.tar.gz" "wg-webui-v${PKG_VERSION}") 2>/dev/null || true
  rm -rf "$PKG_TMP"
  cp "$APP_DIR/release/wg-webui-v${PKG_VERSION}.tar.gz" "/var/lib/wg-webui/packages/" 2>/dev/null || true
fi
cat > "$APP_DIR/release/manifest.json" <<EOF_MANIFEST
{
  "version": "$PKG_VERSION",
  "package_name": "wg-webui-v${PKG_VERSION}.tar.gz",
  "packages": {
    "main": "wg-webui-v${PKG_VERSION}.tar.gz"
  },
  "usage": "统一完整包：网页在线升级和新服务器首次部署都使用 wg-webui-v*.tar.gz"
}
EOF_MANIFEST

log "安装完成：http://服务器IP:$PORT 默认账号 admin 密码 changeme"
log "配置文件：$CONFIG_FILE"
log "安装日志：$LOG_FILE"
