#!/usr/bin/env bash
set -uo pipefail

PACKAGE="${1:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/wg-webui}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/wg-webui-backups}"
UPGRADE_ROOT="${UPGRADE_ROOT:-/opt/wg-webui-upgrade}"
SERVICE="${SERVICE:-wg-webui}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8080/api/version}"
KEEP="${BACKUP_KEEP:-3}"
LOG_DIR="$UPGRADE_ROOT/logs"
TS="$(date +%F-%H%M%S)-$$"
LOG_FILE="$LOG_DIR/upgrade-$TS.log"
STATUS_FILE="$UPGRADE_ROOT/status.json"
LOCK_FILE="$UPGRADE_ROOT/upgrade.lock"
TMP_DIR="/tmp/wg-webui-upgrade-$TS"
BACKUP_DIR="$BACKUP_ROOT/$TS"
PREV_DIR="$INSTALL_DIR.__failed_$TS"
START_HELPER="$UPGRADE_ROOT/start-webui-$TS.sh"
START_READY="$UPGRADE_ROOT/start-ready-$TS.flag"
CONFIG_DIR="${WEBUI_CONFIG_DIR:-/etc/wg-webui}"
CONFIG_FILE="${WEBUI_CONFIG:-$CONFIG_DIR/config.json}"

mkdir -p "$BACKUP_ROOT" "$UPGRADE_ROOT/packages" "$LOG_DIR"
ln -sfn "$LOG_FILE" "$UPGRADE_ROOT/latest.log" 2>/dev/null || true

json_escape(){ python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'; }
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
write_status(){
  local status="$1"; local step="$2"; local msg="$3"
  local esc_msg; esc_msg="$(printf '%s' "$msg" | json_escape)"
  local esc_log; esc_log="$(printf '%s' "$LOG_FILE" | json_escape)"
  printf '{"status":"%s","step":"%s","message":"%s","time":"%s","log":"%s"}\n' "$status" "$step" "$esc_msg" "$(date '+%F %T')" "$esc_log" > "$STATUS_FILE" 2>/dev/null || true
}

check_webui_health(){
  python3 - "$HEALTH_URL" >>"$LOG_FILE" 2>&1 <<'PY'
import sys, urllib.request
url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=8) as r:
        body = r.read(200).decode('utf-8', 'ignore')
    if r.status < 500:
        print(f"health ok: {url} {r.status} {body[:120]}")
        sys.exit(0)
except Exception as e:
    print(f"health failed: {url} {e}")
sys.exit(1)
PY
}

read_json_field(){
  local path="$1"; local key="$2"; local fallback="$3"
  python3 - "$path" "$key" "$fallback" <<'PY' 2>/dev/null || true
import json,sys
path,key,fallback=sys.argv[1],sys.argv[2],sys.argv[3]
try:
    data=json.load(open(path,encoding='utf-8'))
    val=data.get(key,fallback)
    print(val if val not in (None,"") else fallback)
except Exception:
    print(fallback)
PY
}


choose_pip_install(){
  local req="$1"
  local pip_bin="$INSTALL_DIR/venv/bin/pip"
  local common_opts=(--disable-pip-version-check --no-cache-dir --retries 5 --timeout 120)
  local indexes=()
  if [ -n "${PIP_INDEX_URL:-}" ]; then
    indexes+=("$PIP_INDEX_URL|${PIP_TRUSTED_HOST:-}")
  fi
  # 国内环境优先尝试国内镜像，最后再回退官方源。
  indexes+=(
    "https://pypi.tuna.tsinghua.edu.cn/simple|pypi.tuna.tsinghua.edu.cn"
    "https://mirrors.aliyun.com/pypi/simple|mirrors.aliyun.com"
    "https://pypi.mirrors.ustc.edu.cn/simple|pypi.mirrors.ustc.edu.cn"
    "https://repo.huaweicloud.com/repository/pypi/simple|repo.huaweicloud.com"
    "https://pypi.org/simple|pypi.org files.pythonhosted.org"
  )
  local item url trusted args
  for item in "${indexes[@]}"; do
    url="${item%%|*}"
    trusted="${item#*|}"
    log "尝试 pip 源：$url"
    args=("${common_opts[@]}" -i "$url")
    for h in $trusted; do
      [ -n "$h" ] && args+=(--trusted-host "$h")
    done
    if "$pip_bin" install "${args[@]}" -r "$req" >>"$LOG_FILE" 2>&1; then
      log "Python 依赖安装成功：$url"
      return 0
    fi
    log "pip 源失败，继续切换下一个：$url"
  done
  return 1
}

write_webui_service(){
  local port host env_tmp old_service
  port="$(read_json_field "$CONFIG_FILE" listen_port 8080)"
  host="$(read_json_field "$CONFIG_FILE" listen_host 0.0.0.0)"
  old_service="$BACKUP_DIR/wg-webui.service"
  env_tmp="$(mktemp)"
  {
    echo "Environment=WEBUI_CONFIG=$CONFIG_FILE"
    if [ -f "$old_service" ]; then
      grep -E '^Environment=' "$old_service" | grep -v 'WEBUI_CONFIG=' | grep -v 'WEBUI_INSTALL_DIR=' || true
    fi
  } | awk '!seen[$0]++' > "$env_tmp"
  cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=WireGuard WebUI
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR/app
EOF
  cat "$env_tmp" >> "/etc/systemd/system/$SERVICE.service"
  cat >> "/etc/systemd/system/$SERVICE.service" <<EOF
ExecStart=$INSTALL_DIR/venv/bin/uvicorn app:app --host $host --port $port
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  rm -f "$env_tmp" 2>/dev/null || true
  systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
  systemctl enable "$SERVICE" >>"$LOG_FILE" 2>&1 || true
  HEALTH_URL="http://127.0.0.1:${port}/api/version"
  log "已刷新 systemd 服务：$SERVICE，监听端口：$port"
}

migrate_reserved_networks(){
  mkdir -p "$CONFIG_DIR" 2>/dev/null || true
  [ -f "$CONFIG_FILE" ] || return 0
  local legacy=""
  if [ -f "$BACKUP_DIR/wg-webui/app.py" ]; then
    legacy="$(python3 -c 'import re,sys; t=open(sys.argv[1],encoding="utf-8",errors="ignore").read(); m=re.search(r"COMPANY_LAN_CIDR\s*=\s*os\.getenv\([^,]+,\s*[\"\047]([^\"\047]+)[\"\047]\)", t); print(m.group(1) if m else "")' "$BACKUP_DIR/wg-webui/app.py" 2>/dev/null || true)"
  fi
  [ -n "$legacy" ] || legacy="$(printenv COMPANY_LAN_CIDR 2>/dev/null || true)"
  python3 - "$CONFIG_FILE" "$legacy" <<'PY'
import json,sys,os,ipaddress
path,legacy=sys.argv[1],sys.argv[2].strip()
try:
    data=json.load(open(path,encoding='utf-8'))
except Exception:
    data={}
changed=False
reserved=data.get('reserved_client_allowed_ips')
if not isinstance(reserved,list):
    reserved=[]
    changed=True
if legacy:
    try:
        legacy=str(ipaddress.ip_network(legacy,strict=False))
        if legacy not in reserved:
            reserved.append(legacy)
            changed=True
    except Exception:
        pass
data['reserved_client_allowed_ips']=reserved
if changed:
    os.makedirs(os.path.dirname(path),exist_ok=True)
    open(path,'w',encoding='utf-8').write(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print('reserved_client_allowed_ips migrated:', ','.join(reserved))
else:
    print('reserved_client_allowed_ips unchanged:', ','.join(reserved))
PY
  chmod 600 "$CONFIG_FILE" 2>/dev/null || true
}

rollback(){
  log "开始自动回滚..."
  systemctl stop "$SERVICE" >>"$LOG_FILE" 2>&1 || true
  if [ -d "$BACKUP_DIR/wg-webui" ]; then
    rm -rf "$INSTALL_DIR"
    cp -a "$BACKUP_DIR/wg-webui" "$INSTALL_DIR"
    if [ -f "$BACKUP_DIR/wg-webui.service" ]; then
      cp -a "$BACKUP_DIR/wg-webui.service" "/etc/systemd/system/$SERVICE.service"
      systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
    fi
    systemctl reset-failed "$SERVICE" >>"$LOG_FILE" 2>&1 || true
    systemctl restart "$SERVICE" >>"$LOG_FILE" 2>&1 || true
    sleep 3
    if systemctl is-active --quiet "$SERVICE"; then
      log "✅ 已回滚到旧版本，WireGuard 隧道未被操作。"
    else
      log "⚠️ 已恢复旧文件，但 WebUI 服务仍未启动，请执行：systemctl start $SERVICE && journalctl -u $SERVICE -n 80"
    fi
  else
    log "⚠️ 找不到备份目录，无法回滚：$BACKUP_DIR/wg-webui"
  fi
}

fail(){ log "❌ $*"; write_status "failed" "rollback" "$*，开始自动回滚"; rollback; exit 1; }

ensure_platform_config(){
  mkdir -p "$CONFIG_DIR" 2>/dev/null || true
  if [ ! -f "$CONFIG_FILE" ]; then
    log "创建平台配置：$CONFIG_FILE"
    if [ -f "$NEW_DIR/config/config.json.sample" ]; then
      cp "$NEW_DIR/config/config.json.sample" "$CONFIG_FILE" 2>/dev/null || true
    else
      cp "$NEW_DIR/config.json.sample" "$CONFIG_FILE" 2>/dev/null || true
    fi
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
  else
    log "保留已有平台配置：$CONFIG_FILE"
  fi
  migrate_reserved_networks
}

soft_start_warning(){
  local msg="$1"
  log "⚠️ $msg"
  log "文件已经升级完成，但 WebUI 服务未自动恢复。"
  log "请手动执行：systemctl start $SERVICE"
  log "查看日志：journalctl -u $SERVICE -n 80 --no-pager"
  write_status "service_warning" "manual_start_required" "文件已升级完成，但服务未自动启动。请手动执行：systemctl start $SERVICE"
  exit 0
}

start_service_with_retry(){
  log "启动 WebUI 服务：$SERVICE"
  systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
  systemctl reset-failed "$SERVICE" >>"$LOG_FILE" 2>&1 || true
  for i in 1 2 3; do
    log "第 $i 次启动 $SERVICE ..."
    systemctl restart "$SERVICE" >>"$LOG_FILE" 2>&1 && break
    log "systemctl start 返回失败，等待后重试..."
    sleep 3
    systemctl reset-failed "$SERVICE" >>"$LOG_FILE" 2>&1 || true
  done
  sleep 5
  systemctl is-active --quiet "$SERVICE"
}


merge_sample_reserved_networks(){
  log "合并样例配置里的保留网段到平台配置..."
  SAMPLE_FILE="$NEW_DIR/config/config.json.sample"
  [ -f "$SAMPLE_FILE" ] || SAMPLE_FILE="$NEW_DIR/config.json.sample"
  python3 - "$CONFIG_FILE" "$SAMPLE_FILE" <<'PY_MERGE' >>"$LOG_FILE" 2>&1 || true
import json,sys,os,ipaddress
config_path,sample_path=sys.argv[1],sys.argv[2]
def load(p):
    try:
        with open(p,encoding='utf-8') as f:
            x=json.load(f)
        return x if isinstance(x,dict) else {}
    except Exception:
        return {}
def norm(v):
    try:
        n=ipaddress.ip_network(str(v).strip(),strict=False)
        return str(n) if n.version==4 else ''
    except Exception:
        return ''
cfg=load(config_path)
sample=load(sample_path)
reserved=cfg.get('reserved_client_allowed_ips')
if not isinstance(reserved,list):
    reserved=[]
changed=False
for item in sample.get('reserved_client_allowed_ips',[]):
    n=norm(item)
    if n and n not in reserved:
        reserved.append(n); changed=True
cfg['reserved_client_allowed_ips']=reserved
if changed:
    os.makedirs(os.path.dirname(config_path),exist_ok=True)
    with open(config_path,'w',encoding='utf-8') as f:
        json.dump(cfg,f,ensure_ascii=False,indent=2); f.write('\n')
    print('reserved_client_allowed_ips merged:', ','.join(reserved))
else:
    print('reserved_client_allowed_ips unchanged:', ','.join(reserved))
PY_MERGE
  chmod 600 "$CONFIG_FILE" 2>/dev/null || true
}

sync_existing_client_allowedips(){
  log "同步已有用户配置 AllowedIPs..."
  if [ -x "$INSTALL_DIR/tools/repair_allowedips.py" ]; then
    WEBUI_CONFIG="$CONFIG_FILE" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/tools/repair_allowedips.py" --config "$CONFIG_FILE" --sample "$INSTALL_DIR/config/config.json.sample" >>"$LOG_FILE" 2>&1 || true
  elif [ -x "$INSTALL_DIR/tools/sync_allowedips.py" ]; then
    WEBUI_CONFIG="$CONFIG_FILE" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/tools/sync_allowedips.py" --config "$CONFIG_FILE" --sample "$INSTALL_DIR/config/config.json.sample" >>"$LOG_FILE" 2>&1 || true
  elif [ -x "$INSTALL_DIR/sync_allowedips.py" ]; then
    WEBUI_CONFIG="$CONFIG_FILE" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/sync_allowedips.py" --config "$CONFIG_FILE" --sample "$INSTALL_DIR/config/config.json.sample" >>"$LOG_FILE" 2>&1 || true
  else
    WEBUI_CONFIG="$CONFIG_FILE" WEBUI_INSTALL_DIR="$INSTALL_DIR" "$INSTALL_DIR/venv/bin/python" - <<'PY_SYNC' >>"$LOG_FILE" 2>&1 || true
try:
    import app
    app.ensure_reserved_config_from_sample()
    result = app.sync_existing_user_allowedips_once()
    print('sync_existing_user_allowedips_once:', result)
except Exception as e:
    print('client_allowedips_sync warning:', e)
PY_SYNC
  fi
}

create_delayed_start_helper(){
  cat > "$START_HELPER" <<EOS
#!/usr/bin/env bash
set +e
LOG_FILE="$LOG_FILE"
SERVICE="$SERVICE"
READY="$START_READY"
INSTALL_DIR="$INSTALL_DIR"
SERVICE_FILE="/etc/systemd/system/$SERVICE.service"
echo "[\$(date '+%F %T')] restart helper: waiting ready flag \$READY" >>"\$LOG_FILE"
for i in \$(seq 1 120); do
  [ -f "\$READY" ] && break
  sleep 1
done
if [ ! -f "\$READY" ]; then
  echo "[\$(date '+%F %T')] restart helper: ready flag timeout, still trying restart" >>"\$LOG_FILE"
fi
systemctl daemon-reload >>"\$LOG_FILE" 2>&1 || true
systemctl reset-failed "\$SERVICE" >>"\$LOG_FILE" 2>&1 || true
systemctl enable "\$SERVICE" >>"\$LOG_FILE" 2>&1 || true
for i in 1 2 3 4 5; do
  echo "[\$(date '+%F %T')] restart helper: restart attempt \$i" >>"\$LOG_FILE"
  systemctl restart "\$SERVICE" >>"\$LOG_FILE" 2>&1 && break
  sleep 3
  systemctl reset-failed "\$SERVICE" >>"\$LOG_FILE" 2>&1 || true
done
sleep 5
if systemctl is-active --quiet "\$SERVICE"; then
  echo "[\$(date '+%F %T')] restart helper: service active" >>"\$LOG_FILE"
else
  echo "[\$(date '+%F %T')] restart helper: service not active" >>"\$LOG_FILE"
  journalctl -u "\$SERVICE" -n 80 --no-pager >>"\$LOG_FILE" 2>&1 || true
fi
EOS
  chmod +x "$START_HELPER" 2>/dev/null || true
}

launch_start_helper(){
  create_delayed_start_helper
  rm -f "$START_READY" 2>/dev/null || true
  if command -v systemd-run >/dev/null 2>&1; then
    log "启动独立 systemd-run 延迟重启守护..."
    systemd-run --unit="wg-webui-restart-$TS" --collect /bin/bash "$START_HELPER" >>"$LOG_FILE" 2>&1 || nohup /bin/bash "$START_HELPER" >/dev/null 2>&1 &
  else
    log "未检测到 systemd-run，使用 nohup 延迟重启守护..."
    nohup /bin/bash "$START_HELPER" >/dev/null 2>&1 &
  fi
}

signal_start_helper_ready(){
  mkdir -p "$UPGRADE_ROOT" 2>/dev/null || true
  date '+%F %T' > "$START_READY" 2>/dev/null || true
}

LOCK_ACQUIRED=0
cleanup(){
  rm -rf "$TMP_DIR" "$PREV_DIR" 2>/dev/null || true
  if [ "$LOCK_ACQUIRED" = "1" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null || true)" = "$$" ]; then
    rm -f "$LOCK_FILE" 2>/dev/null || true
  fi
}

if [ -e "$LOCK_FILE" ]; then
  oldpid="$(cat "$LOCK_FILE" 2>/dev/null || true)"
  if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
    log "已有升级任务正在运行，PID=$oldpid"
    exit 1
  fi
  rm -f "$LOCK_FILE" 2>/dev/null || true
fi
echo $$ > "$LOCK_FILE"
LOCK_ACQUIRED=1
trap cleanup EXIT

write_status "running" "start" "升级开始"
log "========== WireGuard WebUI 升级开始 =========="
log "说明：本升级只操作 $SERVICE，不停止、不重启 wg-quick@wg0。"

[ -n "$PACKAGE" ] || fail "未指定升级包"
[ -f "$PACKAGE" ] || fail "升级包不存在：$PACKAGE"
tar -tzf "$PACKAGE" >/dev/null 2>&1 || fail "升级包不是有效 tar.gz：$PACKAGE"

mkdir -p "$BACKUP_DIR"
if [ -d "$INSTALL_DIR" ]; then
  write_status "running" "backup" "备份当前版本"
  log "备份当前版本到：$BACKUP_DIR/wg-webui"
  cp -a "$INSTALL_DIR" "$BACKUP_DIR/wg-webui" || fail "备份当前版本失败"
else
  fail "当前安装目录不存在：$INSTALL_DIR"
fi
if [ -f "/etc/systemd/system/$SERVICE.service" ]; then
  cp -a "/etc/systemd/system/$SERVICE.service" "$BACKUP_DIR/wg-webui.service" || true
fi

mkdir -p "$TMP_DIR"
write_status "running" "extract" "解压升级包"
log "解压升级包..."
tar -xzf "$PACKAGE" -C "$TMP_DIR" || fail "解压失败"

NEW_DIR=""
for d in "$TMP_DIR"/*; do
  if [ -d "$d" ] && [ -f "$d/app/app.py" ]; then
    NEW_DIR="$d"
    break
  fi
  if [ -d "$d" ] && [ -f "$d/bundle/app/app.py" ]; then
    NEW_DIR="$d/bundle"
    break
  fi
  if [ -d "$d" ] && [ -f "$d/app.py" ]; then
    NEW_DIR="$d"
    break
  fi
done
if [ -z "$NEW_DIR" ] && [ -f "$TMP_DIR/app/app.py" ]; then
  NEW_DIR="$TMP_DIR"
fi
if [ -z "$NEW_DIR" ] && [ -f "$TMP_DIR/bundle/app/app.py" ]; then
  NEW_DIR="$TMP_DIR/bundle"
fi
if [ -z "$NEW_DIR" ] && [ -f "$TMP_DIR/app.py" ]; then
  NEW_DIR="$TMP_DIR"
fi
[ -n "$NEW_DIR" ] || fail "升级包结构错误：未找到 app/app.py 或 app.py"
if [ -f "$NEW_DIR/app/app.py" ]; then
  [ -f "$NEW_DIR/app/requirements.txt" ] || fail "升级包结构错误：未找到 app/requirements.txt"
else
  [ -f "$NEW_DIR/requirements.txt" ] || fail "升级包结构错误：未找到 requirements.txt"
fi
[ -f "$NEW_DIR/upgrade.sh" ] || fail "升级包结构错误：未找到 upgrade.sh"
if [ ! -f "$NEW_DIR/README.md" ] && [ ! -f "$NEW_DIR/PROJECT_CONTEXT.md" ]; then
  fail "升级包结构错误：未找到 README.md / PROJECT_CONTEXT.md"
fi
log "升级包结构检查通过：$NEW_DIR"
write_status "running" "config" "初始化/迁移平台配置"
ensure_platform_config
merge_sample_reserved_networks
launch_start_helper

write_status "running" "stop_webui" "停止 WebUI，不影响 WireGuard"
log "停止 WebUI 服务，不影响 WireGuard 隧道..."
systemctl stop "$SERVICE" >>"$LOG_FILE" 2>&1 || true
sleep 2

write_status "running" "replace" "替换程序目录"
log "替换程序目录..."
mv "$INSTALL_DIR" "$PREV_DIR" || fail "移动旧目录失败"
mkdir -p "$INSTALL_DIR" || fail "创建新目录失败"
( cd "$NEW_DIR" && tar -cpf - . ) | ( cd "$INSTALL_DIR" && tar -xpf - ) || fail "复制新版本失败"

if [ ! -d "$INSTALL_DIR/venv" ]; then
  if [ -d "$BACKUP_DIR/wg-webui/venv" ]; then
    log "复用旧版本 venv..."
    cp -a "$BACKUP_DIR/wg-webui/venv" "$INSTALL_DIR/venv" || fail "复制 venv 失败"
  else
    log "创建新的 venv..."
    python3 -m venv "$INSTALL_DIR/venv" || fail "创建 venv 失败，请确认已安装 python3-venv"
  fi
fi

if [ -f "$INSTALL_DIR/app/requirements.txt" ]; then
  log "检查/安装 Python 依赖..."
  choose_pip_install "$INSTALL_DIR/app/requirements.txt" || fail "安装依赖失败。可指定镜像重试：PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple bash wg-webui.sh 后在菜单选择升级"
else
  fail "升级包缺少 app/requirements.txt"
fi

write_status "running" "service" "刷新 systemd 服务"
write_webui_service

write_status "running" "repair_wg_nat" "校准 WireGuard NAT 网段"
if [ -x "$INSTALL_DIR/tools/repair_wg_nat.py" ]; then
  WEBUI_CONFIG="$CONFIG_FILE" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/tools/repair_wg_nat.py" --config "$CONFIG_FILE" --apply-live >>"$LOG_FILE" 2>&1 || log "WARN: WireGuard NAT 网段校准失败，请运行：sudo bash wg-webui.sh 检查"
fi

write_status "running" "sync_allowedips" "同步用户 AllowedIPs"
sync_existing_client_allowedips

chmod +x "$INSTALL_DIR/upgrade.sh" 2>/dev/null || true
signal_start_helper_ready
mkdir -p "$UPGRADE_ROOT"
cp -a "$INSTALL_DIR/upgrade.sh" "$UPGRADE_ROOT/upgrade.sh" 2>/dev/null || true
mkdir -p "$UPGRADE_ROOT/scripts"
cp -a "$INSTALL_DIR/scripts/upgrade.sh" "$UPGRADE_ROOT/scripts/upgrade.sh" 2>/dev/null || true
chmod +x "$UPGRADE_ROOT/upgrade.sh" "$UPGRADE_ROOT/scripts/upgrade.sh" 2>/dev/null || true

write_status "running" "start_webui" "启动新版 WebUI"
create_delayed_start_helper
# 优先直接启动；若当前升级服务/旧进程干扰，后台 helper 会再补一次。
if ! start_service_with_retry; then
  log "直接启动未确认成功，交给后台延迟启动脚本再尝试一次。"
  nohup "$START_HELPER" >/dev/null 2>&1 &
  sleep 8
fi

if ! systemctl is-active --quiet "$SERVICE"; then
  soft_start_warning "$SERVICE 未运行"
fi

log "检测 WebUI HTTP 服务：$HEALTH_URL"
if ! check_webui_health; then
  log "HTTP 健康检查第一次失败，等待 5 秒后重试。"
  sleep 5
  if ! check_webui_health; then
    log "⚠️ HTTP 健康检查未通过，但 systemd 服务已经 active。"
    write_status "service_warning" "health_warning" "文件已升级，服务已启动，但 HTTP 健康检查暂未通过。请刷新页面或查看日志。"
  fi
fi

write_status "running" "cleanup" "清理旧备份"
log "清理旧备份，只保留最近 $KEEP 个..."
mapfile -t backups < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk '{print $2}')
idx=0
for b in "${backups[@]}"; do
  idx=$((idx+1))
  if [ "$idx" -gt "$KEEP" ]; then
    log "删除旧备份：$b"
    rm -rf "$b" || true
  fi
done

write_status "success" "done" "升级完成，服务已启动"
log "✅ 升级完成。当前备份：$BACKUP_DIR"
log "========== WireGuard WebUI 升级结束 =========="
exit 0
