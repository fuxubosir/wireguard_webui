#!/usr/bin/env python3
import base64
import io
import os
import re
import shutil
import shlex
import socket
import subprocess
import sys
import json
import platform
import hmac
import hashlib
import secrets
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import qrcode
from fastapi import FastAPI, HTTPException, Depends, Request, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from core.networks import (
    NetworkValidationError,
    csv_or_list as core_csv_or_list,
    network_from_cidr as core_network_from_cidr,
    normalize_allowed_ips as core_normalize_allowed_ips,
    normalize_ipv4_networks,
)
from core.security import LoginAttemptLimiter, as_bool

CONFIG_FILE = Path(os.getenv("WEBUI_CONFIG", "/etc/wg-webui/config.json"))

DEFAULT_CONFIG = {
    "wg_if": "wg0",
    "wg_net": "10.6.0",
    "wg_cidr": "10.6.0.0/24",
    "server_endpoint": "",
    "client_dns": "",
    "client_allowed_ips": [],
    "reserved_client_allowed_ips": [],
    "user_owners": {},
    "site_remarks": {},
    "user_site_permissions": {},
    "webui_user": "admin",
    "webui_password_hash": "",
    "site_ip_start": 2,
    "site_ip_end": 49,
    "user_ip_start": 50,
    "user_ip_end": 200,
    "backup_keep": 5,
    "client_dir": "/etc/wireguard/clients",
    "qr_dir": "/etc/wireguard/qr",
    "site_dir": "/etc/wireguard/site-configs",
    "online_threshold_seconds": 180,
    "login_max_attempts": 5,
    "login_window_seconds": 300,
    "login_lockout_seconds": 300,
    "cookie_secure": False,
    "install_dir": "/opt/wg-webui",
    "upgrade_root": "/opt/wg-webui-upgrade",
    "release_dir": "",
    "webui_backup_root": "/opt/wg-webui-backups",
    "webui_backup_keep": 3,
    "session_cookie": "wg_webui_session",
    "session_ttl_seconds": 1800,
    "listen_host": "0.0.0.0",
    "listen_port": 8080
}

def _load_config() -> Dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        if CONFIG_FILE.exists():
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg.update(loaded)
    except Exception:
        pass
    return cfg

def _cfg(name: str, env_name: str = "", default=None):
    if env_name and os.getenv(env_name) not in (None, ""):
        return os.getenv(env_name)
    return RUNTIME_CONFIG.get(name, default)

def _csv_or_list(value) -> List[str]:
    return core_csv_or_list(value)

def _read_wg_conf_address(wg_if: str) -> str:
    conf = Path(os.getenv("WG_CONF", f"/etc/wireguard/{wg_if}.conf"))
    try:
        for line in conf.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.lower().startswith("address") and "=" in line:
                val = line.split("=", 1)[1].strip().split(",", 1)[0].strip()
                if val:
                    return val
    except Exception:
        pass
    return ""


def _network_from_cidr(value: str) -> tuple[str, str]:
    # Current IP allocation keeps the existing /24-style wg_net prefix.
    return core_network_from_cidr(value, DEFAULT_CONFIG["wg_cidr"])


def _normalize_runtime_wg_network(cfg: Dict) -> Dict:
    # 已运行系统以 /etc/wireguard/wgX.conf 的 Interface Address 为准。
    # 这样首次安装时即使用户填写 10.8.0.1/24，WebUI 也会自动使用 10.8.0 地址池。
    cfg = dict(cfg)
    wg_if = str(cfg.get("wg_if") or DEFAULT_CONFIG["wg_if"])
    conf_addr = _read_wg_conf_address(wg_if)
    source = conf_addr or cfg.get("wg_cidr") or DEFAULT_CONFIG["wg_cidr"]
    wg_cidr, wg_net = _network_from_cidr(str(source))
    changed = cfg.get("wg_cidr") != wg_cidr or cfg.get("wg_net") != wg_net
    cfg["wg_cidr"] = wg_cidr
    cfg["wg_net"] = wg_net
    if changed and CONFIG_FILE.exists():
        try:
            old = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(old, dict):
                old["wg_cidr"] = wg_cidr
                old["wg_net"] = wg_net
                CONFIG_FILE.write_text(json.dumps(old, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except Exception:
            pass
    return cfg


RUNTIME_CONFIG = _normalize_runtime_wg_network(_load_config())
WG_IF = str(_cfg("wg_if", "WG_IF", "wg0"))
WG_CONF = Path(os.getenv("WG_CONF", f"/etc/wireguard/{WG_IF}.conf"))
WG_NET = str(_cfg("wg_net", "WG_NET", "10.6.0"))
WG_CIDR = str(_cfg("wg_cidr", "WG_CIDR", "10.6.0.0/24"))
SERVER_ENDPOINT = str(_cfg("server_endpoint", "SERVER_ENDPOINT", ""))
CLIENT_DNS = str(_cfg("client_dns", "CLIENT_DNS", ""))
CLIENT_ALLOWED_IPS = _csv_or_list(os.getenv("CLIENT_ALLOWED_IPS") or RUNTIME_CONFIG.get("client_allowed_ips", []))
RESERVED_CLIENT_ALLOWED_IPS = _csv_or_list(os.getenv("RESERVED_CLIENT_ALLOWED_IPS") or RUNTIME_CONFIG.get("reserved_client_allowed_ips", []))
# 兼容旧版应急变量：仅在管理员显式设置 COMPANY_LAN_CIDR 时使用，不再在代码里写死任何公司网段。
if os.getenv("COMPANY_LAN_CIDR"):
    RESERVED_CLIENT_ALLOWED_IPS.append(os.getenv("COMPANY_LAN_CIDR", ""))
SITE_IP_START = int(_cfg("site_ip_start", "SITE_IP_START", 2))
SITE_IP_END = int(_cfg("site_ip_end", "SITE_IP_END", 49))
USER_IP_START = int(_cfg("user_ip_start", "USER_IP_START", 50))
USER_IP_END = int(_cfg("user_ip_end", "USER_IP_END", 200))
BACKUP_KEEP = int(_cfg("backup_keep", "BACKUP_KEEP", 5))
CLIENT_DIR = Path(str(_cfg("client_dir", "CLIENT_DIR", "/etc/wireguard/clients")))
QR_DIR = Path(str(_cfg("qr_dir", "QR_DIR", "/etc/wireguard/qr")))
SITE_DIR = Path(str(_cfg("site_dir", "SITE_DIR", "/etc/wireguard/site-configs")))
WEBUI_USER = os.getenv("WEBUI_USER") or str(RUNTIME_CONFIG.get("webui_user") or "admin")
WEBUI_PASSWORD = os.getenv("WEBUI_PASSWORD", "changeme")
# 在线判断阈值：WireGuard 不会上报“主动断开”，只能看最后握手时间。
ONLINE_THRESHOLD_SECONDS = int(_cfg("online_threshold_seconds", "ONLINE_THRESHOLD_SECONDS", 180))
LOGIN_MAX_ATTEMPTS = max(1, int(_cfg("login_max_attempts", "WEBUI_LOGIN_MAX_ATTEMPTS", 5)))
LOGIN_WINDOW_SECONDS = max(30, int(_cfg("login_window_seconds", "WEBUI_LOGIN_WINDOW_SECONDS", 300)))
LOGIN_LOCKOUT_SECONDS = max(30, int(_cfg("login_lockout_seconds", "WEBUI_LOGIN_LOCKOUT_SECONDS", 300)))
COOKIE_SECURE = as_bool(_cfg("cookie_secure", "WEBUI_COOKIE_SECURE", False), False)
LOGIN_LIMITER = LoginAttemptLimiter(
    max_attempts=LOGIN_MAX_ATTEMPTS,
    window_seconds=LOGIN_WINDOW_SECONDS,
    lockout_seconds=LOGIN_LOCKOUT_SECONDS,
)
APP_VERSION = "v2.0.0"

APPLY_STATE_FILE = CONFIG_FILE.with_name("apply_state.json")

def wg_conf_hash() -> str:
    try:
        return hashlib.sha256(WG_CONF.read_bytes()).hexdigest()
    except Exception:
        return ""

def read_apply_state() -> Dict[str, object]:
    try:
        if APPLY_STATE_FILE.exists():
            data = json.loads(APPLY_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}

def write_apply_state(data: Dict[str, object]) -> None:
    APPLY_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(data)
    payload["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    APPLY_STATE_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        APPLY_STATE_FILE.chmod(0o600)
    except Exception:
        pass

def mark_apply_pending(reason: str) -> None:
    state = read_apply_state()
    state["pending"] = True
    state["pending_reason"] = reason
    state["pending_conf_hash"] = wg_conf_hash()
    write_apply_state(state)

def clear_apply_pending(message: str = "配置已应用") -> None:
    state = read_apply_state()
    state["pending"] = False
    state["pending_reason"] = ""
    state["last_applied_conf_hash"] = wg_conf_hash()
    state["last_apply_message"] = message
    state["stale_route_cidrs"] = []
    write_apply_state(state)


def mark_stale_routes(cidrs: List[str], reason: str = "删除站点后需要应用配置并清理旧路由") -> None:
    state = read_apply_state()
    existing = set(str(x) for x in state.get("stale_route_cidrs", []) if x)
    for cidr in cidrs:
        if cidr:
            existing.add(cidr)
    state["stale_route_cidrs"] = sorted(existing)
    state["pending"] = True
    state["pending_reason"] = reason
    state["pending_conf_hash"] = wg_conf_hash()
    write_apply_state(state)

INSTALL_DIR = Path(str(_cfg("install_dir", "WEBUI_INSTALL_DIR", "/opt/wg-webui")))
UPGRADE_ROOT = Path(str(_cfg("upgrade_root", "WEBUI_UPGRADE_ROOT", "/opt/wg-webui-upgrade")))
UPGRADE_PACKAGE_DIR = UPGRADE_ROOT / "packages"
UPGRADE_LOG_DIR = UPGRADE_ROOT / "logs"
RELEASE_DIR = Path(str(_cfg("release_dir", "WEBUI_RELEASE_DIR", str(INSTALL_DIR / "release")) or (INSTALL_DIR / "release")))
BACKUP_ROOT_WEBUI = Path(str(_cfg("webui_backup_root", "WEBUI_BACKUP_ROOT", "/opt/wg-webui-backups")))
WEBUI_BACKUP_KEEP = int(_cfg("webui_backup_keep", "WEBUI_BACKUP_KEEP", 3))
SESSION_COOKIE = str(_cfg("session_cookie", "WEBUI_SESSION_COOKIE", "wg_webui_session"))
SESSION_TTL_SECONDS = int(_cfg("session_ttl_seconds", "SESSION_TTL_SECONDS", 86400))
SESSION_SECRET = os.getenv("WEBUI_SESSION_SECRET") or secrets.token_hex(32)

app = FastAPI(title="WireGuard WebUI Lite")
STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
security = HTTPBasic(auto_error=False)

NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
EXISTING_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")
CIDR_RE = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")


def _current_webui_user() -> str:
    if _account_env_locked():
        return os.getenv("WEBUI_USER", "admin")
    return str(_load_json_dict(CONFIG_FILE).get("webui_user") or WEBUI_USER or "admin")


def _account_env_locked() -> bool:
    env_user = os.getenv("WEBUI_USER")
    env_pass = os.getenv("WEBUI_PASSWORD")
    return bool((env_user and env_user != "admin") or (env_pass and env_pass != "changeme"))


def _hash_password(password: str, salt: str = "", iterations: int = 180000) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", str(password).encode(), salt.encode(), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def _verify_password_hash(password: str, encoded: str) -> bool:
    try:
        alg, iterations_s, salt, expected = str(encoded or "").split("$", 3)
        if alg != "pbkdf2_sha256":
            return False
        actual = _hash_password(password, salt, int(iterations_s)).split("$", 3)[3]
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _verify_webui_credentials(username: str, password: str) -> bool:
    user = _current_webui_user()
    if username != user:
        return False
    cfg = _load_json_dict(CONFIG_FILE)
    password_hash = "" if _account_env_locked() else str(cfg.get("webui_password_hash") or "")
    if password_hash:
        return _verify_password_hash(password, password_hash)
    return hmac.compare_digest(str(password), WEBUI_PASSWORD)


def _default_password_active() -> bool:
    if _account_env_locked():
        return WEBUI_USER == "admin" and WEBUI_PASSWORD == "changeme"
    cfg = _load_json_dict(CONFIG_FILE)
    return str(cfg.get("webui_user") or "admin") == "admin" and not str(cfg.get("webui_password_hash") or "")


def normalize_site_cidrs(raw: str, allow_empty: bool = False) -> List[str]:
    """站点内网网段只允许用英文逗号分隔，避免生成 WireGuard 配置时出现不可控分隔符。"""
    value = str(raw or "").strip()
    if not value:
        if allow_empty:
            return []
        raise HTTPException(status_code=400, detail="请至少填写一个站点内网网段")
    if re.search(r"[，;；\n\r\t]", value):
        raise HTTPException(status_code=400, detail="多个网段只支持英文逗号 , 分隔，例如：192.168.23.0/24,192.168.24.0/24")
    parts = value.split(",")
    out: List[str] = []
    seen = set()
    for part in parts:
        cidr = part.strip()
        if not cidr:
            raise HTTPException(status_code=400, detail="网段列表中存在空项，请检查逗号前后内容")
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"网段格式错误：{cidr}，例如 192.168.23.0/24")
        if net.version != 4:
            raise HTTPException(status_code=400, detail=f"暂只支持 IPv4 网段：{cidr}")
        normalized = str(net)
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    if not out:
        raise HTTPException(status_code=400, detail="请至少填写一个站点内网网段")
    return out


def detect_site_cidr_conflicts(new_cidrs: List[str], ignore_site: str = "") -> List[Dict[str, str]]:
    """检测站点内网网段冲突。

    v1.11.25 只做检测和处理提示，不自动生成映射 NAT。冲突类型包括：
    - 与公司 WireGuard 网段重叠；
    - 与本地/保留网段重叠；
    - 与其他站点内网网段重叠；
    - 同一次提交中的网段互相包含/重叠。
    """
    conflicts: List[Dict[str, str]] = []
    new_nets = [(cidr, ipaddress.ip_network(cidr, strict=False)) for cidr in new_cidrs]

    # 同一次提交中互相重叠，例如 192.168.1.0/24 和 192.168.1.0/25。
    for i, (cidr_a, net_a) in enumerate(new_nets):
        for cidr_b, net_b in new_nets[i + 1:]:
            if net_a.overlaps(net_b):
                conflicts.append({
                    "type": "input",
                    "site": "当前输入",
                    "new": cidr_a,
                    "existing": cidr_b,
                    "message": "同一站点输入的网段互相重叠",
                })

    # 站点内网不能和公司 WG 地址池重叠，否则 AllowedIPs/路由会抢同一地址池。
    try:
        wg_net = ipaddress.ip_network(WG_CIDR, strict=False)
        for new_cidr, new_net in new_nets:
            if new_net.overlaps(wg_net):
                conflicts.append({
                    "type": "vpn",
                    "site": "公司VPN网段",
                    "new": new_cidr,
                    "existing": str(wg_net),
                    "message": "站点内网不能和公司 WireGuard 网段重叠",
                })
    except Exception:
        pass

    for fixed in fixed_client_allowed_ips():
        try:
            fixed_net = ipaddress.ip_network(str(fixed).strip(), strict=False)
        except Exception:
            continue
        for new_cidr, new_net in new_nets:
            if new_net.overlaps(fixed_net):
                conflicts.append({
                    "type": "reserved",
                    "site": "本地/保留网段",
                    "new": new_cidr,
                    "existing": str(fixed_net),
                    "message": "站点内网与本地/保留网段重叠",
                })
    try:
        peers = parse_wg_conf()
    except Exception:
        peers = []
    for p in peers:
        if p.get("type") != "site" or p.get("name") == ignore_site:
            continue
        for part in str(p.get("allowed_ips", "")).split(","):
            old_cidr = part.strip()
            if not old_cidr or old_cidr.startswith(f"{WG_NET}.") or old_cidr == WG_CIDR:
                continue
            try:
                old_net = ipaddress.ip_network(old_cidr, strict=False)
            except ValueError:
                continue
            for new_cidr, new_net in new_nets:
                if new_net.overlaps(old_net):
                    conflicts.append({
                        "type": "site",
                        "site": str(p.get("name", "")),
                        "new": new_cidr,
                        "existing": str(old_net),
                        "message": "站点内网与其他站点重叠",
                    })
    return conflicts


def format_site_conflict_message(conflicts: List[Dict[str, str]]) -> str:
    """生成简洁的页面冲突提示。"""
    if not conflicts:
        return ""
    items = []
    for c in conflicts[:5]:
        owner = c.get("site") or "本地/保留网段"
        items.append(f"{c.get('new')} 与 {owner} 的 {c.get('existing')} 冲突")
    suffix = ""
    if len(conflicts) > 5:
        suffix = f"；另有 {len(conflicts) - 5} 条冲突"
    return "网段冲突：" + "；".join(items) + suffix + "。请修改后再保存。"


def format_cidrs(cidr_list: List[str]) -> str:
    return ", ".join(cidr_list)


def normalize_ipv4_cidr(value: str, label: str) -> str:
    try:
        net = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        raise HTTPException(status_code=500, detail=f"{label} 配置错误：{value}")
    if net.version != 4:
        raise HTTPException(status_code=500, detail=f"{label} 只支持 IPv4 网段：{value}")
    return str(net)


def fixed_client_allowed_ips() -> List[str]:
    # 通用平台原则：业务逻辑不写死环境网段。
    # 每次计算都重新读取 /etc/wg-webui/config.json，避免用户修改配置后必须重启才生效。
    cfg = _load_config()
    reserved = _csv_or_list(os.getenv("RESERVED_CLIENT_ALLOWED_IPS") or cfg.get("reserved_client_allowed_ips", []))
    extra = _csv_or_list(os.getenv("CLIENT_ALLOWED_IPS") or cfg.get("client_allowed_ips", []))
    if os.getenv("COMPANY_LAN_CIDR"):
        reserved.append(os.getenv("COMPANY_LAN_CIDR", ""))
    return [*reserved, *extra]


def current_config_value(name: str, default: str = "") -> str:
    # 创建用户/站点时实时读取配置，避免管理员修改 config.json 后还使用启动时旧值。
    env_map = {"server_endpoint": "SERVER_ENDPOINT", "client_dns": "CLIENT_DNS"}
    env_name = env_map.get(name, "")
    if env_name and os.getenv(env_name) not in (None, ""):
        return str(os.getenv(env_name))
    try:
        cfg = _load_json_dict(CONFIG_FILE) if '_load_json_dict' in globals() else _load_config()
        val = cfg.get(name, default)
        return str(val or default)
    except Exception:
        return str(default or "")


def current_server_endpoint() -> str:
    ep = current_config_value("server_endpoint", SERVER_ENDPOINT).strip()
    if not ep or ep.startswith("YOUR_PUBLIC_IP_OR_DOMAIN"):
        raise HTTPException(status_code=400, detail="server_endpoint 未配置。请在 /etc/wg-webui/config.json 或首次安装向导中填写公网IP/域名:端口。")
    return ep


def current_client_dns() -> str:
    return current_config_value("client_dns", CLIENT_DNS).strip()


def interface_dns_line() -> str:
    dns = current_client_dns()
    return f"DNS = {dns}\n" if dns else ""


def _sign_session(username: str, expires: int) -> str:
    payload = f"{username}|{expires}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def _verify_session(token: str) -> Optional[str]:
    try:
        username, expires_s, sig = token.split("|", 2)
        expires = int(expires_s)
    except Exception:
        return None
    if expires < int(datetime.now().timestamp()):
        return None
    payload = f"{username}|{expires}"
    expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    if username != _current_webui_user():
        return None
    return username


def _login_attempt_key(request: Request, username: str) -> str:
    client = request.client.host if request.client else "unknown"
    return f"{client}:{username or '-'}"


def is_authenticated(request: Request, credentials: Optional[HTTPBasicCredentials] = None) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        user = _verify_session(token)
        if user:
            return user
    if credentials and _verify_webui_credentials(credentials.username, credentials.password):
        return credentials.username
    return None


def require_auth(request: Request, credentials: Optional[HTTPBasicCredentials] = Depends(security)):
    user = is_authenticated(request, credentials)
    if not user:
        raise HTTPException(status_code=401, detail="未登录或登录已过期")
    return user


def login_page(error: str = "") -> str:
    safe_error = error.replace("<", "&lt;").replace(">", "&gt;")
    err = f'<div class="err">{safe_error}</div>' if safe_error else ''
    warn = '<div class="warn">&#24403;&#21069;&#26159;&#40664;&#35748;&#23494;&#30721;&#65292;&#35831;&#23613;&#24555;&#20462;&#25913;&#12290;</div>' if _default_password_active() else ''
    err = warn + err
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>&#30331;&#24405; - WireGuard WebUI</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f7fb;font-family:Arial,"Microsoft YaHei",sans-serif;color:#0f172a}}
.box{{width:min(420px,92vw);background:#fff;border:1px solid #e5e7eb;border-radius:18px;box-shadow:0 18px 50px rgba(15,23,42,.12);padding:28px}}
h1{{margin:0 0 8px;font-size:24px}}p{{margin:0 0 22px;color:#64748b}}label{{display:block;font-weight:800;margin:12px 0 6px}}
input{{width:100%;height:44px;border:1px solid #dbe1ea;border-radius:10px;padding:0 12px;font-size:15px;box-sizing:border-box}}
button{{width:100%;height:44px;margin-top:18px;border:0;border-radius:10px;background:#2563eb;color:#fff;font-weight:900;font-size:15px;cursor:pointer}}
.err{{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:10px;padding:10px 12px;margin-bottom:14px}}
.warn{{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:10px;padding:10px 12px;margin-bottom:14px;font-size:13px;line-height:1.55;font-weight:800}}
</style></head><body><form class="box" method="post" action="/api/login"><h1>WireGuard WebUI</h1><p>&#35831;&#36755;&#20837;&#31649;&#29702;&#21592;&#36134;&#21495;&#23494;&#30721;</p>{err}<label>&#29992;&#25143;&#21517;</label><input name="username" autocomplete="username" autofocus><label>&#23494;&#30721;</label><input name="password" type="password" autocomplete="current-password"><button type="submit">&#30331;&#24405;</button></form></body></html>'''


def run(cmd: List[str], input_text: Optional[str] = None) -> str:
    p = subprocess.run(cmd, input=input_text, text=True, capture_output=True)
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=p.stderr.strip() or f"command failed: {' '.join(cmd)}")
    return p.stdout.strip()


def run_service_cmd(cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)


def cmd_text(p: subprocess.CompletedProcess) -> str:
    return (p.stdout or p.stderr or "").strip()


def service_status() -> Dict[str, object]:
    """
    WireGuard 的真实运行状态不能只看 systemd。

    在 wg-quick@wg0 里，systemd 可能显示 failed / inactive / active(exited)，
    但只要 `wg show wg0` 正常，说明 wg0 内核接口真实存在并且 WireGuard 正在运行。
    所以页面状态以 wg show 为主，systemd 仅作为辅助诊断信息。
    """
    service = f"wg-quick@{WG_IF}"

    active = run_service_cmd(["systemctl", "is-active", service], timeout=8)
    enabled = run_service_cmd(["systemctl", "is-enabled", service], timeout=8)
    unit_state = run_service_cmd(
        ["systemctl", "show", service, "--property=ActiveState", "--property=SubState", "--property=Result", "--no-page"],
        timeout=8,
    )
    ip_link = run_service_cmd(["ip", "link", "show", WG_IF], timeout=8)
    wg_show = run_service_cmd(["wg", "show", WG_IF], timeout=8)

    active_text = cmd_text(active) or "unknown"
    enabled_text = cmd_text(enabled) or "unknown"
    unit_text = cmd_text(unit_state) or "unknown"
    interface_exists = ip_link.returncode == 0
    wg_show_ok = wg_show.returncode == 0
    config_exists = WG_CONF.exists()

    # 真实状态优先级：wg show > ip link > systemd
    # 页面只展示用户真正需要的状态，不暴露 systemd 的 failed/active 等诊断细节。
    # 只要 wg show 正常，就说明 WireGuard 真实运行中。
    if wg_show_ok:
        running = True
        status = "running"
        status_text = "运行中"
        status_level = "ok"
    elif interface_exists:
        running = False
        status = "interface_abnormal"
        status_text = "接口存在但 WireGuard 异常"
        status_level = "warn"
    elif not config_exists:
        running = False
        status = "config_missing"
        status_text = f"配置不存在：{WG_CONF}"
        status_level = "error"
    else:
        running = False
        if active_text == "failed":
            status = "failed"
            status_text = "已停止"
            status_level = "off"
        else:
            status = "stopped"
            status_text = "已停止"
            status_level = "off"

    return {
        "service": service,
        "interface": WG_IF,
        "active": active_text,
        "enabled": enabled_text,
        "systemd": unit_text,
        "interface_exists": interface_exists,
        "wg_show_ok": wg_show_ok,
        "config_exists": config_exists,
        "running": running,
        "status": status,
        "status_text": status_text,
        "status_level": status_level,
    }


def _combined_output(*procs: subprocess.CompletedProcess) -> str:
    chunks = []
    for p in procs:
        t = (p.stderr or p.stdout or "").strip()
        if t:
            chunks.append(t)
    return "\n".join(chunks).strip()



def read_os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    p = Path("/etc/os-release")
    if p.exists():
        for line in p.read_text(errors="ignore").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
    return data


def tool_check(name: str, version_cmd: Optional[List[str]] = None) -> Dict[str, object]:
    path = shutil.which(name)
    item: Dict[str, object] = {"name": name, "ok": bool(path), "path": path or "未找到"}
    if path and version_cmd:
        try:
            p = subprocess.run(version_cmd, text=True, capture_output=True, timeout=5)
            out = (p.stdout or p.stderr or "").strip().splitlines()
            item["version"] = out[0] if out else ""
        except Exception as e:
            item["version"] = str(e)
    return item


def list_wireguard_instances() -> List[Dict[str, object]]:
    instances: List[Dict[str, object]] = []
    conf_dir = Path("/etc/wireguard")
    if not conf_dir.exists():
        return instances
    for conf in sorted(conf_dir.glob("*.conf")):
        name = conf.stem
        if not EXISTING_NAME_RE.match(name):
            continue
        wg_ok = run_service_cmd(["wg", "show", name], timeout=5).returncode == 0
        ip_ok = run_service_cmd(["ip", "link", "show", name], timeout=5).returncode == 0
        svc = f"wg-quick@{name}"
        active = run_service_cmd(["systemctl", "is-active", svc], timeout=5)
        instances.append({
            "name": name,
            "config": str(conf),
            "current": name == WG_IF,
            "running": wg_ok,
            "interface_exists": ip_ok,
            "service": svc,
            "systemd": cmd_text(active) or "unknown",
        })
    return instances



def read_server_runtime() -> Dict[str, object]:
    """读取服务器运行数据：负载、内存、磁盘、运行时间。尽量只依赖标准库，避免额外安装依赖。"""
    load1 = load5 = load15 = None
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        pass

    mem_total = mem_available = 0
    try:
        for line in Path("/proc/meminfo").read_text(errors="ignore").splitlines():
            if line.startswith("MemTotal:"):
                mem_total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                mem_available = int(line.split()[1]) * 1024
    except Exception:
        pass
    mem_used = max(mem_total - mem_available, 0) if mem_total else 0
    mem_percent = round(mem_used * 100 / mem_total, 1) if mem_total else None

    disk_total = disk_used = disk_free = 0
    disk_percent = None
    try:
        du = shutil.disk_usage(str(INSTALL_DIR if INSTALL_DIR.exists() else Path("/")))
        disk_total, disk_used, disk_free = du.total, du.used, du.free
        disk_percent = round(disk_used * 100 / disk_total, 1) if disk_total else None
    except Exception:
        pass

    uptime_seconds = None
    try:
        uptime_seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        pass

    return {
        "loadavg": {"1m": load1, "5m": load5, "15m": load15},
        "memory": {"total": mem_total, "used": mem_used, "available": mem_available, "percent": mem_percent},
        "disk": {"path": str(INSTALL_DIR if INSTALL_DIR.exists() else Path("/")), "total": disk_total, "used": disk_used, "free": disk_free, "percent": disk_percent},
        "uptime_seconds": uptime_seconds,
    }

def system_info() -> Dict[str, object]:
    osr = read_os_release()
    tools = [
        tool_check("wg", ["wg", "--version"]),
        tool_check("wg-quick", ["wg-quick", "--version"]),
        tool_check("systemctl", ["systemctl", "--version"]),
        tool_check("systemd-run", ["systemd-run", "--version"]),
        tool_check("ip", ["ip", "-V"]),
        tool_check("iptables", ["iptables", "--version"]),
        tool_check("nft", ["nft", "--version"]),
        tool_check("tar", ["tar", "--version"]),
    ]
    return {
        "app_version": APP_VERSION,
        "config_file": str(CONFIG_FILE),
        "os": {
            "pretty_name": osr.get("PRETTY_NAME") or platform.platform(),
            "id": osr.get("ID", ""),
            "version_id": osr.get("VERSION_ID", ""),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "current_instance": WG_IF,
        "current_config": str(WG_CONF),
        "instances": list_wireguard_instances(),
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timezone": os.getenv("TZ", "本机时区"),
        "runtime": read_server_runtime(),
        "tools": tools,
        "paths": {
            "install_dir": str(INSTALL_DIR),
            "upgrade_root": str(UPGRADE_ROOT),
            "backup_root": str(BACKUP_ROOT_WEBUI),
            "client_dir": str(CLIENT_DIR),
            "site_dir": str(SITE_DIR),
        },
    }


def ensure_upgrade_env():
    UPGRADE_PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    UPGRADE_LOG_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_ROOT_WEBUI.mkdir(parents=True, exist_ok=True)
    script_src = INSTALL_DIR / "upgrade.sh"
    script_dst = UPGRADE_ROOT / "upgrade.sh"
    if script_src.exists():
        shutil.copy2(script_src, script_dst)
        script_dst.chmod(0o755)
    scripts_dir = UPGRADE_ROOT / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    core_src = INSTALL_DIR / "scripts" / "upgrade.sh"
    core_dst = scripts_dir / "upgrade.sh"
    if core_src.exists():
        shutil.copy2(core_src, core_dst)
        core_dst.chmod(0o755)

    # v1.6.1：网页自升级必须交给独立 systemd 服务执行。
    # 这样 wg-webui.service 被停止后，wg-webui-upgrade.service 仍会继续运行。
    unit_path = Path("/etc/systemd/system/wg-webui-upgrade.service")
    unit_text = """[Unit]
Description=WireGuard WebUI Upgrade Runner
After=network.target

[Service]
Type=simple
EnvironmentFile=-/opt/wg-webui-upgrade/run.env
WorkingDirectory=/
ExecStart=/bin/bash -lc 'exec "${UPGRADE_SCRIPT:-/opt/wg-webui-upgrade/upgrade.sh}" "${PACKAGE}"'
KillMode=process
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
"""
    try:
        if not unit_path.exists() or unit_path.read_text(errors="ignore") != unit_text:
            unit_path.write_text(unit_text)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, timeout=15)
    except Exception:
        # 不能因为服务单元写入失败导致整个页面不可用；预检会明确提示。
        pass


def tail_file(path: Path, max_bytes: int = 20000) -> str:
    if not path.exists():
        return ""
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        return f.read().decode("utf-8", errors="ignore")


def upgrade_info() -> Dict[str, object]:
    backups = []
    if BACKUP_ROOT_WEBUI.exists():
        for d in sorted([x for x in BACKUP_ROOT_WEBUI.iterdir() if x.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                size = int(subprocess.check_output(["du", "-sb", str(d)], text=True).split()[0])
            except Exception:
                size = 0
            backups.append({"name": d.name, "path": str(d), "size": size, "size_human": human_bytes(size)})
    packages = []
    opt = Path("/opt")
    if opt.exists():
        for f in sorted(opt.glob("wg-webui-v*.tar.gz"), key=lambda x: x.stat().st_mtime, reverse=True):
            packages.append({"name": f.name, "path": str(f), "size": f.stat().st_size, "size_human": human_bytes(f.stat().st_size)})
    latest_log = UPGRADE_ROOT / "latest.log"
    lock = UPGRADE_ROOT / "upgrade.lock"
    running = False
    unit_active = subprocess.run(["systemctl", "is-active", "wg-webui-upgrade"], capture_output=True, text=True, timeout=8)
    if unit_active.returncode == 0 and (unit_active.stdout or "").strip() == "active":
        running = True
    elif lock.exists():
        try:
            pid = int(lock.read_text().strip())
            running = subprocess.run(["kill", "-0", str(pid)], capture_output=True).returncode == 0
        except Exception:
            running = False
    return {
        "version": APP_VERSION,
        "install_dir": str(INSTALL_DIR),
        "backup_root": str(BACKUP_ROOT_WEBUI),
        "backup_keep": WEBUI_BACKUP_KEEP,
        "backup_count": len(backups),
        "backup_summary": f"自动保留最近 {WEBUI_BACKUP_KEEP} 个备份，当前 {len(backups)} 个",
        "backups": backups,
        "packages": packages,
        "upgrade_running": running,
        "latest_log": tail_file(latest_log),
    }


def extract_app_package_if_full(package: Path) -> Path:
    # 允许网页上传完整部署包；后台自动取出里面的 app 包再走原应用升级流程。
    name = package.name
    if not (name.startswith("wg-webui-full-v") or name.startswith("wg-webui-bundle-v")):
        return package
    import tarfile
    ensure_upgrade_env()
    with tarfile.open(package, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.isfile() and re.search(r"(^|/)wg-webui-app-v[^/]+\.tar\.gz$", m.name)]
        if not members:
            raise HTTPException(status_code=400, detail="完整部署包内未找到 wg-webui-app-v*.tar.gz")
        member = sorted(members, key=lambda x: x.name)[-1]
        out = UPGRADE_PACKAGE_DIR / Path(member.name).name
        src = tf.extractfile(member)
        if src is None:
            raise HTTPException(status_code=400, detail="无法读取完整部署包内的应用包")
        out.write_bytes(src.read())
        return out


def inspect_upgrade_package(package: Path) -> Dict[str, object]:
    """升级包预检：只检查，不停服务、不替换目录、不影响 WireGuard。"""
    checks = []
    def add(name: str, ok: bool, message: str):
        checks.append({"name": name, "ok": bool(ok), "message": message})

    package = package.resolve()
    add("升级包存在", package.exists() and package.is_file(), str(package))
    is_app_pkg = (package.name.startswith("wg-webui-app-v") or package.name.startswith("wg-webui-v")) and package.name.endswith(".tar.gz")
    add("升级包命名", is_app_pkg, package.name)
    add("安装目录", INSTALL_DIR.exists() and INSTALL_DIR.is_dir(), str(INSTALL_DIR))
    add("虚拟环境", (INSTALL_DIR / "venv" / "bin" / "python").exists(), str(INSTALL_DIR / "venv"))
    add("systemd 服务", Path(f"/etc/systemd/system/wg-webui.service").exists(), "/etc/systemd/system/wg-webui.service")
    upgrade_unit = Path("/etc/systemd/system/wg-webui-upgrade.service")
    add("独立升级服务", upgrade_unit.exists(), str(upgrade_unit) if upgrade_unit.exists() else "未创建 wg-webui-upgrade.service")
    sd = shutil.which("systemctl") is not None
    add("独立后台升级", sd, "systemctl 可用，使用 wg-webui-upgrade.service" if sd else "未找到 systemctl，禁止网页升级")
    add("systemctl", shutil.which("systemctl") is not None, "systemctl 可用")
    try:
        BACKUP_ROOT_WEBUI.mkdir(parents=True, exist_ok=True)
        probe = BACKUP_ROOT_WEBUI / ".write-test"
        probe.write_text("ok")
        probe.unlink(missing_ok=True)
        add("备份目录可写", True, str(BACKUP_ROOT_WEBUI))
    except Exception as e:
        add("备份目录可写", False, f"{BACKUP_ROOT_WEBUI}: {e}")

    tmp = Path(f"/tmp/wg-webui-precheck-{os.getpid()}-{int(datetime.now().timestamp())}")
    root_dir = ""
    try:
        p = subprocess.run(["tar", "-tzf", str(package)], capture_output=True, text=True, timeout=30)
        add("tar.gz 格式", p.returncode == 0, "有效压缩包" if p.returncode == 0 else (p.stderr or p.stdout or "tar 校验失败"))
        if p.returncode == 0:
            top_items = [x.split("/", 1)[0] for x in p.stdout.splitlines() if x.strip()]
            root_dir = top_items[0] if top_items else ""
            add("升级包目录", bool(root_dir), root_dir or "未识别顶层目录")
            tmp.mkdir(parents=True, exist_ok=True)
            p2 = subprocess.run(["tar", "-xzf", str(package), "-C", str(tmp)], capture_output=True, text=True, timeout=30)
            add("解压测试", p2.returncode == 0, "解压成功" if p2.returncode == 0 else (p2.stderr or p2.stdout or "解压失败"))
            new_dir = None
            app_file = None
            req_file = None
            for d in tmp.iterdir():
                if d.is_dir() and (d / "app" / "app.py").exists():
                    new_dir = d
                    app_file = d / "app" / "app.py"
                    req_file = d / "app" / "requirements.txt"
                    break
                if d.is_dir() and (d / "bundle" / "app" / "app.py").exists():
                    new_dir = d / "bundle"
                    app_file = new_dir / "app" / "app.py"
                    req_file = new_dir / "app" / "requirements.txt"
                    break
                if d.is_dir() and (d / "app.py").exists():
                    new_dir = d
                    app_file = d / "app.py"
                    req_file = d / "requirements.txt"
                    break
            if new_dir is None and (tmp / "app" / "app.py").exists():
                new_dir = tmp
                app_file = tmp / "app" / "app.py"
                req_file = tmp / "app" / "requirements.txt"
            if new_dir is None and (tmp / "bundle" / "app" / "app.py").exists():
                new_dir = tmp / "bundle"
                app_file = new_dir / "app" / "app.py"
                req_file = new_dir / "app" / "requirements.txt"
            if new_dir is None and (tmp / "app.py").exists():
                new_dir = tmp
                app_file = tmp / "app.py"
                req_file = tmp / "requirements.txt"
            add("入口文件 app.py", app_file is not None, str(app_file) if app_file else "未找到 app.py")
            if new_dir is not None:
                add("依赖文件 requirements.txt", req_file.exists() if req_file else False, str(req_file) if req_file else "未找到 requirements.txt")
                add("升级脚本 upgrade.sh", (new_dir / "upgrade.sh").exists(), str(new_dir / "upgrade.sh"))
                try:
                    txt = app_file.read_text(errors="ignore")
                    m = re.search(r'APP_VERSION\s*=\s*["\']([^"\']+)', txt)
                    pkg_ver = m.group(1) if m else "未知"
                    add("版本识别", pkg_ver != "未知", pkg_ver)
                    if pkg_ver != "未知":
                        cmp = compare_versions(pkg_ver, APP_VERSION)
                        if cmp > 0:
                            add("版本对比", True, f"当前 {APP_VERSION} → 新版 {pkg_ver}")
                        elif cmp == 0:
                            add("版本对比", False, f"当前已是 {APP_VERSION}，升级包也是 {pkg_ver}，不建议重复升级")
                        else:
                            add("版本对比", False, f"当前 {APP_VERSION}，升级包版本 {pkg_ver} 较旧，禁止降级")
                    readme_file = new_dir / "README.md"
                    compat_context = new_dir / "PROJECT_CONTEXT.md"
                    add("README", readme_file.exists() or compat_context.exists(), str(readme_file if readme_file.exists() else compat_context))
                    docs_dir = new_dir / "docs"
                    add("文档目录", docs_dir.exists(), str(docs_dir) if docs_dir.exists() else "未找到 docs 目录")
                except Exception as e:
                    add("版本识别", False, str(e))
    except Exception as e:
        add("预检异常", False, str(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = all(c["ok"] for c in checks)
    return {"ok": ok, "package": str(package), "filename": package.name, "root_dir": root_dir, "checks": checks}

def ensure_env():
    for d in [CLIENT_DIR, QR_DIR, SITE_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
    if not WG_CONF.exists():
        raise HTTPException(status_code=500, detail=f"未找到 {WG_CONF}")


def backup_conf():
    ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    backup = WG_CONF.with_name(WG_CONF.name + f".bak.{ts}")
    shutil.copy2(WG_CONF, backup)
    backups = sorted(WG_CONF.parent.glob(WG_CONF.name + ".bak.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[BACKUP_KEEP:]:
        old.unlink(missing_ok=True)
    return str(backup)


def apply_wg():
    try:
        subprocess.run(["ip", "link", "show", WG_IF], check=True, capture_output=True)
        stripped = run(["wg-quick", "strip", WG_IF])
        run(["wg", "syncconf", WG_IF, "/dev/stdin"], input_text=stripped)
    except Exception:
        run(["systemctl", "restart", f"wg-quick@{WG_IF}"])


def validate_name(name: str):
    if not name or not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="名称只能包含字母、数字、横线、下划线")

def validate_existing_name(name: str):
    if not name or not EXISTING_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="名称只能包含字母、数字、横线、下划线、小数点")


def validate_cidr(cidr: str):
    if not cidr or not CIDR_RE.match(cidr):
        raise HTTPException(status_code=400, detail="CIDR 格式错误，例如 192.168.23.0/24")


def genkey() -> str:
    return run(["wg", "genkey"])


def pubkey(private_key: str) -> str:
    return run(["wg", "pubkey"], input_text=private_key)


def genpsk() -> str:
    return run(["wg", "genpsk"])


def server_pubkey() -> str:
    return run(["wg", "show", WG_IF, "public-key"])


def used_ip_numbers() -> set:
    text = WG_CONF.read_text(errors="ignore")
    return set(int(m.group(1)) for m in re.finditer(rf"{re.escape(WG_NET)}\.(\d{{1,3}})", text))


def ip_pool_status(start: int, end: int, peer_type: str) -> Dict[str, object]:
    used = set()
    try:
        for peer in parse_wg_conf():
            if peer.get("type") != peer_type:
                continue
            vpn_ip, _ = split_peer_allowed_ips(peer)
            host = vpn_ip.split("/", 1)[0]
            m = re.match(rf"^{re.escape(WG_NET)}[.](\d{{1,3}})$", host)
            if m:
                used.add(int(m.group(1)))
    except Exception:
        used = set()
    total = max(0, int(end) - int(start) + 1)
    used_in_range = sorted(i for i in used if int(start) <= i <= int(end))
    free = max(0, total - len(used_in_range))
    return {
        "start": int(start),
        "end": int(end),
        "total": total,
        "used": len(used_in_range),
        "free": free,
        "used_numbers": used_in_range,
    }


def next_ip(start: int, end: int) -> str:
    used = used_ip_numbers()
    for i in range(start, end + 1):
        if i not in used:
            return f"{WG_NET}.{i}"
    raise HTTPException(status_code=400, detail=f"IP 地址池已用完：{WG_NET}.{start}-{end}")




def normalize_allowed_ips(items: List[str]) -> str:
    return core_normalize_allowed_ips(items)


def site_lan_allowed_ips() -> List[str]:
    """
    从 /etc/wireguard/wg0.conf 里的 site 节点自动提取现场内网网段。
    这样新增站点后，再新增用户时，用户客户端 AllowedIPs 会自动包含新的现场网段。
    """
    lans: List[str] = []
    try:
        for p in parse_wg_conf():
            if p.get("type") != "site":
                continue
            for part in str(p.get("allowed_ips", "")).split(","):
                ip = part.strip()
                if not ip:
                    continue
                # 站点 peer 里一般是：10.6.0.x/32, 现场网段。
                # 用户客户端只需要现场网段，不需要把每个站点的 10.6.0.x/32 都塞进去。
                if ip.startswith(f"{WG_NET}."):
                    continue
                if ip == WG_CIDR:
                    continue
                if CIDR_RE.match(ip):
                    lans.append(ip)
    except Exception:
        pass
    return lans


def site_lans_by_name() -> Dict[str, List[str]]:
    sites: Dict[str, List[str]] = {}
    try:
        for p in parse_wg_conf():
            if p.get("type") != "site":
                continue
            lans: List[str] = []
            for part in str(p.get("allowed_ips", "")).split(","):
                ip = part.strip()
                if not ip or ip.startswith(f"{WG_NET}.") or ip == WG_CIDR:
                    continue
                if CIDR_RE.match(ip):
                    lans.append(ip)
            sites[str(p.get("name", ""))] = lans
    except Exception:
        pass
    return sites


def user_site_permissions_config() -> Dict[str, Dict[str, object]]:
    raw = _load_json_dict(CONFIG_FILE).get("user_site_permissions", {})
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, Dict[str, object]] = {}
    for user, item in raw.items():
        if not isinstance(item, dict):
            continue
        mode = str(item.get("mode") or "all").strip().lower()
        if mode not in {"all", "custom"}:
            mode = "all"
        sites = [str(x).strip() for x in item.get("sites", []) if str(x).strip()] if isinstance(item.get("sites", []), list) else []
        out[str(user)] = {"mode": mode, "sites": sorted(set(sites))}
    return out


def user_permission_for(name: str) -> Dict[str, object]:
    perms = user_site_permissions_config()
    item = perms.get(name)
    if not item:
        # 兼容旧版本：未配置权限的老用户仍保持“全部站点”，避免升级后突然失联。
        return {"mode": "all", "sites": []}
    return item


def set_user_site_permission(name: str, mode: str, sites: List[str]) -> Dict[str, object]:
    validate_existing_name(name)
    mode = str(mode or "all").strip().lower()
    if mode not in {"all", "custom"}:
        raise HTTPException(status_code=400, detail="授权模式必须是 all 或 custom")
    existing_sites = set(site_lans_by_name().keys())
    clean_sites = sorted(set(str(x).strip() for x in sites if str(x).strip()))
    unknown = [x for x in clean_sites if x not in existing_sites]
    if unknown:
        raise HTTPException(status_code=400, detail="站点不存在：" + ", ".join(unknown))
    cfg = _load_json_dict(CONFIG_FILE)
    perms = cfg.get("user_site_permissions", {})
    if not isinstance(perms, dict):
        perms = {}
    perms[name] = {"mode": mode, "sites": clean_sites if mode == "custom" else []}
    cfg["user_site_permissions"] = perms
    _write_config_json(cfg)
    return {"name": name, "mode": mode, "sites": clean_sites if mode == "custom" else []}




def user_names() -> List[str]:
    try:
        return sorted([str(p.get("name", "")) for p in parse_wg_conf() if p.get("type") == "user" and str(p.get("name", "")).strip()])
    except Exception:
        return []


def bulk_update_user_site_permissions(users: List[str], action: str, sites: List[str]) -> Dict[str, object]:
    names = [str(x).strip() for x in users if str(x).strip()]
    names = sorted(set(names))
    existing_users = set(user_names())
    unknown_users = [x for x in names if x not in existing_users]
    if unknown_users:
        raise HTTPException(status_code=400, detail="用户不存在：" + ", ".join(unknown_users))

    site_map = site_lans_by_name()
    existing_sites = set(site_map.keys())
    clean_sites = sorted(set(str(x).strip() for x in sites if str(x).strip()))
    unknown_sites = [x for x in clean_sites if x not in existing_sites]
    if unknown_sites:
        raise HTTPException(status_code=400, detail="站点不存在：" + ", ".join(unknown_sites))

    action = str(action or "add").strip().lower()
    if action not in {"add", "remove", "set_all", "set_custom"}:
        raise HTTPException(status_code=400, detail="批量操作类型必须是 add / remove / set_all / set_custom")
    if action in {"add", "remove"} and not clean_sites:
        raise HTTPException(status_code=400, detail="请选择至少一个站点")

    all_sites = sorted(existing_sites)
    changed: List[str] = []
    results: List[Dict[str, object]] = []
    for name in names:
        old = user_permission_for(name)
        old_mode = str(old.get("mode", "all"))
        old_sites = sorted(set(str(x) for x in old.get("sites", []) if str(x)))

        if action == "set_all":
            new_mode, new_sites = "all", []
        else:
            current_sites = set(all_sites if old_mode == "all" else old_sites)
            if action == "add":
                current_sites.update(clean_sites)
            elif action == "remove":
                current_sites.difference_update(clean_sites)
            elif action == "set_custom":
                current_sites = set(clean_sites)
            new_sites = sorted(current_sites)
            new_mode = "all" if set(new_sites) == set(all_sites) else "custom"
            if new_mode == "all":
                new_sites = []

        set_user_site_permission(name, new_mode, new_sites)
        if old_mode != new_mode or old_sites != new_sites:
            changed.append(name)
        results.append({"name": name, "mode": new_mode, "sites": new_sites})

    if names:
        mark_apply_pending("用户访问权限已批量变更，需要应用配置刷新服务端访问控制")
    return {"ok": True, "total": len(names), "changed": len(changed), "changed_users": changed, "results": results}


def set_site_authorized_users(site: str, users: List[str]) -> Dict[str, object]:
    site_map = site_lans_by_name()
    if site not in site_map:
        raise HTTPException(status_code=404, detail="站点不存在")
    all_users = user_names()
    selected = sorted(set(str(x).strip() for x in users if str(x).strip()))
    unknown_users = [x for x in selected if x not in set(all_users)]
    if unknown_users:
        raise HTTPException(status_code=400, detail="用户不存在：" + ", ".join(unknown_users))
    changed: List[str] = []
    all_sites = sorted(site_map.keys())
    selected_set = set(selected)
    for user in all_users:
        old = user_permission_for(user)
        old_mode = str(old.get("mode", "all"))
        current = set(all_sites if old_mode == "all" else [str(x) for x in old.get("sites", []) if str(x)])
        before = sorted(current)
        if user in selected_set:
            current.add(site)
        else:
            current.discard(site)
        new_sites = sorted(current)
        new_mode = "all" if set(new_sites) == set(all_sites) else "custom"
        if new_mode == "all":
            new_sites = []
        set_user_site_permission(user, new_mode, new_sites)
        if old_mode != new_mode or before != sorted(current):
            changed.append(user)
    mark_apply_pending("站点授权用户已变更，需要应用配置刷新服务端访问控制")
    return {"ok": True, "site": site, "selected_users": selected, "changed": len(changed), "changed_users": changed}

def remove_user_site_permission(name: str) -> None:
    cfg = _load_json_dict(CONFIG_FILE)
    perms = cfg.get("user_site_permissions", {})
    if not isinstance(perms, dict) or name not in perms:
        return
    perms.pop(name, None)
    cfg["user_site_permissions"] = perms
    _write_config_json(cfg)


def allowed_site_lans_for_user(name: str) -> List[str]:
    sites = site_lans_by_name()
    perm = user_permission_for(name)
    if perm.get("mode") == "custom":
        names = [str(x) for x in perm.get("sites", [])]
    else:
        names = sorted(sites.keys())
    out: List[str] = []
    for site in names:
        out.extend(sites.get(site, []))
    return out


def client_allowed_ips_for_user(name: str = "") -> str:
    # 用户客户端 AllowedIPs = 固定/保留网段 + 该用户被授权的站点网段。
    # 未配置权限的旧用户默认全部站点，避免升级后访问突然收窄。
    allowed = normalize_allowed_ips([*fixed_client_allowed_ips(), *allowed_site_lans_for_user(name)])
    return allowed or WG_CIDR


def client_allowed_ips() -> str:
    # 兼容旧调用：返回全部站点网段。新增权限逻辑请优先使用 client_allowed_ips_for_user(name)。
    allowed = normalize_allowed_ips([*fixed_client_allowed_ips(), *site_lan_allowed_ips()])
    return allowed or WG_CIDR

def parse_wg_conf() -> List[Dict]:
    ensure_env()
    peers = []
    current_name = "UNKNOWN"
    current_type = "unknown"
    peer = None

    for raw in WG_CONF.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("# "):
            label = line[2:].strip()
            if label.startswith("user-"):
                current_type = "user"
                current_name = label[5:]
            elif label.startswith("site-"):
                current_type = "site"
                current_name = label[5:]
            else:
                current_type = "unknown"
                current_name = label
        elif line == "[Peer]":
            peer = {"name": current_name, "type": current_type, "public_key": "", "allowed_ips": ""}
            peers.append(peer)
        elif peer and line.startswith("PublicKey"):
            peer["public_key"] = line.split("=", 1)[1].strip()
        elif peer and line.startswith("AllowedIPs"):
            peer["allowed_ips"] = line.split("=", 1)[1].strip()
    return peers


def parse_wg_dump() -> Dict[str, Dict]:
    status = {}
    try:
        out = run(["wg", "show", WG_IF, "dump"])
    except Exception:
        return status
    lines = out.splitlines()
    now_ts = int(datetime.now().timestamp())
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) >= 8:
            pub = parts[0]
            endpoint = parts[2] if len(parts) > 2 and parts[2] != "(none)" else ""
            handshake = int(parts[4]) if parts[4].isdigit() else 0
            rx = int(parts[5]) if parts[5].isdigit() else 0
            tx = int(parts[6]) if parts[6].isdigit() else 0
            age = (now_ts - handshake) if handshake > 0 else None
            online = bool(handshake > 0 and age is not None and age <= ONLINE_THRESHOLD_SECONDS)
            handshake_time = datetime.fromtimestamp(handshake).strftime("%Y-%m-%d %H:%M:%S") if handshake > 0 else ""
            status[pub] = {
                "endpoint": endpoint,
                "latest_handshake": handshake,
                "latest_handshake_time": handshake_time,
                "latest_handshake_age": age,
                "rx": rx,
                "tx": tx,
                "online": online,
            }
    return status


def human_bytes(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024


def handshake_age_text(age: Optional[int]) -> str:
    if age is None:
        return "从未握手"
    age = max(0, int(age))
    if age < 60:
        return f"{age} 秒前"
    minutes = age // 60
    if minutes < 60:
        return f"{minutes} 分钟前"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} 小时前"
    return f"{hours // 24} 天前"


def wireguard_connection_snapshot() -> str:
    peers = parse_wg_conf()
    status = parse_wg_dump()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    online = 0
    rows = []
    for peer in peers:
        s = status.get(peer.get("public_key", ""), {})
        is_online = bool(s.get("online"))
        if is_online:
            online += 1
        allowed = peer.get("allowed_ips", "")
        vpn_ip = allowed.split(",", 1)[0].strip() if allowed else "-"
        rows.append({
            "type": peer.get("type", "unknown"),
            "name": peer.get("name", "UNKNOWN"),
            "online": is_online,
            "vpn_ip": vpn_ip,
            "allowed": allowed or "-",
            "endpoint": s.get("endpoint") or "未连接",
            "handshake": handshake_age_text(s.get("latest_handshake_age")),
            "handshake_time": s.get("latest_handshake_time") or "-",
            "rx": human_bytes(int(s.get("rx") or 0)),
            "tx": human_bytes(int(s.get("tx") or 0)),
        })
    rows.sort(key=lambda x: (not x["online"], x["type"] != "user", x["name"]))
    out = [
        f"WireGuard 连接快照（{WG_IF}）",
        f"生成时间：{now}",
        f"在线判定：最近 {ONLINE_THRESHOLD_SECONDS} 秒内有握手",
        f"节点统计：在线 {online} / 总计 {len(rows)}",
        "",
    ]
    if not rows:
        out.append("暂无节点配置")
        return "\n".join(out)
    for item in rows:
        state = "在线" if item["online"] else "离线"
        node_type = "用户" if item["type"] == "user" else "站点" if item["type"] == "site" else item["type"]
        out.extend([
            f"[{state}] {node_type}：{item['name']}",
            f"  VPN 地址：{item['vpn_ip']}",
            f"  最近握手：{item['handshake']}（{item['handshake_time']}）",
            f"  连接端点：{item['endpoint']}",
            f"  流量统计：接收 {item['rx']} / 发送 {item['tx']}",
            f"  AllowedIPs：{item['allowed']}",
            "",
        ])
    return "\n".join(out).rstrip()


def ping_host(host: str, timeout: int = 1, count: int = 1) -> Dict[str, object]:
    """轻量 ping 检测。失败时只返回原因，不抛异常，避免页面卡死。"""
    host = str(host or "").strip()
    if not host:
        return {"ok": False, "host": host, "message": "未提供检测地址"}
    try:
        p = subprocess.run(["ping", "-c", str(count), "-W", str(timeout), host], text=True, capture_output=True, timeout=max(3, timeout * count + 2))
        out = (p.stdout or p.stderr or "").strip()
        m = re.search(r"time=([0-9.]+)\s*ms", out)
        return {"ok": p.returncode == 0, "host": host, "latency_ms": float(m.group(1)) if m else None, "message": "可达" if p.returncode == 0 else (out.splitlines()[-1] if out else "不可达")}
    except Exception as e:
        return {"ok": False, "host": host, "latency_ms": None, "message": str(e)}


def first_host_from_cidr(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        if net.version != 4:
            return ""
        # 现场常见网关是 .1；如果 .1 不在网段内，再取第一个可用地址。
        candidate = ipaddress.ip_address(str(net.network_address + 1))
        if candidate in net:
            return str(candidate)
        hosts = list(net.hosts())
        return str(hosts[0]) if hosts else str(net.network_address)
    except Exception:
        return ""


def site_health_for_peer(peer: Dict, status: Dict[str, Dict]) -> Dict[str, object]:
    """站点健康检测：握手 + 站点 VPN IP ping + 站点内网网关 ping。"""
    s = status.get(peer.get("public_key", ""), {})
    allowed = [x.strip() for x in str(peer.get("allowed_ips", "")).split(",") if x.strip()]
    vpn_ip = allowed[0].split("/", 1)[0] if allowed else ""
    lan_cidrs = [x for x in allowed[1:] if x and not x.startswith(f"{WG_NET}.")]
    lan_probe = first_host_from_cidr(lan_cidrs[0]) if lan_cidrs else ""
    vpn_ping = ping_host(vpn_ip) if vpn_ip else {"ok": False, "host": "", "message": "无 VPN IP"}
    lan_ping = ping_host(lan_probe) if lan_probe else {"ok": False, "host": "", "message": "无内网探测地址"}
    handshake_ok = bool(s.get("latest_handshake") and s.get("online"))
    if handshake_ok and vpn_ping.get("ok") and (not lan_probe or lan_ping.get("ok")):
        level, text = "ok", "正常"
    elif handshake_ok and vpn_ping.get("ok") and lan_probe and not lan_ping.get("ok"):
        level, text = "warn", "VPN通，内网不通"
    elif handshake_ok and not vpn_ping.get("ok"):
        level, text = "warn", "已握手，VPN IP 不通"
    else:
        level, text = "bad", "未握手或离线"
    return {"name": peer.get("name"), "level": level, "text": text, "handshake_ok": handshake_ok, "vpn_ip": vpn_ip, "vpn_ping": vpn_ping, "lan_probe": lan_probe, "lan_ping": lan_ping, "latest_handshake_age": s.get("latest_handshake_age"), "latest_handshake_time": s.get("latest_handshake_time", "")}


def config_audit() -> Dict[str, object]:
    ensure_env()
    peers = parse_wg_conf()
    issues: List[Dict[str, str]] = []
    seen_names = set(); seen_pub = set(); seen_ips = {}; site_nets = []
    for p in peers:
        label = f"{p.get('type')}-{p.get('name')}"
        if label in seen_names:
            issues.append({"level": "bad", "item": label, "message": "节点名称重复"})
        seen_names.add(label)
        pub = p.get("public_key") or ""
        if not pub:
            issues.append({"level": "bad", "item": label, "message": "缺少 PublicKey"})
        elif pub in seen_pub:
            issues.append({"level": "bad", "item": label, "message": "PublicKey 重复"})
        seen_pub.add(pub)
        allowed = [x.strip() for x in str(p.get("allowed_ips", "")).split(",") if x.strip()]
        if not allowed:
            issues.append({"level": "bad", "item": label, "message": "缺少 AllowedIPs"})
            continue
        for a in allowed:
            try:
                net = ipaddress.ip_network(a, strict=False)
            except Exception:
                issues.append({"level": "bad", "item": label, "message": f"AllowedIPs 格式错误：{a}"})
                continue
            if str(net).startswith(f"{WG_NET}.") or (net.prefixlen == 32 and str(net.network_address).startswith(f"{WG_NET}.")):
                if str(net) in seen_ips:
                    issues.append({"level": "bad", "item": label, "message": f"VPN IP 重复：{net}，已被 {seen_ips[str(net)]} 使用"})
                seen_ips[str(net)] = label
            if p.get("type") == "site" and not str(net.network_address).startswith(f"{WG_NET}."):
                for old_label, old_net in site_nets:
                    if net.overlaps(old_net):
                        issues.append({"level": "bad", "item": label, "message": f"站点网段重叠：{net} 与 {old_label} 的 {old_net}"})
                site_nets.append((label, net))
    desired = client_allowed_ips()
    outdated_users = []
    for conf in sorted(CLIENT_DIR.glob("*.conf")):
        current = read_client_allowed_ips_file(conf)
        if current is None or normalize_allowed_ips([current]) != desired:
            outdated_users.append(conf.stem)
    if outdated_users:
        issues.append({"level": "warn", "item": "用户配置", "message": f"{len(outdated_users)} 个用户配置 AllowedIPs 未同步最新站点网段"})
    route_checks = []
    for p in peers:
        if p.get("type") != "site":
            continue
        _, lans = split_peer_allowed_ips(p)
        for cidr in lans:
            st = route_status_for_cidr(cidr)
            st["site"] = str(p.get("name", ""))
            route_checks.append(st)
            if not st.get("ok"):
                issues.append({"level": "bad", "item": f"站点路由 {p.get('name')}", "message": f"{cidr} 缺少 dev {WG_IF} 路由"})
    return {
        "ok": not any(i["level"] == "bad" for i in issues),
        "issue_count": len(issues),
        "issues": issues,
        "peer_count": len(peers),
        "outdated_users": outdated_users,
        "desired_user_allowed_ips": desired,
        "route_checks": route_checks,
        "stale_route_checks": stale_route_checks,
        "stale_route_cidrs": stale_cidrs,
    }


def parse_app_version(value: str) -> tuple:
    """把 v1.6.3 / 1.6.3 转为可比较元组。"""
    nums = re.findall(r"\d+", value or "")
    return tuple(int(x) for x in nums[:4]) if nums else tuple()

def compare_versions(a: str, b: str) -> int:
    aa = list(parse_app_version(a))
    bb = list(parse_app_version(b))
    n = max(len(aa), len(bb), 3)
    aa += [0] * (n - len(aa))
    bb += [0] * (n - len(bb))
    return (aa > bb) - (aa < bb)


def remove_peer_block(peer_type: str, name: str):
    target = f"# {peer_type}-{name}"
    lines = WG_CONF.read_text(errors="ignore").splitlines()
    out = []
    deleting = False
    found = False
    for line in lines:
        if line.strip() == target:
            deleting = True
            found = True
            continue
        if deleting and line.strip() == "":
            deleting = False
            continue
        if not deleting:
            out.append(line)
    if not found:
        raise HTTPException(status_code=404, detail=f"未找到 {peer_type}-{name}")
    WG_CONF.write_text("\n".join(out).rstrip() + "\n")


def split_peer_allowed_ips(peer: Dict) -> tuple[str, List[str]]:
    parts = [x.strip() for x in str(peer.get("allowed_ips", "")).split(",") if x.strip()]
    vpn_ip = parts[0] if parts else ""
    lan_cidrs = [x for x in parts[1:] if x and not x.startswith(f"{WG_NET}.") and x != WG_CIDR]
    return vpn_ip, lan_cidrs


def apply_wg_live_only() -> Dict[str, object]:
    try:
        subprocess.run(["ip", "link", "show", WG_IF], check=True, capture_output=True)
        stripped = run(["wg-quick", "strip", WG_IF])
        run(["wg", "syncconf", WG_IF, "/dev/stdin"], input_text=stripped)
        return {"applied": True, "message": "WireGuard running config synced"}
    except Exception as e:
        return {"applied": False, "message": str(e)}


def _run_route_cmd(cmd: List[str]) -> Dict[str, object]:
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
    return {"cmd": " ".join(cmd), "ok": p.returncode == 0, "stdout": (p.stdout or "").strip(), "stderr": (p.stderr or "").strip()}



def route_status_for_cidr(cidr: str) -> Dict[str, object]:
    """Return whether a CIDR route currently exists on the WireGuard interface.

    This helper must be defensive because it is called by status APIs after
    site-network edits/deletes.  Missing iproute2, invalid CIDR values, or a
    stopped wg interface should never turn a normal WebUI operation into a
    500 Internal Server Error; they should only mark the route as not applied.
    """
    cidr = str(cidr or "").strip()
    if not cidr:
        return {"cidr": cidr, "ok": False, "message": "empty cidr", "route": ""}
    try:
        ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        return {"cidr": cidr, "ok": False, "message": f"invalid cidr: {e}", "route": ""}
    try:
        p = subprocess.run(["ip", "route", "show", cidr], text=True, capture_output=True, timeout=10)
        route_text = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        ok = p.returncode == 0 and bool(route_text) and f"dev {WG_IF}" in route_text
        return {"cidr": cidr, "ok": ok, "route": route_text, "stderr": err}
    except FileNotFoundError:
        return {"cidr": cidr, "ok": False, "message": "ip command not found", "route": ""}
    except subprocess.TimeoutExpired:
        return {"cidr": cidr, "ok": False, "message": "ip route show timeout", "route": ""}
    except Exception as e:
        return {"cidr": cidr, "ok": False, "message": str(e), "route": ""}

def sync_site_lan_routes(old_lans: List[str], new_lans: List[str]) -> Dict[str, object]:
    """Keep kernel routes aligned with site LAN AllowedIPs without restarting wg-quick."""
    results: List[Dict[str, object]] = []
    link = subprocess.run(["ip", "link", "show", WG_IF], text=True, capture_output=True, timeout=10)
    if link.returncode != 0:
        return {"ok": False, "skipped": True, "message": f"{WG_IF} interface not found", "results": results}

    old_set = set(old_lans)
    new_set = set(new_lans)
    for cidr in sorted(new_set - old_set):
        results.append({"action": "add", "cidr": cidr, **_run_route_cmd(["ip", "route", "replace", cidr, "dev", WG_IF])})

    remaining_site_lans = set(site_lan_networks_for_reserved_check())
    for cidr in sorted(old_set - new_set):
        if cidr in remaining_site_lans:
            results.append({"action": "keep", "cidr": cidr, "ok": True, "message": "still used by another site"})
            continue
        shown = subprocess.run(["ip", "route", "show", cidr], text=True, capture_output=True, timeout=10)
        route_text = (shown.stdout or "").strip()
        if f"dev {WG_IF}" not in route_text:
            results.append({"action": "skip-delete", "cidr": cidr, "ok": True, "message": "route is absent or not owned by current wg interface"})
            continue
        results.append({"action": "delete", "cidr": cidr, **_run_route_cmd(["ip", "route", "del", cidr, "dev", WG_IF])})

    return {"ok": all(r.get("ok") for r in results), "skipped": False, "results": results}


def sync_all_site_lan_routes() -> Dict[str, object]:
    """Sync current site routes and remove stale routes recorded from deleted sites."""
    desired_lans = set(site_lan_networks_for_reserved_check())
    state = read_apply_state()
    stale_lans = set(str(x) for x in state.get("stale_route_cidrs", []) if x)
    old_lans = sorted(stale_lans - desired_lans)
    new_lans = sorted(desired_lans)
    return sync_site_lan_routes(old_lans, new_lans)



def config_apply_status() -> Dict[str, object]:
    state = read_apply_state()
    desired_hash = wg_conf_hash()
    route_checks = []
    try:
        route_checks = [route_status_for_cidr(cidr) for cidr in site_lan_networks_for_reserved_check()]
    except Exception:
        route_checks = []
    stale_cidrs = [str(x) for x in state.get("stale_route_cidrs", []) if x]
    try:
        stale_route_checks = [route_status_for_cidr(cidr) for cidr in stale_cidrs]
    except Exception:
        stale_route_checks = []
    stale_route_pending = any(bool(r.get("ok")) for r in stale_route_checks)
    route_pending = any(not bool(r.get("ok")) for r in route_checks) or stale_route_pending
    hash_pending = bool(state.get("pending"))
    if state.get("last_applied_conf_hash") and state.get("last_applied_conf_hash") != desired_hash:
        hash_pending = True
    pending = bool(hash_pending or route_pending)
    reasons = []
    if state.get("pending_reason"):
        reasons.append(str(state.get("pending_reason")))
    if any(not bool(r.get("ok")) for r in route_checks):
        missing = [r.get("cidr") for r in route_checks if not bool(r.get("ok"))]
        reasons.append("有站点内网路由未刷新：" + ", ".join([str(x) for x in missing[:8] if x]))
    if stale_route_pending:
        stale_present = [r.get("cidr") for r in stale_route_checks if bool(r.get("ok"))]
        reasons.append("有已删除站点的旧路由待清理：" + ", ".join([str(x) for x in stale_present[:8] if x]))
    return {
        "ok": True,
        "pending": pending,
        "button_enabled": pending,
        "button_class": "green" if pending else "gray",
        "message": "有配置变更需要应用" if pending else "当前没有需要应用的配置",
        "reasons": reasons,
        "conf_hash": desired_hash,
        "last_applied_conf_hash": state.get("last_applied_conf_hash", ""),
        "last_apply_message": state.get("last_apply_message", ""),
        "updated_at": state.get("updated_at", ""),
        "route_checks": route_checks,
    }

ACL_CHAIN = "WG_WEBUI_ACL"


def user_vpn_ips_by_name() -> Dict[str, str]:
    users: Dict[str, str] = {}
    try:
        for p in parse_wg_conf():
            if p.get("type") != "user":
                continue
            vpn_ip, _ = split_peer_allowed_ips(p)
            if vpn_ip:
                users[str(p.get("name", ""))] = vpn_ip.split("/", 1)[0]
    except Exception:
        pass
    return users


def run_iptables(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["iptables", *args], text=True, capture_output=True, timeout=10)


def _acl_disabled_prefix() -> str:
    return "# ACL_DISABLED "


def _is_forward_full_allow_rule_text(line: str) -> bool:
    """识别会绕过 ACL 的 wg 用户侧全放通 FORWARD 规则。"""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    if "iptables" not in stripped or "FORWARD" not in stripped or "-j ACCEPT" not in stripped:
        return False
    if "--ctstate" in stripped or "RELATED,ESTABLISHED" in stripped:
        return False
    if f"-i {WG_IF}" not in stripped or f"-s {WG_CIDR}" not in stripped:
        return False
    # 只处理 PostUp/PostDown 里的主动放行规则，不处理 NAT 和返回流量规则。
    return stripped.startswith("PostUp") or stripped.startswith("PostDown")


def disable_acl_bypass_rules_in_config() -> List[str]:
    """启用 ACL 时，自动注释 wg0->内网全放通规则，保留可恢复标记。"""
    changed: List[str] = []
    if not WG_CONF.exists():
        return [f"未找到 {WG_CONF}，无法检查全放通配置"]
    try:
        lines = WG_CONF.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as exc:
        return [f"读取 {WG_CONF} 失败：{exc}"]
    out: List[str] = []
    prefix = _acl_disabled_prefix()
    for line in lines:
        if _is_forward_full_allow_rule_text(line):
            out.append(prefix + line)
            changed.append(line.strip())
        else:
            out.append(line)
    if changed:
        try:
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = WG_CONF.with_name(WG_CONF.name + f".acl-bypass.bak.{ts}")
            shutil.copy2(WG_CONF, backup)
            WG_CONF.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
            changed.insert(0, f"已注释 {len(changed)} 条 ACL 全放通绕过规则，备份：{backup}")
        except Exception as exc:
            return [f"注释 ACL 全放通绕过规则失败：{exc}"]
    return changed


def remove_live_acl_bypass_rules() -> List[str]:
    """清理当前内核里会绕过 ACL 的全放通 FORWARD 规则。"""
    notes: List[str] = []
    if not shutil.which("iptables"):
        return notes
    p = run_iptables(["-S", "FORWARD"])
    if p.returncode != 0:
        return notes
    for raw in (p.stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("-A FORWARD"):
            continue
        if f"-i {WG_IF}" not in line or f"-s {WG_CIDR}" not in line or "-j ACCEPT" not in line:
            continue
        if "--ctstate" in line or "RELATED,ESTABLISHED" in line:
            continue
        # 把 -A FORWARD ... 转成 -D FORWARD ... 精确删除。
        args = line.split()
        args[0] = "-D"
        res = run_iptables(args)
        if res.returncode == 0:
            notes.append("已禁用当前生效的 WireGuard 全放通 FORWARD 规则：" + line)
    return notes


def ensure_acl_chain() -> List[str]:
    warnings: List[str] = []
    if not shutil.which("iptables"):
        return ["未找到 iptables，跳过服务端访问控制 ACL"]

    p = run_iptables(["-N", ACL_CHAIN])
    if p.returncode not in (0, 1):
        warnings.append((p.stderr or p.stdout or "创建 ACL 链失败").strip())

    # v1.11.35：ACL 接管所有从 WireGuard 用户侧进入的转发流量，
    # 并自动禁用会导致 ACL 失效的 wg0->内网全放通策略。
    old_jump = run_iptables(["-C", "FORWARD", "-i", WG_IF, "-o", WG_IF, "-j", ACL_CHAIN])
    if old_jump.returncode == 0:
        run_iptables(["-D", "FORWARD", "-i", WG_IF, "-o", WG_IF, "-j", ACL_CHAIN])

    p = run_iptables(["-C", "FORWARD", "-i", WG_IF, "-j", ACL_CHAIN])
    if p.returncode != 0:
        p2 = run_iptables(["-I", "FORWARD", "1", "-i", WG_IF, "-j", ACL_CHAIN])
        if p2.returncode != 0:
            warnings.append((p2.stderr or p2.stdout or "插入 ACL 跳转规则失败").strip())

    # 启用 ACL 后，传统 wg0 -> 内网全放通会绕过权限控制。
    # 配置文件中用注释保留，当前内核规则中直接删除。
    warnings.extend(disable_acl_bypass_rules_in_config())
    warnings.extend(remove_live_acl_bypass_rules())
    return warnings


def sync_server_acl() -> Dict[str, object]:
    """按用户授权范围刷新服务端防火墙 ACL。

    这是真正的访问控制：即使用户手动修改客户端 AllowedIPs，
    未授权的用户 VPN IP 也不能访问未授权的站点内网。
    """
    warnings = ensure_acl_chain()
    if not shutil.which("iptables"):
        return {"ok": False, "enabled": False, "warnings": warnings, "message": "未找到 iptables，无法应用访问控制 ACL"}

    p = run_iptables(["-F", ACL_CHAIN])
    if p.returncode != 0:
        warnings.append((p.stderr or p.stdout or "刷新 ACL 链失败").strip())

    users = user_vpn_ips_by_name()
    all_site_lans = [x.strip() for x in normalize_allowed_ips(site_lan_allowed_ips()).split(",") if x.strip()]
    allow_count = 0
    deny_count = 0

    # 白名单：只放行用户被授权的站点网段。
    for user, ip in sorted(users.items()):
        allowed_lans = [x.strip() for x in normalize_allowed_ips(allowed_site_lans_for_user(user)).split(",") if x.strip()]
        for lan in allowed_lans:
            p = run_iptables(["-A", ACL_CHAIN, "-s", f"{ip}/32", "-d", lan, "-j", "ACCEPT"])
            if p.returncode == 0:
                allow_count += 1
            else:
                warnings.append((p.stderr or p.stdout or f"添加允许规则失败：{user} -> {lan}").strip())

    # 默认拒绝：VPN 用户访问所有站点网段，未命中白名单时统一拒绝。
    # 这样不会再按“用户 x 未授权站点”生成大量 REJECT 规则。
    for lan in all_site_lans:
        p = run_iptables(["-A", ACL_CHAIN, "-s", WG_CIDR, "-d", lan, "-j", "REJECT"])
        if p.returncode == 0:
            deny_count += 1
        else:
            warnings.append((p.stderr or p.stdout or f"添加默认拒绝规则失败：{lan}").strip())

    run_iptables(["-A", ACL_CHAIN, "-j", "RETURN"])
    hard_warnings = [
        w for w in warnings
        if "未找到 iptables" not in w
        and "Chain already exists" not in w
        and "链已存在" not in w
        and not w.startswith("已注释")
        and not w.startswith("已禁用当前生效")
    ]
    return {
        "ok": len(hard_warnings) == 0,
        "enabled": True,
        "chain": ACL_CHAIN,
        "users": len(users),
        "site_lans": len(all_site_lans),
        "allow_rules": allow_count,
        "deny_rules": deny_count,
        "warnings": warnings,
        "message": f"服务端访问控制已同步：{len(users)} 个用户，{len(all_site_lans)} 个站点网段；ACL 已接管全放通策略",
    }


def acl_status() -> Dict[str, object]:
    if not shutil.which("iptables"):
        return {"ok": False, "enabled": False, "message": "未找到 iptables"}
    p = run_iptables(["-S", ACL_CHAIN])
    return {"ok": p.returncode == 0, "enabled": p.returncode == 0, "chain": ACL_CHAIN, "rules": (p.stdout or "").splitlines()}


def apply_config_and_routes() -> Dict[str, object]:
    # 统一入口：应用配置时同时同步用户客户端 AllowedIPs、热更新 wg0、刷新站点路由和 ACL。
    # 这样“网段管理”页面只需要保存配置，真正同步与生效统一交给顶部“应用配置”按钮。
    user_sync = sync_existing_user_allowedips_once()
    live = apply_wg_live_only()
    route_sync = sync_all_site_lan_routes()
    acl_sync = sync_server_acl()
    ok = bool(user_sync.get("ok")) and bool(live.get("applied")) and bool(route_sync.get("ok")) and bool(acl_sync.get("ok"))
    if ok:
        clear_apply_pending("用户 AllowedIPs、WireGuard 配置、站点路由与访问控制已热更新")
    else:
        mark_apply_pending("应用配置未完全成功，请检查用户配置、WireGuard、路由和访问控制状态")
    return {
        "ok": ok,
        "message": "配置已应用，用户 AllowedIPs、路由与访问控制已刷新" if ok else "配置应用未完全成功",
        "user_sync": user_sync,
        "live": live,
        "route_sync": route_sync,
        "acl_sync": acl_sync,
        "status": config_apply_status(),
    }


def update_site_allowed_ips(name: str, allowed_ips: str) -> bool:
    target = f"# site-{name}"
    lines = WG_CONF.read_text(errors="ignore").splitlines()
    out = []
    in_target = False
    changed = False
    found = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("# "):
            in_target = stripped == target
        elif in_target and found and stripped == "":
            in_target = False
        if in_target and stripped == "[Peer]":
            found = True
        if in_target and stripped.startswith("AllowedIPs") and "=" in stripped:
            out.append(f"AllowedIPs = {allowed_ips}")
            changed = True
            continue
        out.append(line)
    if not found:
        raise HTTPException(status_code=404, detail="站点不存在")
    if not changed:
        raise HTTPException(status_code=500, detail="站点 Peer 中未找到 AllowedIPs，无法修改")
    WG_CONF.write_text("\n".join(out).rstrip() + "\n")
    return True


class UserCreate(BaseModel):
    name: str = Field(..., min_length=1)
    owner: str = ""


class SiteCreate(BaseModel):
    name: str = Field(..., min_length=1)
    lan_cidr: str = ""
    lan_if: str = ""
    remark: str = ""


class SiteNetworksUpdate(BaseModel):
    lan_cidr: str = ""


class UserOwnerUpdate(BaseModel):
    owner: str = ""


class SiteRemarkUpdate(BaseModel):
    remark: str = ""


class UserSitePermissionUpdate(BaseModel):
    mode: str = "all"
    sites: List[str] = []


class BulkSitePermissionUpdate(BaseModel):
    users: List[str] = []
    action: str = "add"  # add / remove / set_all / set_custom
    sites: List[str] = []


class SiteAuthorizedUsersUpdate(BaseModel):
    users: List[str] = []


class BackupRestoreRequest(BaseModel):
    name: str
    confirm: str


@app.get("/", response_class=HTMLResponse)
def index(request: Request, credentials: Optional[HTTPBasicCredentials] = Depends(security)):
    if not is_authenticated(request, credentials):
        return HTMLResponse(login_page())
    return Path(__file__).with_name("templates").joinpath("index.html").read_text()




def _login_response(request: Request, credentials: Optional[HTTPBasicCredentials] = None) -> HTMLResponse:
    # force=1 用于会话过期、升级完成、账号修改后强制回到登录页；
    # 同时清理旧 cookie，避免浏览器继续带着已失效或旧版本 cookie 反复进入首页。
    force = request.query_params.get("force") in {"1", "true", "yes"}
    msg = request.query_params.get("msg", "")
    if (not force) and is_authenticated(request, credentials):
        return HTMLResponse('<!doctype html><meta http-equiv="refresh" content="0;url=/">')
    hint = ""
    if msg == "expired":
        hint = "会话已过期，请重新登录"
    elif msg == "upgraded":
        hint = "系统已更新，请重新登录"
    resp = HTMLResponse(login_page(hint))
    if force:
        resp.delete_cookie(SESSION_COOKIE)
    return resp

@app.get("/api/login", response_class=HTMLResponse)
def api_login_page(request: Request, credentials: Optional[HTTPBasicCredentials] = Depends(security)):
    # 兼容部分手机浏览器/桌面模式/收藏地址直接打开 /api/login 的情况，
    # 避免 GET /api/login 返回 405 Method Not Allowed。
    return _login_response(request, credentials)

@app.get("/login", response_class=HTMLResponse)
def login_alias(request: Request, credentials: Optional[HTTPBasicCredentials] = Depends(security)):
    return _login_response(request, credentials)


@app.post("/api/login")
async def api_login(request: Request):
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    attempt_key = _login_attempt_key(request, username)
    retry_after = LOGIN_LIMITER.retry_after(attempt_key)
    if retry_after > 0:
        return HTMLResponse(login_page(f"登录失败次数过多，请 {retry_after} 秒后再试"), status_code=429)
    if not _verify_webui_credentials(username, password):
        LOGIN_LIMITER.record_failure(attempt_key)
        return HTMLResponse(login_page("用户名或密码错误"), status_code=401)
    LOGIN_LIMITER.record_success(attempt_key)
    expires = int(datetime.now().timestamp()) + SESSION_TTL_SECONDS
    token = _sign_session(username, expires)
    resp = HTMLResponse('<!doctype html><meta http-equiv="refresh" content="0;url=/">登录成功')
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="lax", secure=COOKIE_SECURE)
    return resp


@app.post("/api/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/api/peers")
def api_peers(_: str = Depends(require_auth)):
    peers = parse_wg_conf()
    status = parse_wg_dump()
    owners = user_owners_config()
    site_remarks = site_remarks_config()
    permissions = user_site_permissions_config()
    site_map = site_lans_by_name()
    for p in peers:
        s = status.get(p["public_key"], {"endpoint": "", "latest_handshake": 0, "latest_handshake_time": "", "latest_handshake_age": None, "rx": 0, "tx": 0, "online": False})
        p.update(s)
        p["rx_human"] = human_bytes(p["rx"])
        p["tx_human"] = human_bytes(p["tx"])
        allowed_parts = [x.strip() for x in str(p.get("allowed_ips", "")).split(",") if x.strip()]
        p["vpn_ip"] = allowed_parts[0] if allowed_parts else ""
        p["lan_ips"] = ", ".join(allowed_parts[1:]) if len(allowed_parts) > 1 else ""
        p["owner"] = owners.get(p["name"], "") if p.get("type") == "user" else ""
        p["remark"] = site_remarks.get(p["name"], "") if p.get("type") == "site" else ""
        if p.get("type") == "user":
            perm = permissions.get(p["name"], {"mode": "all", "sites": []})
            p["access_mode"] = perm.get("mode", "all")
            selected = list(perm.get("sites", [])) if isinstance(perm.get("sites", []), list) else []
            p["access_sites"] = selected
            p["access_site_count"] = len(site_map) if p["access_mode"] == "all" else len(selected)
            p["access_lan_count"] = len(allowed_site_lans_for_user(p["name"]))
            access_names = sorted(site_map.keys()) if p["access_mode"] == "all" else selected
            access_labels = []
            access_title_parts = []
            for site_name in access_names:
                site_key = str(site_name)
                label = site_remarks.get(site_key, "").strip() or site_key
                access_labels.append(label)
                lans = site_map.get(str(site_name), [])
                if lans:
                    access_title_parts.append(f"{label} / {site_key}（{', '.join(lans)}）")
                else:
                    access_title_parts.append(f"{label} / {site_key}" if label != site_key else site_key)
            p["access_site_labels"] = access_labels
            if p["access_mode"] == "all":
                p["access_detail"] = "全部站点"
                p["access_detail_title"] = "全部站点：" + "、".join(access_title_parts) if access_title_parts else "全部站点"
            else:
                p["access_detail"] = "、".join(access_labels) if access_labels else "未授权站点"
                p["access_detail_title"] = "、".join(access_title_parts) if access_title_parts else "未授权站点"
    return {"peers": peers, "online_threshold_seconds": ONLINE_THRESHOLD_SECONDS}




def read_journal(unit: str, lines: int = 120) -> str:
    lines = max(20, min(int(lines or 120), 500))
    p = subprocess.run(["journalctl", "-u", unit, "-n", str(lines), "--no-pager"], text=True, capture_output=True, timeout=15)
    return (p.stdout or p.stderr or "").strip()


def backup_clients_dir() -> Optional[str]:
    if not CLIENT_DIR.exists():
        return None
    ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    dest = CLIENT_DIR.parent / f"clients.bak.{ts}"
    shutil.copytree(CLIENT_DIR, dest)
    backups = sorted(CLIENT_DIR.parent.glob("clients.bak.*"), key=lambda x: x.stat().st_mtime, reverse=True)
    for old in backups[BACKUP_KEEP:]:
        shutil.rmtree(old, ignore_errors=True)
    return str(dest)





def conf_path_for(peer_type: str, name: str) -> Path:
    validate_existing_name(name)
    if peer_type == "user":
        return CLIENT_DIR / f"{name}.conf"
    if peer_type == "site":
        return SITE_DIR / f"{name}-wg0.conf"
    raise HTTPException(status_code=400, detail="节点类型必须是 user 或 site")


def conf_download_name(peer_type: str, name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", name)
    return f"{safe}.conf" if peer_type == "user" else f"{safe}-wg0.conf"

def read_client_allowed_ips_file(path: Path) -> Optional[str]:
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return None
    m = re.search(r"(?m)^AllowedIPs\s*=\s*(.*)$", text)
    if not m:
        return None
    return normalize_allowed_ips([m.group(1)])


def allowedips_sync_status() -> Dict:
    ensure_env()
    total = 0
    need_update = 0
    missing = 0
    users = []
    for conf in sorted(CLIENT_DIR.glob("*.conf")):
        total += 1
        current = read_client_allowed_ips_file(conf)
        name = conf.stem
        desired = client_allowed_ips_for_user(name)
        perm = user_permission_for(name)
        if current is None:
            missing += 1
            need_update += 1
            users.append({"name": name, "reason": "missing_allowedips", "desired": desired, "permission": perm})
            continue
        if normalize_allowed_ips([current]) != desired:
            need_update += 1
            users.append({"name": name, "reason": "outdated", "current": current, "desired": desired, "permission": perm})
    return {
        "ok": True,
        "allowed_ips": client_allowed_ips(),
        "total": total,
        "need_update": need_update,
        "missing": missing,
        "users": users,
        "synced": need_update == 0,
    }

def update_client_allowed_ips_file(path: Path, allowed_ips: str) -> bool:
    text = path.read_text(errors="ignore")
    new_text, n = re.subn(r"(?m)^AllowedIPs\s*=.*$", f"AllowedIPs = {allowed_ips}", text, count=1)
    if n == 0:
        return False
    if new_text != text:
        path.write_text(new_text)
    return True


def _load_json_dict(path: Path) -> Dict:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _write_config_json(cfg: Dict) -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        CONFIG_FILE.chmod(0o600)
    except Exception:
        pass


def user_owners_config() -> Dict[str, str]:
    owners = _load_json_dict(CONFIG_FILE).get("user_owners", {})
    if not isinstance(owners, dict):
        return {}
    return {
        str(name): str(owner).strip()
        for name, owner in owners.items()
        if str(name).strip() and str(owner).strip()
    }


def set_user_owner(name: str, owner: str) -> Dict[str, str]:
    validate_existing_name(name)
    cfg = _load_json_dict(CONFIG_FILE)
    owners = cfg.get("user_owners", {})
    if not isinstance(owners, dict):
        owners = {}
    owner = str(owner or "").strip()
    if owner:
        owners[name] = owner
    else:
        owners.pop(name, None)
    cfg["user_owners"] = owners
    _write_config_json(cfg)
    return {"name": name, "owner": owner}


def remove_user_owner(name: str) -> None:
    cfg = _load_json_dict(CONFIG_FILE)
    owners = cfg.get("user_owners", {})
    if not isinstance(owners, dict) or name not in owners:
        return
    owners.pop(name, None)
    cfg["user_owners"] = owners
    _write_config_json(cfg)


def site_remarks_config() -> Dict[str, str]:
    remarks = _load_json_dict(CONFIG_FILE).get("site_remarks", {})
    if not isinstance(remarks, dict):
        return {}
    return {
        str(name): str(remark).strip()
        for name, remark in remarks.items()
        if str(name).strip() and str(remark).strip()
    }


def set_site_remark(name: str, remark: str) -> Dict[str, str]:
    validate_existing_name(name)
    cfg = _load_json_dict(CONFIG_FILE)
    remarks = cfg.get("site_remarks", {})
    if not isinstance(remarks, dict):
        remarks = {}
    remark = str(remark or "").strip()[:200]
    if remark:
        remarks[name] = remark
    else:
        remarks.pop(name, None)
    cfg["site_remarks"] = remarks
    _write_config_json(cfg)
    return {"name": name, "remark": remark}


def remove_site_remark(name: str) -> None:
    cfg = _load_json_dict(CONFIG_FILE)
    remarks = cfg.get("site_remarks", {})
    if not isinstance(remarks, dict) or name not in remarks:
        return
    remarks.pop(name, None)
    cfg["site_remarks"] = remarks
    _write_config_json(cfg)


def ensure_reserved_config_from_sample() -> Dict:
    """运行中系统自修复：把安装包样例配置里的保留网段合并到真实配置。

    这样即使旧 upgrade.sh 没执行新迁移逻辑，只要新版 WebUI 被启动，
    也会自动补齐 /etc/wg-webui/config.json。
    """
    sample_path = Path(__file__).resolve().parents[1] / "config" / "config.json.sample"
    cfg = _load_json_dict(CONFIG_FILE)
    sample = _load_json_dict(sample_path)
    reserved = cfg.get("reserved_client_allowed_ips")
    if not isinstance(reserved, list):
        reserved = []
    changed = False
    for item in _csv_or_list(sample.get("reserved_client_allowed_ips", [])):
        try:
            item = str(ipaddress.ip_network(item, strict=False))
        except Exception:
            continue
        if item not in reserved:
            reserved.append(item)
            changed = True
    if "reserved_client_allowed_ips" not in cfg or cfg.get("reserved_client_allowed_ips") != reserved:
        cfg["reserved_client_allowed_ips"] = reserved
        changed = True
    if changed:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            CONFIG_FILE.chmod(0o600)
        except Exception:
            pass
    return cfg


def sync_existing_user_allowedips_once() -> Dict:
    """按用户授权范围把 AllowedIPs 写回已有用户配置。"""
    ensure_env()
    total = updated = skipped = missing = 0
    backup = None
    need_update = []
    if not CLIENT_DIR.exists():
        return {"ok": True, "total": 0, "updated": 0, "message": "client dir not exists"}
    for conf in sorted(CLIENT_DIR.glob("*.conf")):
        total += 1
        allowed = client_allowed_ips_for_user(conf.stem)
        current = read_client_allowed_ips_file(conf)
        if current is None:
            missing += 1
            need_update.append((conf, allowed))
        elif normalize_allowed_ips([current]) != allowed:
            need_update.append((conf, allowed))
        else:
            skipped += 1
    if need_update:
        backup = backup_clients_dir()
        for conf, allowed in need_update:
            try:
                if update_client_allowed_ips_file(conf, allowed):
                    updated += 1
            except Exception:
                pass
    return {"ok": True, "total": total, "updated": updated, "skipped": skipped, "missing": missing, "backup": backup}


@app.on_event("startup")
def startup_live_repair():
    # 面向已经在跑的系统：升级脚本不可靠时，应用启动也要完成配置补齐和已有用户配置同步。
    try:
        ensure_reserved_config_from_sample()
    except Exception as e:
        print(f"startup reserved config repair skipped: {e}")
    try:
        result = sync_existing_user_allowedips_once()
        print(f"startup allowedips sync: {result}")
    except Exception as e:
        print(f"startup allowedips sync skipped: {e}")
    try:
        route_result = sync_all_site_lan_routes()
        print(f"startup site route sync: {route_result}")
    except Exception as e:
        print(f"startup site route sync skipped: {e}")



@app.get("/api/service")
def api_service_status(_: str = Depends(require_auth)):
    return service_status()




@app.post("/api/webui/restart")
def api_webui_restart(_: str = Depends(require_auth)):
    """Restart only the WebUI service, not WireGuard."""
    if not shutil.which("systemctl"):
        raise HTTPException(status_code=500, detail="当前系统未检测到 systemctl，不能在网页中重启 WebUI")
    cmd = "sleep 1; systemctl restart wg-webui"
    try:
        subprocess.Popen(["bash", "-lc", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动 WebUI 重启任务失败：{e}")
    return {"ok": True, "message": "WebUI 重启已触发，请稍后重新登录"}


@app.post("/api/service/{action}")
def api_service_action(action: str, _: str = Depends(require_auth)):
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(status_code=400, detail="操作必须是 start、stop 或 restart")

    service = f"wg-quick@{WG_IF}"
    warnings: List[str] = []

    try:
        if action == "start":
            subprocess.run(["systemctl", "reset-failed", service], capture_output=True, text=True, timeout=10)
            p = run_service_cmd(["systemctl", "start", service], timeout=35)
            if p.returncode != 0:
                warnings.append(_combined_output(p) or f"systemctl start {service} 失败，已尝试用真实接口状态判断")
                # 如果 systemd 状态异常但 wg0 已经真实运行，不再误报失败。
                # 如果没有运行，再尝试 wg-quick up 作为兜底。
                if not service_status().get("running"):
                    p2 = run_service_cmd(["wg-quick", "up", WG_IF], timeout=35)
                    if p2.returncode != 0:
                        warnings.append(_combined_output(p2) or f"wg-quick up {WG_IF} 失败")

        elif action == "stop":
            p = run_service_cmd(["systemctl", "stop", service], timeout=35)
            if p.returncode != 0:
                warnings.append(_combined_output(p) or f"systemctl stop {service} 失败，已尝试 wg-quick down")
            if service_status().get("running") or service_status().get("interface_exists"):
                p2 = run_service_cmd(["wg-quick", "down", WG_IF], timeout=35)
                if p2.returncode != 0:
                    warnings.append(_combined_output(p2) or f"wg-quick down {WG_IF} 失败")

        elif action == "restart":
            subprocess.run(["systemctl", "reset-failed", service], capture_output=True, text=True, timeout=10)
            p = run_service_cmd(["systemctl", "restart", service], timeout=45)
            if p.returncode != 0:
                warnings.append(_combined_output(p) or f"systemctl restart {service} 失败，已尝试 wg-quick down/up")
                run_service_cmd(["wg-quick", "down", WG_IF], timeout=35)
                p2 = run_service_cmd(["wg-quick", "up", WG_IF], timeout=35)
                if p2.returncode != 0:
                    warnings.append(_combined_output(p2) or f"wg-quick up {WG_IF} 失败")

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail=f"{service} {action} 执行超时")

    st = service_status()
    if action in {"start", "restart"} and not st.get("running"):
        raise HTTPException(status_code=500, detail="WireGuard 未能启动：" + ("\n".join(warnings) or st.get("status_text", "未知错误")))
    if action == "stop" and (st.get("running") or st.get("interface_exists")):
        raise HTTPException(status_code=500, detail="WireGuard 未能停止：" + ("\n".join(warnings) or st.get("status_text", "未知错误")))

    return {"ok": True, "warnings": warnings, **st}


@app.post("/api/users")
def api_add_user(data: UserCreate, _: str = Depends(require_auth)):
    ensure_env(); validate_name(data.name)
    if any(p["type"] == "user" and p["name"] == data.name for p in parse_wg_conf()):
        raise HTTPException(status_code=400, detail="用户已存在")
    vpn_ip = next_ip(USER_IP_START, USER_IP_END)
    priv = genkey(); pub = pubkey(priv); psk = genpsk(); spub = server_pubkey()
    backup_conf()
    with WG_CONF.open("a") as f:
        f.write(f"\n# user-{data.name}\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {vpn_ip}/32\n")
    apply_wg()
    endpoint = current_server_endpoint()
    dns_line = interface_dns_line()
    conf = f"""[Interface]\nPrivateKey = {priv}\nAddress = {vpn_ip}/32\n{dns_line}\n[Peer]\nPublicKey = {spub}\nPresharedKey = {psk}\nEndpoint = {endpoint}\nAllowedIPs = {client_allowed_ips_for_user(data.name)}\nPersistentKeepalive = 25\n"""
    path = CLIENT_DIR / f"{data.name}.conf"
    path.write_text(conf); path.chmod(0o600)
    owner = str(data.owner or "").strip()
    if owner:
        set_user_owner(data.name, owner)
    return {"ok": True, "name": data.name, "ip": vpn_ip, "owner": owner}


@app.post("/api/users/{name}/owner")
def api_set_user_owner(name: str, data: UserOwnerUpdate, _: str = Depends(require_auth)):
    validate_existing_name(name)
    if not any(p["type"] == "user" and p["name"] == name for p in parse_wg_conf()):
        raise HTTPException(status_code=404, detail="user not found")
    result = set_user_owner(name, data.owner)
    return {"ok": True, **result}


@app.post("/api/sites")
def api_add_site(data: SiteCreate, _: str = Depends(require_auth)):
    ensure_env(); validate_name(data.name)
    site_cidrs = normalize_site_cidrs(data.lan_cidr, allow_empty=True)
    peers = parse_wg_conf()
    if any(p["type"] == "site" and p["name"] == data.name for p in peers):
        raise HTTPException(status_code=400, detail="站点已存在")
    conflicts = detect_site_cidr_conflicts(site_cidrs)
    if conflicts:
        raise HTTPException(status_code=400, detail=format_site_conflict_message(conflicts))
    site_lan_if = str(data.lan_if or "").strip()
    if site_lan_if and not NAME_RE.match(site_lan_if):
        raise HTTPException(status_code=400, detail="现场网卡名称格式错误")
    vpn_ip = next_ip(SITE_IP_START, SITE_IP_END)
    priv = genkey(); pub = pubkey(priv); psk = genpsk(); spub = server_pubkey()
    allowed = ", ".join([f"{vpn_ip}/32", *site_cidrs])
    backup_conf()
    with WG_CONF.open("a") as f:
        f.write(f"\n# site-{data.name}\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {allowed}\n")
    apply_message = "新增站点后必须点击应用配置，否则服务端运行态不会加载该站点 Peer，站点端会出现只发送不接收、无法握手"
    mark_apply_pending(apply_message)
    site_cidrs_text = format_cidrs(site_cidrs)
    lan_if_for_template = site_lan_if or "__LAN_IF__"
    conf = f"""[Interface]\nAddress = {vpn_ip}/24\nPrivateKey = {priv}\n\nPostUp = sysctl -w net.ipv4.ip_forward=1\nPostUp = iptables -t nat -C POSTROUTING -s {WG_CIDR} -o {lan_if_for_template} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {WG_CIDR} -o {lan_if_for_template} -j MASQUERADE\nPostUp = iptables -C FORWARD -i wg0 -o {lan_if_for_template} -s {WG_CIDR} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -o {lan_if_for_template} -s {WG_CIDR} -j ACCEPT\nPostUp = iptables -C FORWARD -i {lan_if_for_template} -o wg0 -d {WG_CIDR} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -i {lan_if_for_template} -o wg0 -d {WG_CIDR} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\nPostDown = iptables -t nat -D POSTROUTING -s {WG_CIDR} -o {lan_if_for_template} -j MASQUERADE 2>/dev/null || true\nPostDown = iptables -D FORWARD -i wg0 -o {lan_if_for_template} -s {WG_CIDR} -j ACCEPT 2>/dev/null || true\nPostDown = iptables -D FORWARD -i {lan_if_for_template} -o wg0 -d {WG_CIDR} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true\n\n[Peer]\nPublicKey = {spub}\nPresharedKey = {psk}\nEndpoint = {current_server_endpoint()}\nAllowedIPs = {WG_CIDR}\nPersistentKeepalive = 25\n"""
    path = SITE_DIR / f"{data.name}-wg0.conf"
    path.write_text(conf); path.chmod(0o600)
    remark = str(data.remark or "").strip()
    if remark:
        set_site_remark(data.name, remark)
    return {"ok": True, "name": data.name, "ip": vpn_ip, "site_cidrs": site_cidrs, "site_cidrs_text": site_cidrs_text, "remark": remark[:200], "message": apply_message, "apply_status": config_apply_status()}


@app.get("/api/sites/{name}/networks")
def api_get_site_networks(name: str, _: str = Depends(require_auth)):
    validate_existing_name(name)
    peer = next((p for p in parse_wg_conf() if p.get("type") == "site" and p.get("name") == name), None)
    if not peer:
        raise HTTPException(status_code=404, detail="站点不存在")
    vpn_ip, lan_cidrs = split_peer_allowed_ips(peer)
    return {
        "ok": True,
        "name": name,
        "vpn_ip": vpn_ip,
        "lan_cidrs": lan_cidrs,
        "lan_cidr": format_cidrs(lan_cidrs),
        "conflicts": detect_site_cidr_conflicts(lan_cidrs, ignore_site=name),
    }


@app.post("/api/sites/{name}/remark")
def api_update_site_remark(name: str, data: SiteRemarkUpdate, _: str = Depends(require_auth)):
    validate_existing_name(name)
    peer = next((p for p in parse_wg_conf() if p.get("type") == "site" and p.get("name") == name), None)
    if not peer:
        raise HTTPException(status_code=404, detail="站点不存在")
    result = set_site_remark(name, data.remark)
    return {"ok": True, **result}


@app.post("/api/sites/{name}/networks")
def api_update_site_networks(name: str, data: SiteNetworksUpdate, _: str = Depends(require_auth)):
    ensure_env()
    validate_existing_name(name)
    peer = next((p for p in parse_wg_conf() if p.get("type") == "site" and p.get("name") == name), None)
    if not peer:
        raise HTTPException(status_code=404, detail="站点不存在")
    vpn_ip, old_lans = split_peer_allowed_ips(peer)
    if not vpn_ip:
        raise HTTPException(status_code=500, detail="站点 Peer 缺少 VPN IP，无法修改内网网段")
    new_lans = normalize_site_cidrs(data.lan_cidr, allow_empty=True)
    conflicts = detect_site_cidr_conflicts(new_lans, ignore_site=name)
    if conflicts:
        raise HTTPException(status_code=400, detail=format_site_conflict_message(conflicts))
    old_allowed = normalize_allowed_ips([vpn_ip, *old_lans])
    new_allowed = normalize_allowed_ips([vpn_ip, *new_lans])
    if old_allowed == new_allowed:
        return {
            "ok": True,
            "changed": False,
            "name": name,
            "vpn_ip": vpn_ip,
            "lan_cidrs": new_lans,
            "lan_cidr": format_cidrs(new_lans),
            "message": "站点内网网段未变化，未执行热更新；如路由状态异常，请点击应用配置统一刷新",
            "apply_status": config_apply_status(),
            "sync": allowedips_sync_status(),
        }
    backup = backup_conf()
    update_site_allowed_ips(name, new_allowed)
    removed_lans = sorted(set(old_lans) - set(new_lans))
    if removed_lans:
        mark_stale_routes(removed_lans, "站点内网网段已修改，需要应用配置并清理旧路由")
    else:
        mark_apply_pending("站点内网网段已修改，需要应用配置并刷新路由")
    return {
        "ok": True,
        "changed": True,
        "name": name,
        "vpn_ip": vpn_ip,
        "old_lan_cidrs": old_lans,
        "lan_cidrs": new_lans,
        "lan_cidr": format_cidrs(new_lans),
        "backup": backup,
        "apply_status": config_apply_status(),
        "sync": allowedips_sync_status(),
        "message": "站点内网网段已更新；请点击应用配置刷新 WireGuard 和内核路由；如已有用户需要访问新网段，请同步用户 AllowedIPs",
    }


def site_conf_template_for_package(conf_text: str) -> str:
    """把站点配置里的现场出口网卡替换成安装时动态检测的占位符。"""
    lines = []
    for line in conf_text.splitlines():
        if "MASQUERADE" in line:
            line = re.sub(r"-o\s+\S+", "-o __LAN_IF__", line)
        if "FORWARD" in line and "-i wg0" in line:
            line = line.replace("-i wg0", "-i __WG_IF__")
            line = re.sub(r"-o\s+\S+", "-o __LAN_IF__", line)
        if "FORWARD" in line and "-o wg0" in line:
            line = line.replace("-o wg0", "-o __WG_IF__")
            line = re.sub(r"-i\s+\S+", "-i __LAN_IF__", line)
        lines.append(line)
    return "\n".join(lines).rstrip() + "\n"


def site_standard_install_script(site_name: str, lan_cidr: str) -> str:
    script = '''#!/usr/bin/env bash
set -euo pipefail

SITE_NAME="__SITE_NAME__"
SITE_LAN="__SITE_LAN__"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_TEMPLATE="${CONF_TEMPLATE:-$SCRIPT_DIR/wg0.conf.template}"
WG_IF="${WG_IF:-wg-site}"
CONF_TARGET="/etc/wireguard/${WG_IF}.conf"
STATE_FILE="${STATE_FILE:-$SCRIPT_DIR/.site-install-state}"
LOG_FILE="${LOG_FILE:-$SCRIPT_DIR/install-site.log}"
LAN_IF="${LAN_IF:-}"
ASSUME_YES="${ASSUME_YES:-0}"

log(){ echo "[INFO] $*" | tee -a "$LOG_FILE"; }
ok(){ echo "[OK] $*" | tee -a "$LOG_FILE"; }
warn(){ echo "[WARN] $*" | tee -a "$LOG_FILE"; }
fail(){ echo "[FAIL] $*" | tee -a "$LOG_FILE"; exit 1; }
confirm(){
  local prompt="$1" ans
  [ "$ASSUME_YES" = "1" ] && return 0
  read -r -p "$prompt [y/N]: " ans || true
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

need_root(){ [ "$(id -u)" -eq 0 ] || fail "请使用 root 执行"; }
need_linux(){ [ "$(uname -s)" = "Linux" ] || fail "当前不是 Linux 系统"; }
need_systemd(){ command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || fail "未检测到 systemd"; }
need_tun(){ [ -e /dev/net/tun ] || fail "未检测到 /dev/net/tun"; }
need_template(){ [ -f "$CONF_TEMPLATE" ] || fail "缺少 $CONF_TEMPLATE"; }

show_interfaces(){
  echo "当前网卡信息：" | tee -a "$LOG_FILE"
  ip -br addr 2>/dev/null | tee -a "$LOG_FILE" || true
  echo "默认路由：" | tee -a "$LOG_FILE"
  ip route show default 2>/dev/null | tee -a "$LOG_FILE" || true
}

select_lan_if(){
  local detected ans
  show_interfaces
  detected="$(ip route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
  if [ -n "$LAN_IF" ]; then
    log "使用指定出口网卡：$LAN_IF"
  elif [ -n "$detected" ]; then
    if [ "$ASSUME_YES" = "1" ]; then
      LAN_IF="$detected"
    else
      read -r -p "检测到默认出口网卡：$detected，是否使用？[Y/n]: " ans || true
      case "${ans:-Y}" in n|N|no|NO) read -r -p "请输入出口网卡名称: " LAN_IF ;; *) LAN_IF="$detected" ;; esac
    fi
  else
    read -r -p "未检测到默认路由，请输入出口网卡名称: " LAN_IF
  fi
  [ -n "$LAN_IF" ] || fail "出口网卡不能为空"
  ip link show "$LAN_IF" >/dev/null 2>&1 || fail "网卡 $LAN_IF 不存在"
}

render_config(){
  mkdir -p /etc/wireguard
  sed "s/__LAN_IF__/$LAN_IF/g; s/__WG_IF__/$WG_IF/g" "$CONF_TEMPLATE" > "$SCRIPT_DIR/${WG_IF}.conf.rendered"
}

write_config(){
  local rendered="$SCRIPT_DIR/${WG_IF}.conf.rendered"
  [ -f "$CONF_TARGET" ] && cp -a "$CONF_TARGET" "$CONF_TARGET.bak.$(date +%F-%H%M%S)"
  install -m 0600 "$rendered" "$CONF_TARGET"
  ok "已写入 $CONF_TARGET"
}

enable_forward(){
  sysctl -w net.ipv4.ip_forward=1 2>&1 | tee -a "$LOG_FILE" || fail "开启 ip_forward 失败"
  if [ -d /etc/sysctl.d ]; then
    SYSCTL_FILE="/etc/sysctl.d/99-wireguard-site-${WG_IF}.conf"
    echo 'net.ipv4.ip_forward=1' > "$SYSCTL_FILE"
  fi
}

start_wg(){
  systemctl daemon-reload
  systemctl reset-failed "wg-quick@$WG_IF" >/dev/null 2>&1 || true
  systemctl enable "wg-quick@$WG_IF" 2>&1 | tee -a "$LOG_FILE" || fail "启用 wg-quick@$WG_IF 失败"
  systemctl restart "wg-quick@$WG_IF" 2>&1 | tee -a "$LOG_FILE" || fail "启动 wg-quick@$WG_IF 失败，请查看 journalctl -u wg-quick@$WG_IF -n 80 --no-pager"
  systemctl is-active --quiet "wg-quick@$WG_IF" || fail "wg-quick@$WG_IF 未运行"
}

write_state(){
  cat > "$STATE_FILE" <<EOF
SITE_NAME="$SITE_NAME"
SITE_LAN="$SITE_LAN"
MODE="standard"
WG_IF="$WG_IF"
LAN_IF="$LAN_IF"
CONF_TARGET="$CONF_TARGET"
SYSCTL_FILE="${SYSCTL_FILE:-/etc/sysctl.d/99-wireguard-site-${WG_IF}.conf}"
EOF
}

post_check(){
  echo "===== 安装后自检 =====" | tee -a "$LOG_FILE"
  systemctl is-active --quiet "wg-quick@$WG_IF" && ok "服务运行：wg-quick@$WG_IF" || warn "服务未运行：wg-quick@$WG_IF"
  ip link show "$WG_IF" >/dev/null 2>&1 && ok "接口存在：$WG_IF" || warn "接口不存在：$WG_IF"
  wg show "$WG_IF" 2>&1 | tee -a "$LOG_FILE" || true
}

main(){
  need_root; need_linux; need_systemd; need_tun; need_template
  echo "===== 标准内核 WireGuard 部署 =====" | tee -a "$LOG_FILE"
  echo "站点：$SITE_NAME" | tee -a "$LOG_FILE"
  echo "接口：$WG_IF" | tee -a "$LOG_FILE"
  echo "配置：$CONF_TARGET" | tee -a "$LOG_FILE"
  select_lan_if
  render_config
  echo "出口网卡：$LAN_IF" | tee -a "$LOG_FILE"
  grep -E 'Address|Endpoint|AllowedIPs|PostUp|PostDown' "$SCRIPT_DIR/${WG_IF}.conf.rendered" | tee -a "$LOG_FILE" || true
  confirm "确认写入配置并启动 $WG_IF？" || fail "用户取消安装"
  write_config
  enable_forward
  start_wg
  write_state
  post_check
  ok "部署完成，日志：$LOG_FILE"
}

main "$@"
'''
    return script.replace("__SITE_NAME__", site_name).replace("__SITE_LAN__", lan_cidr)

def site_install_script(site_name: str, lan_cidr: str) -> str:
    script = '''#!/usr/bin/env bash
set -euo pipefail

SITE_NAME="__SITE_NAME__"
SITE_LAN="__SITE_LAN__"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 站点包结构：根目录只保留 site.sh 和说明文件，核心脚本/模板放在 bundle/。
# 兼容直接执行 bundle/install.sh，也兼容旧包里根目录 install.sh 的场景。
if [ -d "$SCRIPT_DIR/bundle" ]; then
  PACKAGE_ROOT="$SCRIPT_DIR"
  CORE_DIR="$SCRIPT_DIR/bundle"
else
  CORE_DIR="$SCRIPT_DIR"
  PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
CONF_TEMPLATE="$CORE_DIR/wg0.conf.template"
STANDARD_INSTALL="$CORE_DIR/.standard-install.sh"
USERSPACE_ARCHIVE="$CORE_DIR/tools/wireguard-userspace-compat-v0.5.0.tar.gz"
USERSPACE_WORK="$CORE_DIR/.userspace-tool"
STATE_FILE="$PACKAGE_ROOT/.site-install-state"
LOG_FILE="$PACKAGE_ROOT/install-site.log"
WG_IF="${WG_IF:-}"
ASSUME_YES="0"
ACTION="${1:-menu}"
[ "${ACTION:-}" = "--auto" ] && ACTION="deploy" && ASSUME_YES="1"

log(){ echo "[INFO] $*" | tee -a "$LOG_FILE"; }
ok(){ echo "[OK] $*" | tee -a "$LOG_FILE"; }
warn(){ echo "[WARN] $*" | tee -a "$LOG_FILE"; }
fail(){ echo "[FAIL] $*" | tee -a "$LOG_FILE"; exit 1; }
pause(){ read -r -p "按回车继续..." _ || true; }

need_root(){ [ "$(id -u)" -eq 0 ] || fail "请使用 root 执行：sudo bash site.sh"; }
need_linux(){ [ "$(uname -s)" = "Linux" ] || fail "当前不是 Linux 系统，安装已停止"; }
need_systemd(){ command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || fail "未检测到 systemd，当前自动部署仅支持 systemd 系统"; }
need_tun(){ [ -e /dev/net/tun ] || fail "未检测到 /dev/net/tun，请先开启 TUN/TAP 支持"; }
need_files(){
  [ -f "$CONF_TEMPLATE" ] || fail "缺少 bundle/wg0.conf.template，请在完整站点部署包目录内执行"
  [ -f "$STANDARD_INSTALL" ] || fail "缺少 bundle/.standard-install.sh，站点包不完整"
}

has_cmd(){ command -v "$1" >/dev/null 2>&1; }

iface_busy(){
  local iface="$1"
  if [ -f "/etc/wireguard/${iface}.conf" ]; then return 0; fi
  if ip link show "$iface" >/dev/null 2>&1; then return 0; fi
  if systemctl is-active --quiet "wg-quick@$iface" 2>/dev/null; then return 0; fi
  return 1
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

select_wg_if(){
  local candidate i manual
  if [ -n "${WG_IF:-}" ]; then
    if iface_busy "$WG_IF"; then
      fail "指定接口 $WG_IF 已存在或正在运行，请换一个名称，例如：sudo WG_IF=wg-site bash site.sh install"
    fi
    return 0
  fi
  for candidate in wg0 wg-site wg-xaj wgsite wg1 wg2 wg3 wg4 wg5 wg6 wg7 wg8 wg9; do
    if ! iface_busy "$candidate"; then
      WG_IF="$candidate"
      break
    fi
  done
  [ -n "$WG_IF" ] || fail "没有找到可用的 WireGuard 接口名，请用 WG_IF=名称 手动指定"
  if [ "$WG_IF" != "wg0" ]; then
    warn "检测到 wg0 已存在或正在运行，本次自动改用接口：$WG_IF"
    warn "这适合服务器同时作为 WireGuard 服务端和站点接入端的双角色场景；安装不会覆盖现有 wg0。"
  fi
  if [ "$ASSUME_YES" != "1" ]; then
    read -r -p "本次使用 WireGuard 接口 $WG_IF，直接回车确认，或输入自定义接口名: " manual || true
    manual="$(echo "${manual:-}" | tr -d '[:space:]')"
    if [ -n "$manual" ]; then
      valid_wg_if "$manual" || fail "接口名只能使用字母、数字、横线、下划线、点号，且长度不超过 15 个字符"
      WG_IF="$manual"
      if iface_busy "$WG_IF"; then
        fail "接口 $WG_IF 已存在或正在运行，不能覆盖"
      fi
    fi
  fi
  echo "已确认 WireGuard 接口：$WG_IF" | tee -a "$LOG_FILE"
}

show_interfaces(){
  echo "当前网卡信息：" | tee -a "$LOG_FILE"
  ip -br addr 2>/dev/null | tee -a "$LOG_FILE" || true
  echo "默认路由：" | tee -a "$LOG_FILE"
  ip route show default 2>/dev/null | tee -a "$LOG_FILE" || true
}

select_lan_if(){
  local detected ans
  show_interfaces
  detected="$(ip route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
  if [ -n "${LAN_IF:-}" ]; then
    log "使用指定出口网卡：$LAN_IF"
  elif [ -n "$detected" ]; then
    if [ "$ASSUME_YES" = "1" ]; then
      LAN_IF="$detected"
    else
      read -r -p "检测到默认出口网卡：$detected，是否使用？[Y/n]: " ans || true
      case "${ans:-Y}" in n|N|no|NO) read -r -p "请输入出口网卡名称: " LAN_IF ;; *) LAN_IF="$detected" ;; esac
    fi
  else
    read -r -p "未检测到默认路由，请输入出口网卡名称: " LAN_IF
  fi
  [ -n "$LAN_IF" ] || fail "出口网卡不能为空"
  ip link show "$LAN_IF" >/dev/null 2>&1 || fail "网卡 $LAN_IF 不存在"
}

render_userspace_conf(){
  USERSPACE_CONF="$SCRIPT_DIR/${WG_IF}.userspace.conf"
  sed "s/__LAN_IF__/$LAN_IF/g; s/__WG_IF__/$WG_IF/g" "$CONF_TEMPLATE" > "$USERSPACE_CONF"
}

missing_required_commands(){
  local missing=()
  has_cmd wg || missing+=(wireguard-tools)
  has_cmd wg-quick || missing+=(wireguard-tools)
  has_cmd ip || missing+=(iproute)
  has_cmd iptables || missing+=(iptables)
  printf '%s\n' "${missing[@]}" | awk 'NF && !seen[$0]++'
}

apt_pkg_name(){
  case "$1" in
    wireguard-tools) echo "wireguard-tools" ;;
    iproute) echo "iproute2" ;;
    iptables) echo "iptables" ;;
  esac
}

yum_pkg_name(){
  case "$1" in
    wireguard-tools) echo "wireguard-tools" ;;
    iproute) echo "iproute" ;;
    iptables) echo "iptables" ;;
  esac
}

install_minimal_deps(){
  mapfile -t missing < <(missing_required_commands)
  if [ "${#missing[@]}" -eq 0 ]; then
    ok "WireGuard 基础命令已存在"
    return 0
  fi
  log "缺失基础组件：${missing[*]}"
  if has_cmd apt-get; then
    local pkgs=() item pkg
    for item in "${missing[@]}"; do pkg="$(apt_pkg_name "$item")"; [ -n "$pkg" ] && pkgs+=("$pkg"); done
    export DEBIAN_FRONTEND=noninteractive
    apt-get update 2>&1 | tee -a "$LOG_FILE" || warn "apt-get update 失败，继续尝试使用已有索引安装"
    apt-get install -y --no-install-recommends "${pkgs[@]}" 2>&1 | tee -a "$LOG_FILE" || fail "基础组件安装失败：${pkgs[*]}"
  elif has_cmd dnf; then
    local pkgs=() item pkg
    for item in "${missing[@]}"; do pkg="$(yum_pkg_name "$item")"; [ -n "$pkg" ] && pkgs+=("$pkg"); done
    dnf install -y "${pkgs[@]}" 2>&1 | tee -a "$LOG_FILE" || fail "基础组件安装失败：${pkgs[*]}"
  elif has_cmd yum; then
    local pkgs=() item pkg
    for item in "${missing[@]}"; do pkg="$(yum_pkg_name "$item")"; [ -n "$pkg" ] && pkgs+=("$pkg"); done
    yum install -y "${pkgs[@]}" 2>&1 | tee -a "$LOG_FILE" || fail "基础组件安装失败：${pkgs[*]}"
  else
    fail "未检测到 apt/dnf/yum，请手动安装 wireguard-tools、iptables、iproute2/iproute 后重试"
  fi
}

kernel_wg_supported(){
  local test_if="wgtest$$"
  if ip link add "$test_if" type wireguard >/dev/null 2>&1; then
    ip link delete "$test_if" >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

status_view(){
  echo "========== 当前状态 =========="
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    echo "站点：${SITE_NAME:-unknown}"
    echo "接口：${WG_IF:-unknown}"
    echo "模式：${MODE:-unknown}"
  else
    echo "未找到本部署包状态文件，可能尚未安装。"
  fi
  local iface="${WG_IF:-wg0}"
  systemctl status "wg-quick@$iface" --no-pager -l 2>/dev/null || true
  echo
  wg show "$iface" 2>/dev/null || true
}

run_standard(){
  ok "当前内核支持 WireGuard，使用标准站点部署"
  WG_IF="$WG_IF" STATE_FILE="$STATE_FILE" LOG_FILE="$LOG_FILE" ASSUME_YES="$ASSUME_YES" bash "$STANDARD_INSTALL"
}

run_userspace(){
  [ -f "$USERSPACE_ARCHIVE" ] || fail "当前内核不支持 WireGuard，但站点包内缺少兼容部署工具"
  warn "当前内核不支持 WireGuard，自动切换到用户态兼容部署"
  rm -rf "$USERSPACE_WORK"
  mkdir -p "$USERSPACE_WORK"
  tar -xzf "$USERSPACE_ARCHIVE" -C "$USERSPACE_WORK"
  local tool_dir
  tool_dir="$(find "$USERSPACE_WORK" -maxdepth 1 -type d -name 'wireguard-userspace-compat-*' | head -1)"
  [ -n "$tool_dir" ] || fail "兼容部署工具包结构异常"
  select_lan_if
  render_userspace_conf
  WG_IF="$WG_IF" bash "$tool_dir/install.sh" --auto --conf "$USERSPACE_CONF" --no-start
  ok "用户态兼容环境和配置已写入，准备由 systemd 统一启动 $WG_IF"
  systemctl stop "wg-quick@$WG_IF" >/dev/null 2>&1 || true
  wg-quick down "$WG_IF" >/dev/null 2>&1 || true
  ip link delete "$WG_IF" >/dev/null 2>&1 || true
  systemctl daemon-reload
  systemctl reset-failed "wg-quick@$WG_IF" >/dev/null 2>&1 || true
  systemctl enable "wg-quick@$WG_IF" 2>&1 | tee -a "$LOG_FILE" || fail "启用 wg-quick@$WG_IF 失败"
  systemctl start "wg-quick@$WG_IF" 2>&1 | tee -a "$LOG_FILE" || fail "启动 wg-quick@$WG_IF 失败，请查看 journalctl -u wg-quick@$WG_IF -n 80 --no-pager"
  systemctl is-active --quiet "wg-quick@$WG_IF" || fail "wg-quick@$WG_IF 未处于 active 状态，请查看 journalctl -u wg-quick@$WG_IF -n 80 --no-pager"
  cat > "$STATE_FILE" <<EOF
SITE_NAME="$SITE_NAME"
SITE_LAN="$SITE_LAN"
MODE="userspace"
WG_IF="$WG_IF"
LAN_IF="${LAN_IF:-auto}"
CONF_TARGET="/etc/wireguard/${WG_IF}.conf"
SYSCTL_FILE="/etc/sysctl.d/99-wireguard-site-${WG_IF}.conf"
EOF
  ok "用户态兼容部署完成"
  wg show "$WG_IF" 2>&1 | tee -a "$LOG_FILE" || true
}

preflight(){
  echo "站点内网：$SITE_LAN" | tee -a "$LOG_FILE"
  need_root
  need_linux
  need_systemd
  need_tun
  need_files
}

deploy(){
  : > "$LOG_FILE"
  echo "===== WireGuard 站点一键部署：$SITE_NAME =====" | tee -a "$LOG_FILE"
  preflight
  install_minimal_deps
  select_wg_if
  echo "本次接口：$WG_IF" | tee -a "$LOG_FILE"
  if kernel_wg_supported; then
    run_standard
  else
    run_userspace
  fi
}

menu(){
  while true; do
    clear 2>/dev/null || true
    echo "------------------------------------------------------------"
    echo "WireGuard 站点部署"
    echo "站点：$SITE_NAME"
    echo "内网：$SITE_LAN"
    echo "------------------------------------------------------------"
    echo "说明："
    echo "- 会自动检测内核 WireGuard，不支持时会尝试用户态兼容模式。"
    echo "- 如果本机已有 wg0，会自动改用 wg-site / wg1 等空闲接口。"
    echo "- 安装前会确认出口网卡和接口名，不会覆盖已有 wg0 配置。"
    echo
    echo "1) 开始部署"
    echo "2) 查看当前部署状态"
    echo "9) 返回上级菜单"
    echo "0) 退出"
    echo "------------------------------------------------------------"
    read -r -p "请选择 [0/1/2/9]: " c || true
    case "$c" in
      1) deploy; pause;;
      2) status_view; pause;;
      9|0) exit 0;;
      *) echo "无效选择，请输入 0、1、2 或 9。"; pause;;
    esac
  done
}

main(){
  case "$ACTION" in
    deploy) deploy ;;
    status|--status) status_view ;;
    menu|*) menu ;;
  esac
}

main "$@"
'''
    return script.replace("__SITE_NAME__", site_name).replace("__SITE_LAN__", lan_cidr)

def _legacy_site_uninstall_script_unused() -> str:
    return '''#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 站点包结构：根目录只保留 site.sh 和说明文件，核心脚本/模板放在 bundle/。
# 兼容直接执行 bundle/uninstall.sh，也兼容旧包里根目录 uninstall.sh 的场景。
if [ -d "$SCRIPT_DIR/bundle" ]; then
  PACKAGE_ROOT="$SCRIPT_DIR"
else
  PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
STATE_FILE="$PACKAGE_ROOT/.site-install-state"
LOG_FILE="$PACKAGE_ROOT/uninstall-site.log"
WG_IF="${WG_IF:-}"
CONF_TARGET=""
SYSCTL_FILE="/etc/sysctl.d/99-wireguard-site.conf"

ok(){ echo "[OK] $*" | tee -a "$LOG_FILE"; }
warn(){ echo "[WARN] $*" | tee -a "$LOG_FILE"; }
fail(){ echo "[FAIL] $*" | tee -a "$LOG_FILE"; exit 1; }
pause(){ read -r -p "按回车继续..." _ || true; }
need_root(){ [ "$(id -u)" -eq 0 ] || fail "请使用 root 执行：sudo bash site.sh"; }

load_state(){
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
  fi
  if [ -z "${WG_IF:-}" ]; then
    read -r -p "未找到安装状态，请输入要卸载的 WireGuard 接口名: " WG_IF
  fi
  [ -n "$WG_IF" ] || fail "接口名不能为空"
  CONF_TARGET="${CONF_TARGET:-/etc/wireguard/${WG_IF}.conf}"
}

remove_iptables_rule_repeated(){
  local table="$1"; shift
  while iptables ${table:+-t "$table"} -D "$@" 2>/dev/null; do :; done
}

remove_forward_rules_by_scan(){
  local line hay cidr outif deleted=0
  mapfile -t cidrs < <(collect_cidrs | sed '/^$/d' | sort -u)
  mapfile -t outifs < <(collect_outifs | sed '/^$/d' | sort -u)
  while IFS= read -r line; do
    hay=" $line "
    [[ "$line" == "-A FORWARD "* ]] || continue
    [[ "$hay" == *" -j ACCEPT "* ]] || continue
    [[ "$hay" == *" -i $WG_IF "* || "$hay" == *" -o $WG_IF "* ]] || continue
    if [ "${#cidrs[@]}" -gt 0 ]; then
      local cidr_match=0
      for cidr in "${cidrs[@]}"; do
        if [[ "$hay" == *" -s $cidr "* || "$hay" == *" -d $cidr "* ]]; then cidr_match=1; fi
      done
      [ "$cidr_match" = "1" ] || continue
    fi
    if [ "${#outifs[@]}" -gt 0 ]; then
      local outif_match=0
      for outif in "${outifs[@]}"; do
        if [[ "$hay" == *" -i $outif "* || "$hay" == *" -o $outif "* ]]; then outif_match=1; fi
      done
      [ "$outif_match" = "1" ] || continue
    fi
    while true; do
      read -r -a rule_parts <<< "$line"
      rule_parts[0]="-D"
      iptables "${rule_parts[@]}" 2>/dev/null || break
      deleted=$((deleted + 1))
    done
  done < <(iptables -S FORWARD 2>/dev/null || true)
  [ "$deleted" -gt 0 ] && echo "已删除 FORWARD 规则 $deleted 条"
}

collect_cidrs(){
  if [ -f "$CONF_TARGET" ]; then
    grep -Eo -- '-s[[:space:]]+[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/[0-9]+' "$CONF_TARGET" | awk '{print $2}'
    grep -Eo -- '-d[[:space:]]+[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/[0-9]+' "$CONF_TARGET" | awk '{print $2}'
  fi
}

collect_outifs(){
  if [ -f "$CONF_TARGET" ]; then
    grep -Eo -- '-o[[:space:]]+[^[:space:]]+' "$CONF_TARGET" | awk '{print $2}'
  fi
}

cleanup_rules(){
  if ! command -v iptables >/dev/null 2>&1; then
    warn "未找到 iptables，跳过规则清理"
    return 0
  fi
  mapfile -t cidrs < <(collect_cidrs | sed '/^$/d' | sort -u)
  mapfile -t outifs < <(collect_outifs | sed '/^$/d' | sort -u)
  for cidr in "${cidrs[@]:-}"; do
    for outif in "${outifs[@]:-}"; do
      [ -n "$cidr" ] && [ -n "$outif" ] || continue
      remove_iptables_rule_repeated nat POSTROUTING -s "$cidr" -o "$outif" -j MASQUERADE || true
      remove_iptables_rule_repeated "" FORWARD -i "$WG_IF" -o "$outif" -s "$cidr" -j ACCEPT || true
      remove_iptables_rule_repeated "" FORWARD -i "$outif" -o "$WG_IF" -d "$cidr" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true
      remove_iptables_rule_repeated "" FORWARD -i "$outif" -o "$WG_IF" -d "$cidr" -m state --state RELATED,ESTABLISHED -j ACCEPT || true
    done
  done
  ok "已清理本次配置匹配的 NAT/FORWARD 规则"
}

stop_service(){
  systemctl stop "wg-quick@$WG_IF" 2>/dev/null || true
  wg-quick down "$WG_IF" >/dev/null 2>&1 || true
  ip link delete "$WG_IF" >/dev/null 2>&1 || true
  systemctl disable "wg-quick@$WG_IF" 2>/dev/null || true
  systemctl reset-failed "wg-quick@$WG_IF" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
}

status_view(){
  echo "========== 当前部署状态 =========="
  echo "接口：$WG_IF"
  echo "配置：$CONF_TARGET"
  echo "状态文件：$STATE_FILE"
  systemctl status "wg-quick@$WG_IF" --no-pager -l 2>/dev/null || true
  echo
  wg show "$WG_IF" 2>/dev/null || true
}

remove_site(){
  echo "即将清除本次站点部署："
  echo "- 停止并禁用 wg-quick@$WG_IF"
  echo "- 删除 $CONF_TARGET"
  echo "- 清理本配置匹配的 NAT/FORWARD 规则"
  echo "- 删除本目录下的安装状态和日志"
  echo
  read -r -p "请输入 DELETE-SITE-WG 确认: " confirm
  [ "$confirm" = "DELETE-SITE-WG" ] || fail "确认不匹配，已取消"
  stop_service
  cleanup_rules
  rm -f "$CONF_TARGET" "$SYSCTL_FILE"
  rm -f "$STATE_FILE" "$SCRIPT_DIR"/*.conf.rendered "$SCRIPT_DIR/install-site.log" "$SCRIPT_DIR/uninstall-site.log"
  ok "站点部署已清除。系统软件包未卸载。"
}

menu(){
  while true; do
    echo
    echo "========== WireGuard 站点卸载 =========="
    echo "当前接口：$WG_IF"
    echo "1) 查看状态"
    echo "2) 停止服务，保留配置"
    echo "3) 清除本次站点部署"
    echo "0) 退出"
    read -r -p "请选择: " c
    case "$c" in
      1) status_view; pause;;
      2) stop_service; ok "已停止 wg-quick@$WG_IF，配置仍保留：$CONF_TARGET"; pause;;
      3) remove_site; pause;;
      0) exit 0;;
      *) echo "无效选择";;
    esac
  done
}

main(){
  : > "$LOG_FILE"
  need_root
  load_state
  case "${1:-menu}" in
    --remove|remove) remove_site ;;
    --status|status) status_view ;;
    menu|*) menu ;;
  esac
}

main "$@"
'''

def site_uninstall_script() -> str:
    return '''#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 站点包结构：根目录只保留 site.sh 和说明文件，核心脚本/模板放在 bundle/。
# 兼容直接执行 bundle/uninstall.sh，也兼容旧包里根目录 uninstall.sh 的场景。
if [ -d "$SCRIPT_DIR/bundle" ]; then
  PACKAGE_ROOT="$SCRIPT_DIR"
else
  PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
STATE_FILE="$PACKAGE_ROOT/.site-install-state"
LOG_FILE="$PACKAGE_ROOT/uninstall-site.log"
WG_IF="${WG_IF:-}"
CONF_TARGET=""
SYSCTL_FILE=""

ok(){ echo "[OK] $*" | tee -a "$LOG_FILE"; }
warn(){ echo "[WARN] $*" | tee -a "$LOG_FILE"; }
fail(){ echo "[FAIL] $*" | tee -a "$LOG_FILE"; exit 1; }
pause(){ read -r -p "按回车继续..." _ || true; }
need_root(){ [ "$(id -u)" -eq 0 ] || fail "请使用 root 执行：sudo bash site.sh"; }

load_state(){
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
  fi
  if [ -z "${WG_IF:-}" ]; then
    read -r -p "未找到安装状态，请输入要卸载的 WireGuard 接口名: " WG_IF
  fi
  [ -n "$WG_IF" ] || fail "接口名不能为空"
  CONF_TARGET="${CONF_TARGET:-/etc/wireguard/${WG_IF}.conf}"
  SYSCTL_FILE="${SYSCTL_FILE:-/etc/sysctl.d/99-wireguard-site-${WG_IF}.conf}"
}

remove_iptables_rule_repeated(){
  local table="$1"; shift
  while iptables ${table:+-t "$table"} -D "$@" 2>/dev/null; do :; done
}

remove_forward_rules_by_scan(){
  local line hay cidr outif deleted=0
  mapfile -t cidrs < <(collect_cidrs | sed '/^$/d' | sort -u)
  mapfile -t outifs < <(collect_outifs | sed '/^$/d' | sort -u)
  while IFS= read -r line; do
    hay=" $line "
    [[ "$line" == "-A FORWARD "* ]] || continue
    [[ "$hay" == *" -j ACCEPT "* ]] || continue
    [[ "$hay" == *" -i $WG_IF "* || "$hay" == *" -o $WG_IF "* ]] || continue
    if [ "${#cidrs[@]}" -gt 0 ]; then
      local cidr_match=0
      for cidr in "${cidrs[@]}"; do
        if [[ "$hay" == *" -s $cidr "* || "$hay" == *" -d $cidr "* ]]; then cidr_match=1; fi
      done
      [ "$cidr_match" = "1" ] || continue
    fi
    if [ "${#outifs[@]}" -gt 0 ]; then
      local outif_match=0
      for outif in "${outifs[@]}"; do
        if [[ "$hay" == *" -i $outif "* || "$hay" == *" -o $outif "* ]]; then outif_match=1; fi
      done
      [ "$outif_match" = "1" ] || continue
    fi
    while true; do
      read -r -a rule_parts <<< "$line"
      rule_parts[0]="-D"
      iptables "${rule_parts[@]}" 2>/dev/null || break
      deleted=$((deleted + 1))
    done
  done < <(iptables -S FORWARD 2>/dev/null || true)
  [ "$deleted" -gt 0 ] && echo "已删除 FORWARD 规则 $deleted 条"
}

collect_cidrs(){
  if [ -f "$CONF_TARGET" ]; then
    grep -Eo -- '-s[[:space:]]+[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/[0-9]+' "$CONF_TARGET" | awk '{print $2}'
    grep -Eo -- '-d[[:space:]]+[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/[0-9]+' "$CONF_TARGET" | awk '{print $2}'
  fi
}

collect_outifs(){
  if [ -f "$CONF_TARGET" ]; then
    grep -Eo -- '-o[[:space:]]+[^[:space:]]+' "$CONF_TARGET" | awk '{print $2}'
  fi
}

print_rule_plan(){
  mapfile -t cidrs < <(collect_cidrs | sed '/^$/d' | sort -u)
  mapfile -t outifs < <(collect_outifs | sed '/^$/d' | sort -u)
  if [ "${#cidrs[@]}" -eq 0 ] || [ "${#outifs[@]}" -eq 0 ]; then
    echo "- 未从 $CONF_TARGET 解析到 NAT/FORWARD 规则，跳过规则清理"
    return 0
  fi
  for cidr in "${cidrs[@]}"; do
    for outif in "${outifs[@]}"; do
      [ -n "$cidr" ] && [ -n "$outif" ] || continue
      echo "- nat POSTROUTING -s $cidr -o $outif -j MASQUERADE"
      echo "- FORWARD -i $WG_IF -o $outif -s $cidr -j ACCEPT"
      echo "- FORWARD -i $outif -o $WG_IF -d $cidr -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    done
  done
}

cleanup_rules(){
  if ! command -v iptables >/dev/null 2>&1; then
    warn "未找到 iptables，跳过规则清理"
    return 0
  fi
  mapfile -t cidrs < <(collect_cidrs | sed '/^$/d' | sort -u)
  mapfile -t outifs < <(collect_outifs | sed '/^$/d' | sort -u)
  for cidr in "${cidrs[@]:-}"; do
    for outif in "${outifs[@]:-}"; do
      [ -n "$cidr" ] && [ -n "$outif" ] || continue
      remove_iptables_rule_repeated nat POSTROUTING -s "$cidr" -o "$outif" -j MASQUERADE || true
      remove_iptables_rule_repeated "" FORWARD -i "$WG_IF" -o "$outif" -s "$cidr" -j ACCEPT || true
      remove_iptables_rule_repeated "" FORWARD -i "$outif" -o "$WG_IF" -d "$cidr" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true
      remove_iptables_rule_repeated "" FORWARD -i "$outif" -o "$WG_IF" -d "$cidr" -m state --state RELATED,ESTABLISHED -j ACCEPT || true
    done
  done
  remove_forward_rules_by_scan
  ok "已按 $CONF_TARGET 清理本接口匹配的 NAT/FORWARD 规则"
}

stop_service(){
  systemctl stop "wg-quick@$WG_IF" 2>/dev/null || true
  wg-quick down "$WG_IF" >/dev/null 2>&1 || true
  ip link delete "$WG_IF" 2>/dev/null || true
  systemctl disable "wg-quick@$WG_IF" 2>/dev/null || true
  systemctl reset-failed "wg-quick@$WG_IF" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
}

status_view(){
  echo "========== 当前站点状态 =========="
  echo "状态文件：$STATE_FILE"
  echo "站点：${SITE_NAME:-unknown}"
  echo "模式：${MODE:-unknown}"
  echo "接口：$WG_IF"
  echo "配置：$CONF_TARGET"
  echo "sysctl：$SYSCTL_FILE"
  systemctl status "wg-quick@$WG_IF" --no-pager -l 2>/dev/null || true
  echo
  wg show "$WG_IF" 2>/dev/null || true
}

remove_site(){
  echo "将清理本站点部署包安装的内容："
  echo "- 停止并禁用 wg-quick@$WG_IF"
  echo "- 删除 $CONF_TARGET"
  echo "- 删除 $SYSCTL_FILE"
  echo "- 删除 $STATE_FILE"
  echo "- 删除本部署目录内的渲染配置和安装/卸载日志"
  echo
  echo "将清理的规则为："
  print_rule_plan
  echo
  echo "不会删除其它 WireGuard 接口、其它站点包配置、WebUI 系统包或系统依赖。"
  read -r -p "请输入 DELETE-SITE-WG 确认: " confirm
  [ "$confirm" = "DELETE-SITE-WG" ] || fail "确认不匹配，已取消"
  stop_service
  cleanup_rules
  rm -f "$CONF_TARGET" "$SYSCTL_FILE"
  rm -f "$STATE_FILE" "$SCRIPT_DIR"/*.conf.rendered "$SCRIPT_DIR"/*.userspace.conf "$SCRIPT_DIR/install-site.log" "$SCRIPT_DIR/uninstall-site.log"
  ok "站点部署已清理，系统依赖未卸载。"
}

menu(){
  while true; do
    clear 2>/dev/null || true
    echo "------------------------------------------------------------"
    echo "WireGuard 站点卸载 / 清理"
    echo "当前接口：$WG_IF"
    echo "配置文件：$CONF_TARGET"
    echo "------------------------------------------------------------"
    echo "1) 查看状态"
    echo "2) 停止服务，保留配置"
    echo "3) 清理本站点部署"
    echo "9) 返回上级菜单"
    echo "0) 退出"
    echo "------------------------------------------------------------"
    read -r -p "请选择 [0/1/2/3/9]: " c || true
    case "$c" in
      1) status_view; pause;;
      2) stop_service; ok "已停止 wg-quick@$WG_IF，配置仍保留：$CONF_TARGET"; pause;;
      3) remove_site; pause;;
      9|0) exit 0;;
      *) echo "无效选择，请输入 0、1、2、3 或 9。"; pause;;
    esac
  done
}

main(){
  : > "$LOG_FILE"
  need_root
  load_state
  case "${1:-menu}" in
    --remove|remove) remove_site ;;
    --status|status) status_view ;;
    menu|*) menu ;;
  esac
}

main "$@"
'''

def site_entry_script() -> str:
    return '''#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/bundle"
INSTALL_SCRIPT="$CORE_DIR/install.sh"
UNINSTALL_SCRIPT="$CORE_DIR/uninstall.sh"
STATE_FILE="$SCRIPT_DIR/.site-install-state"
LOG_INSTALL="$SCRIPT_DIR/install-site.log"
LOG_UNINSTALL="$SCRIPT_DIR/uninstall-site.log"

if [ -t 1 ]; then
  C_BLUE="[1;34m"; C_GREEN="[1;32m"; C_YELLOW="[1;33m"; C_RED="[1;31m"; C_RESET="[0m"
else
  C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_RESET=""
fi

line(){ printf '%*s\\n' "${COLUMNS:-72}" '' | tr ' ' '-'; }
ok(){ echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[提示]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*"; }
pause(){ echo; read -r -p "按回车返回菜单..." _ || true; }

need_core(){
  local missing=0
  [ -d "$CORE_DIR" ] || { err "缺少 bundle 目录，站点部署包不完整。"; missing=1; }
  [ -f "$INSTALL_SCRIPT" ] || { err "缺少 bundle/install.sh，站点部署包不完整。"; missing=1; }
  [ -f "$UNINSTALL_SCRIPT" ] || { err "缺少 bundle/uninstall.sh，站点部署包不完整。"; missing=1; }
  [ -f "$CORE_DIR/wg0.conf.template" ] || { err "缺少 bundle/wg0.conf.template，站点部署包不完整。"; missing=1; }
  [ "$missing" = "0" ] || return 1
}
run_install(){ need_core || return 1; bash "$INSTALL_SCRIPT" "$@"; }
run_uninstall(){ need_core || return 1; bash "$UNINSTALL_SCRIPT" "$@"; }
show_help(){
  cat <<'HELP'
用法：
  sudo bash site.sh

说明：
  直接执行会打开站点部署菜单。
  根目录只有 site.sh 一个入口，安装、状态查看、卸载清理都从这里进入。
  高级用法仍兼容：install / status / uninstall。
HELP
}
show_brief_status(){
  if [ -f "$STATE_FILE" ]; then
    echo "状态：检测到已部署记录"
    # shellcheck disable=SC1090
    . "$STATE_FILE" 2>/dev/null || true
    [ -n "${WG_IF:-}" ] && echo "接口：$WG_IF"
    [ -n "${CONF_TARGET:-}" ] && echo "配置：$CONF_TARGET"
  else
    echo "状态：未检测到部署记录"
  fi
}
print_header(){
  clear 2>/dev/null || true
  line
  echo -e "${C_BLUE}WireGuard 站点部署包${C_RESET}"
  echo "目录：$SCRIPT_DIR"
  show_brief_status
  line
}
view_logs(){
  echo "安装日志：$LOG_INSTALL"
  [ -f "$LOG_INSTALL" ] && tail -n 120 "$LOG_INSTALL" || echo "暂无安装日志"
  echo
  echo "卸载日志：$LOG_UNINSTALL"
  [ -f "$LOG_UNINSTALL" ] && tail -n 80 "$LOG_UNINSTALL" || echo "暂无卸载日志"
}
menu(){
  while true; do
    print_header
    echo "1) 部署 / 重新部署站点"
    echo "2) 查看当前部署状态"
    echo "3) 卸载 / 清理本站点部署"
    echo "4) 查看安装/卸载日志"
    echo "0) 退出"
    line
    read -r -p "请选择 [0-4]: " ans || true
    case "$ans" in
      1) run_install deploy || true; pause ;;
      2) run_install status || true; pause ;;
      3) run_uninstall || true; pause ;;
      4) view_logs; pause ;;
      0) echo "已退出。"; exit 0 ;;
      *) warn "无效选择，请输入 0-4。"; pause ;;
    esac
  done
}

case "${1:-}" in
  ""|menu) menu ;;
  install|deploy) shift; run_install deploy "$@" ;;
  status) shift; run_install status "$@" ;;
  uninstall|remove) shift; run_uninstall "$@" ;;
  log|logs) view_logs ;;
  -h|--help|help) show_help ;;
  *) err "未知操作：$1"; show_help; exit 1 ;;
esac
'''

def site_package_readme(site_name: str, lan_cidr: str) -> str:
    return f'''WireGuard 站点部署包

站点名称：{site_name}
站点内网：{lan_cidr}

目录结构：

```text
{site_name}-site-package/
├── site.sh              # 唯一入口脚本
├── README.md            # 使用说明
├── CHECKLIST.md         # 现场检查清单
├── manifest.json        # 包信息
└── bundle/              # 内部核心文件，日常不要手动执行
    ├── install.sh
    ├── uninstall.sh
    ├── .standard-install.sh
    ├── wg0.conf.template
    └── tools/
```

部署步骤：

```bash
tar -xzf {site_name}-site-package.tar.gz
cd {site_name}-site-package
sudo bash site.sh
```

说明：
- 根目录只需要执行 `site.sh`，不要再单独找 `install.sh` 或 `uninstall.sh`。
- `site.sh` 菜单里包含部署、状态查看、卸载/清理、日志查看等入口。
- `bundle/` 是内部核心目录，保存模板、安装实现、卸载实现和用户态兼容工具。
- 支持内核 WireGuard 时，自动使用标准站点部署。
- 不支持内核 WireGuard 但 `/dev/net/tun` 可用时，自动切换到内置用户态兼容部署。
- 部署过程会自动检测真实出口网卡，不需要提前固定 `eth0`、`ens18` 等名称。
- 部署过程会自动选择 WireGuard 接口名：`wg0` 空闲时使用 `wg0`；如果设备已有 `wg0`，会自动改用 `wg-site`、`wgsite`、`wg1` 等可用名称。
- 如需手动指定接口名，可执行：`sudo WG_IF=wg-site bash site.sh install`。
- 同一台服务器可以同时作为 WireGuard 服务端和站点接入端：原服务端继续使用 `wg0`，站点接入端使用自动选择的新接口，互不覆盖。
- 如果检测到系统不支持 WireGuard、没有 systemd、没有 `/dev/net/tun`，会停止安装并提示原因。
- 卸载/清理会读取 `.site-install-state`，只清理本次部署实际使用的接口和配置。

部署完成后可在菜单里查看状态，也可以手动检查：

```bash
cat .site-install-state
systemctl status wg-quick@实际接口名 --no-pager -l
wg show 实际接口名
ip route
```
'''

def site_package_checklist() -> str:
    return '''故障检查清单

1. 服务状态
cat .site-install-state
systemctl status wg-quick@实际接口名 --no-pager -l
journalctl -u wg-quick@实际接口名 -n 80 --no-pager

2. WireGuard 状态
wg show 实际接口名
ip addr show 实际接口名

3. 路由与转发
ip route
sysctl net.ipv4.ip_forward
iptables -t nat -S | grep MASQUERADE

4. 常见问题
- /dev/net/tun 不存在：虚拟机/容器未开启 TUN 支持。
- wg-quick 启动失败：检查实际接口配置语法、公钥、端口、网卡名称。
- 能握手但不通内网：检查现场出口网卡、iptables NAT、现场防火墙、目标设备网关。
- 本机既是服务端又是站点端：确认服务端仍运行在 wg0，站点端运行在 .site-install-state 中记录的独立接口。
- 接口已启动但没有握手：回到 WebUI 服务端确认该站点已点击“应用配置”，并检查 UDP Endpoint 端口是否放行。
'''


def remove_wg_peer_live(public_key: str) -> Dict[str, object]:
    public_key = str(public_key or "").strip()
    if not public_key:
        return {"ok": True, "skipped": True, "message": "empty public key"}
    try:
        p = subprocess.run(["wg", "set", WG_IF, "peer", public_key, "remove"], text=True, capture_output=True, timeout=10)
        return {"ok": p.returncode == 0, "returncode": p.returncode, "stdout": (p.stdout or "").strip(), "stderr": (p.stderr or "").strip()}
    except FileNotFoundError:
        return {"ok": False, "skipped": True, "message": "wg command not found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "skipped": True, "message": "wg peer remove timeout"}
    except Exception as e:
        return {"ok": False, "skipped": True, "message": str(e)}


@app.delete("/api/peers/{peer_type}/{name}")
def api_delete_peer(peer_type: str, name: str, _: str = Depends(require_auth)):
    ensure_env(); validate_existing_name(name)
    if peer_type not in {"user", "site"}:
        raise HTTPException(status_code=400, detail="类型必须是 user 或 site")
    peers = parse_wg_conf()
    peer = next((p for p in peers if p["type"] == peer_type and p["name"] == name), None)
    if not peer:
        raise HTTPException(status_code=404, detail="节点不存在")
    _, deleted_site_lans = split_peer_allowed_ips(peer) if peer_type == "site" else ("", [])
    backup_conf()
    live_remove = remove_wg_peer_live(peer.get("public_key", "")) if peer.get("public_key") else {"ok": True, "skipped": True}
    remove_peer_block(peer_type, name)
    if peer_type == "user":
        (CLIENT_DIR / f"{name}.conf").unlink(missing_ok=True)
        (QR_DIR / f"{name}.png").unlink(missing_ok=True)
        remove_user_owner(name)
        remove_user_site_permission(name)
    else:
        (SITE_DIR / f"{name}-wg0.conf").unlink(missing_ok=True)
        remove_site_remark(name)
        mark_stale_routes(deleted_site_lans, "删除站点后需要应用配置并清理旧路由")
    apply_wg_live_only()
    return {"ok": True, "deleted_site_lans": deleted_site_lans, "live_remove": live_remove, "apply_status": config_apply_status()}


@app.get("/api/conf/{peer_type}/{name}", response_class=PlainTextResponse)
def api_peer_conf(peer_type: str, name: str, _: str = Depends(require_auth)):
    path = conf_path_for(peer_type, name)
    if not path.exists():
        raise HTTPException(status_code=404, detail="配置不存在")
    return path.read_text()


@app.get("/api/conf/{peer_type}/{name}/download")
def api_peer_conf_download(peer_type: str, name: str, _: str = Depends(require_auth)):
    path = conf_path_for(peer_type, name)
    if not path.exists():
        raise HTTPException(status_code=404, detail="配置不存在")
    headers = {"Content-Disposition": f'attachment; filename="{conf_download_name(peer_type, name)}"'}
    return StreamingResponse(path.open("rb"), media_type="application/octet-stream", headers=headers)



@app.get("/api/site-package/{name}/download")
def api_site_package_download(name: str, _: str = Depends(require_auth)):
    validate_existing_name(name)
    peers = parse_wg_conf()
    peer = next((p for p in peers if p.get("type") == "site" and p.get("name") == name), None)
    if not peer:
        raise HTTPException(status_code=404, detail="站点不存在")
    conf_path = SITE_DIR / f"{name}-wg0.conf"
    if not conf_path.exists():
        raise HTTPException(status_code=404, detail="站点配置不存在")
    lan_cidrs = []
    for ip in str(peer.get("allowed_ips", "")).split(","):
        ip = ip.strip()
        if ip and not ip.startswith(WG_NET + ".") and ip != WG_CIDR:
            lan_cidrs.append(ip)
    lan_cidr = format_cidrs(lan_cidrs)
    conf_template = site_conf_template_for_package(conf_path.read_text(errors="ignore"))
    manifest = {
        "type": "site-package",
        "app_version": APP_VERSION,
        "site_name": name,
        "site_lan_cidrs": lan_cidrs,
        "wireguard_interface": "auto",
        "auto_detect_install": True,
        "userspace_fallback": True,
        "entry_script": "site.sh",
        "root_layout": "root keeps site.sh and docs only; core files are stored in bundle/",
        "internal_scripts": ["bundle/install.sh", "bundle/uninstall.sh", "bundle/.standard-install.sh"],
        "interface_conflict_policy": "use wg0 when free, otherwise auto-select wg-site/wgsite/wg1...",
        "userspace_tool": "wireguard-userspace-compat-v0.5.0.tar.gz",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }
    userspace_pkg = INSTALL_DIR / "tools" / "wireguard-userspace-compat-v0.5.0.tar.gz"
    buf = io.BytesIO()
    pkg_dir = f"{name}-site-package"
    import tarfile

    def add_text(tf, rel: str, text: str, mode: int = 0o644):
        data = text.encode("utf-8")
        info = tarfile.TarInfo(f"{pkg_dir}/{rel}")
        info.size = len(data)
        info.mode = mode
        info.mtime = int(datetime.now().timestamp())
        tf.addfile(info, io.BytesIO(data))

    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        add_text(tf, "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        add_text(tf, "site.sh", site_entry_script(), 0o755)
        add_text(tf, "bundle/install.sh", site_install_script(name, lan_cidr), 0o755)
        add_text(tf, "bundle/.standard-install.sh", site_standard_install_script(name, lan_cidr), 0o755)
        add_text(tf, "bundle/uninstall.sh", site_uninstall_script(), 0o755)
        add_text(tf, "bundle/wg0.conf.template", conf_template)
        add_text(tf, "README.md", site_package_readme(name, lan_cidr))
        add_text(tf, "CHECKLIST.md", site_package_checklist())
        if userspace_pkg.exists():
            tf.add(userspace_pkg, arcname=f"{pkg_dir}/bundle/tools/{userspace_pkg.name}")
    buf.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="{name}-site-package.tar.gz"'}
    return StreamingResponse(buf, media_type="application/gzip", headers=headers)

@app.get("/api/qr/user/{name}")
def api_user_qr(name: str, _: str = Depends(require_auth)):
    validate_existing_name(name)
    path = CLIENT_DIR / f"{name}.conf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="配置不存在")
    img = qrcode.make(path.read_text())
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/qr/site/{name}")
def api_site_qr(name: str, _: str = Depends(require_auth)):
    validate_existing_name(name)
    path = SITE_DIR / f"{name}-wg0.conf"
    if not path.exists():
        raise HTTPException(status_code=404, detail="配置不存在")
    img = qrcode.make(path.read_text())
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")



@app.get("/api/users/allowedips-status")
def api_user_allowedips_status(_: str = Depends(require_auth)):
    return allowedips_sync_status()


@app.post("/api/users/{name}/refresh-allowedips")
def api_refresh_user_allowedips(name: str, _: str = Depends(require_auth)):
    """只同步单个用户配置里的 AllowedIPs，适合站点网段变化后按需更新。"""
    validate_existing_name(name)
    ensure_env()
    conf = CLIENT_DIR / f"{name}.conf"
    if not conf.exists():
        raise HTTPException(status_code=404, detail="用户配置不存在")
    allowed = client_allowed_ips_for_user(name)
    backup = backup_clients_dir()
    current = read_client_allowed_ips_file(conf)
    if current is not None and normalize_allowed_ips([current]) == allowed:
        return {"ok": True, "name": name, "changed": False, "allowed_ips": allowed, "backup": backup, "message": "该用户已是最新网段"}
    if not update_client_allowed_ips_file(conf, allowed):
        raise HTTPException(status_code=500, detail="用户配置中未找到 AllowedIPs，无法同步")
    mark_apply_pending("用户 AllowedIPs 已按权限同步，需要应用配置刷新服务端访问控制")
    return {"ok": True, "name": name, "changed": True, "allowed_ips": allowed, "backup": backup, "apply_status": config_apply_status(), "message": "用户网段已同步"}

@app.post("/api/users/refresh-allowedips")
def api_refresh_all_user_allowedips(_: str = Depends(require_auth)):
    ensure_env()
    backup = backup_clients_dir()
    updated = 0
    failed = []
    for conf in sorted(CLIENT_DIR.glob("*.conf")):
        try:
            allowed = client_allowed_ips_for_user(conf.stem)
            current = read_client_allowed_ips_file(conf)
            if current is not None and normalize_allowed_ips([current]) == allowed:
                continue
            if update_client_allowed_ips_file(conf, allowed):
                updated += 1
        except Exception as e:
            failed.append(f"{conf.name}: {e}")
    mark_apply_pending("用户 AllowedIPs 已按权限同步，需要应用配置刷新服务端访问控制")
    status = allowedips_sync_status()
    return {"ok": True, "allowed_ips": "按用户授权生成", "updated": updated, "backup": backup, "failed": failed, "sync": status, "apply_status": config_apply_status()}


@app.get("/api/users/{name}/site-permissions")
def api_get_user_site_permissions(name: str, _: str = Depends(require_auth)):
    validate_existing_name(name)
    if not any(p["type"] == "user" and p["name"] == name for p in parse_wg_conf()):
        raise HTTPException(status_code=404, detail="用户不存在")
    perm = user_permission_for(name)
    sites = []
    remarks = site_remarks_config()
    for site, lans in site_lans_by_name().items():
        sites.append({"name": site, "remark": remarks.get(site, ""), "lan_cidrs": lans})
    sites.sort(key=lambda x: x["name"])
    return {"ok": True, "name": name, "mode": perm.get("mode", "all"), "selected_sites": perm.get("sites", []), "sites": sites, "desired_allowed_ips": client_allowed_ips_for_user(name)}


@app.post("/api/users/{name}/site-permissions")
def api_set_user_site_permissions(name: str, data: UserSitePermissionUpdate, _: str = Depends(require_auth)):
    validate_existing_name(name)
    if not any(p["type"] == "user" and p["name"] == name for p in parse_wg_conf()):
        raise HTTPException(status_code=404, detail="用户不存在")
    result = set_user_site_permission(name, data.mode, data.sites)
    mark_apply_pending("用户访问权限已变更，需要应用配置刷新服务端访问控制")
    desired = client_allowed_ips_for_user(name)
    status = allowedips_sync_status()
    return {"ok": True, **result, "desired_allowed_ips": desired, "sync": status, "apply_status": config_apply_status(), "message": "访问权限已保存，请按权限同步用户网段并应用配置"}




@app.post("/api/permissions/bulk")
def api_bulk_site_permissions(data: BulkSitePermissionUpdate, _: str = Depends(require_auth)):
    result = bulk_update_user_site_permissions(data.users, data.action, data.sites)
    return {**result, "sync": allowedips_sync_status(), "apply_status": config_apply_status(), "message": "批量权限已保存，请按权限同步用户网段并应用配置"}


@app.get("/api/sites/{name}/authorized-users")
def api_get_site_authorized_users(name: str, _: str = Depends(require_auth)):
    site_map = site_lans_by_name()
    if name not in site_map:
        raise HTTPException(status_code=404, detail="站点不存在")
    users = []
    for user in user_names():
        perm = user_permission_for(user)
        allowed = perm.get("mode") == "all" or name in [str(x) for x in perm.get("sites", [])]
        users.append({"name": user, "owner": user_owners_config().get(user, ""), "authorized": bool(allowed), "vpn_ip": user_vpn_ips_by_name().get(user, "")})
    users.sort(key=lambda x: (str(x.get("owner") or ""), str(x.get("name") or "")))
    return {"ok": True, "site": name, "lan_cidrs": site_map.get(name, []), "users": users}


@app.post("/api/sites/{name}/authorized-users")
def api_set_site_authorized_users(name: str, data: SiteAuthorizedUsersUpdate, _: str = Depends(require_auth)):
    result = set_site_authorized_users(name, data.users)
    return {**result, "sync": allowedips_sync_status(), "apply_status": config_apply_status(), "message": "站点授权已保存，请按权限同步用户网段并应用配置"}

@app.get("/api/logs/{kind}", response_class=PlainTextResponse)
def api_logs(kind: str, lines: int = 120, _: str = Depends(require_auth)):
    if kind == "handshake":
        return wireguard_connection_snapshot()
    if kind == "webui":
        return read_journal("wg-webui", lines)
    if kind == "wireguard":
        return read_journal(f"wg-quick@{WG_IF}", lines)
    if kind == "upgrade":
        return tail_file(UPGRADE_ROOT / "latest.log", max_bytes=60000) or "暂无升级日志"
    raise HTTPException(status_code=400, detail="日志类型必须是 handshake、webui、wireguard 或 upgrade")


def validate_reserved_networks(values) -> List[str]:
    try:
        return normalize_ipv4_networks(values)
    except NetworkValidationError as e:
        if e.reason == "ipv4":
            raise HTTPException(status_code=400, detail=f"只支持 IPv4 网段：{e.value}")
        raise HTTPException(status_code=400, detail=f"网段格式错误：{e.value}")


def site_lan_networks_for_reserved_check() -> List[str]:
    out: List[str] = []
    try:
        peers = parse_wg_conf()
    except Exception:
        peers = []
    for p in peers:
        if p.get("type") != "site":
            continue
        for part in str(p.get("allowed_ips", "")).split(","):
            cidr = part.strip()
            if not cidr or cidr == WG_CIDR or cidr.startswith(f"{WG_NET}."):
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
            if net.version == 4 and str(net) not in out:
                out.append(str(net))
    return out


def reserved_network_conflicts(networks: List[str]) -> List[Dict[str, str]]:
    conflicts: List[Dict[str, str]] = []
    site_lans = site_lan_networks_for_reserved_check()
    for n in networks:
        try:
            nn = ipaddress.ip_network(n, strict=False)
        except Exception:
            continue
        for old in site_lans:
            try:
                on = ipaddress.ip_network(old, strict=False)
            except Exception:
                continue
            if nn.overlaps(on):
                conflicts.append({"reserved": str(nn), "site_lan": str(on)})
    return conflicts


def read_platform_config() -> Dict:
    cfg = dict(DEFAULT_CONFIG)
    loaded = _load_json_dict(CONFIG_FILE)
    if loaded:
        cfg.update(loaded)
    return cfg


def write_platform_config(cfg: Dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        CONFIG_FILE.chmod(0o600)
    except Exception:
        pass


@app.get("/api/settings/reserved-networks")
def api_get_reserved_networks(_: str = Depends(require_auth)):
    cfg = read_platform_config()
    networks = validate_reserved_networks(cfg.get("reserved_client_allowed_ips", []))
    cfg["reserved_client_allowed_ips"] = networks
    return {
        "ok": True,
        "config_file": str(CONFIG_FILE),
        "reserved_client_allowed_ips": networks,
        "client_allowed_ips": _csv_or_list(cfg.get("client_allowed_ips", [])),
        "site_lans": site_lan_networks_for_reserved_check(),
        "final_allowed_ips": client_allowed_ips(),
        "sync": allowedips_sync_status(),
        "conflicts": reserved_network_conflicts(networks),
    }


@app.post("/api/settings/reserved-networks")
def api_set_reserved_networks(data: Dict, _: str = Depends(require_auth)):
    cfg = read_platform_config()
    values = data.get("reserved_client_allowed_ips", data.get("networks", []))
    networks = validate_reserved_networks(values)
    cfg["reserved_client_allowed_ips"] = networks
    write_platform_config(cfg)
    mark_apply_pending("本地/保留网段已修改，需要点击应用配置同步用户 AllowedIPs 并刷新配置")
    result = {"ok": True, "config_file": str(CONFIG_FILE), "reserved_client_allowed_ips": networks, "conflicts": reserved_network_conflicts(networks), "final_allowed_ips": client_allowed_ips()}
    # v1.11.46 起页面不再提供“保存并同步用户配置”按钮，统一由顶部“应用配置”执行同步和生效。
    result["sync"] = allowedips_sync_status()
    return result


SETTINGS_CRITICAL_FIELDS = {"server_endpoint", "wg_if", "wg_cidr", "site_ip_start", "site_ip_end", "user_ip_start", "user_ip_end"}
SETTINGS_TEXT_FIELDS = {"server_endpoint", "client_dns", "wg_if", "wg_cidr"}
SETTINGS_LIST_FIELDS = {"client_allowed_ips", "reserved_client_allowed_ips"}
SETTINGS_INT_FIELDS = {
    "site_ip_start": (2, 254),
    "site_ip_end": (2, 254),
    "user_ip_start": (2, 254),
    "user_ip_end": (2, 254),
    "backup_keep": (1, 200),
    "online_threshold_seconds": (30, 86400),
    "login_max_attempts": (1, 100),
    "login_window_seconds": (30, 86400),
    "login_lockout_seconds": (30, 86400),
    "webui_backup_keep": (1, 100),
    "session_ttl_seconds": (300, 2592000),
    "config_backup_keep": (1, 200),
    "log_keep_days": (1, 3650),
    "package_keep": (1, 50),
}
SETTINGS_BOOL_FIELDS = {"cookie_secure"}
SETTINGS_APPLY_FIELDS = {
    "server_endpoint",
    "client_dns",
    "client_allowed_ips",
    "reserved_client_allowed_ips",
    "wg_if",
    "wg_cidr",
    "site_ip_start",
    "site_ip_end",
    "user_ip_start",
    "user_ip_end",
    "backup_keep",
}
SETTINGS_RESTART_FIELDS = set()


def apply_runtime_security_settings(cfg: Dict) -> List[str]:
    global LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS, LOGIN_LOCKOUT_SECONDS, LOGIN_LIMITER, SESSION_TTL_SECONDS, COOKIE_SECURE
    updated = []
    next_login_max = max(1, int(cfg.get("login_max_attempts", LOGIN_MAX_ATTEMPTS)))
    next_login_window = max(30, int(cfg.get("login_window_seconds", LOGIN_WINDOW_SECONDS)))
    next_login_lockout = max(30, int(cfg.get("login_lockout_seconds", LOGIN_LOCKOUT_SECONDS)))
    next_session_ttl = max(300, int(cfg.get("session_ttl_seconds", SESSION_TTL_SECONDS)))
    next_cookie_secure = as_bool(cfg.get("cookie_secure", COOKIE_SECURE), False)
    if (next_login_max, next_login_window, next_login_lockout) != (LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS, LOGIN_LOCKOUT_SECONDS):
        LOGIN_MAX_ATTEMPTS = next_login_max
        LOGIN_WINDOW_SECONDS = next_login_window
        LOGIN_LOCKOUT_SECONDS = next_login_lockout
        LOGIN_LIMITER = LoginAttemptLimiter(
            max_attempts=LOGIN_MAX_ATTEMPTS,
            window_seconds=LOGIN_WINDOW_SECONDS,
            lockout_seconds=LOGIN_LOCKOUT_SECONDS,
        )
        updated.append("login_limiter")
    if next_session_ttl != SESSION_TTL_SECONDS:
        SESSION_TTL_SECONDS = next_session_ttl
        updated.append("session_ttl_seconds")
    if next_cookie_secure != COOKIE_SECURE:
        COOKIE_SECURE = next_cookie_secure
        updated.append("cookie_secure")
    return updated


def _config_for_ui() -> Dict:
    cfg = read_platform_config()
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    merged["config_file"] = str(CONFIG_FILE)
    merged["effective"] = {
        "wg_if": WG_IF,
        "wg_conf": str(WG_CONF),
        "install_dir": str(INSTALL_DIR),
        "backup_root": str(BACKUP_ROOT_WEBUI),
        "release_dir": str(RELEASE_DIR),
        "listen_host": str(_cfg("listen_host", "", "0.0.0.0")),
        "listen_port": int(_cfg("listen_port", "", 8080)),
    }
    return merged


def _validate_int_setting(name: str, value) -> int:
    low, high = SETTINGS_INT_FIELDS[name]
    try:
        num = int(value)
    except Exception:
        raise HTTPException(status_code=400, detail=f"{name} 必须是整数")
    if num < low or num > high:
        raise HTTPException(status_code=400, detail=f"{name} 必须在 {low}-{high} 之间")
    return num


def _validate_text_setting(name: str, value) -> str:
    text = str(value or "").strip()
    if name == "wg_if" and text and not NAME_RE.match(text):
        raise HTTPException(status_code=400, detail="wg_if 只能使用字母、数字、横线、下划线")
    if name == "wg_cidr" and text:
        try:
            ipaddress.ip_network(text, strict=False)
        except Exception:
            raise HTTPException(status_code=400, detail="wg_cidr 不是有效 CIDR")
    if name in {"client_dir", "qr_dir", "site_dir", "install_dir", "upgrade_root", "release_dir", "webui_backup_root"}:
        if text and not text.startswith("/"):
            raise HTTPException(status_code=400, detail=f"{name} 必须是绝对路径")
    return text


@app.get("/api/settings/config")
def api_get_system_config(_: str = Depends(require_auth)):
    return {"ok": True, "config": _config_for_ui()}


@app.post("/api/settings/config")
def api_set_system_config(data: Dict, _: str = Depends(require_auth)):
    cfg = read_platform_config()
    before = dict(cfg)
    changed = []
    requested_critical = SETTINGS_CRITICAL_FIELDS & set(data.keys())
    if requested_critical and not data.get("confirm_critical"):
        raise HTTPException(status_code=400, detail="关键运行配置需要先解锁并确认风险")
    for name in SETTINGS_TEXT_FIELDS:
        if name in data:
            cfg[name] = _validate_text_setting(name, data.get(name))
    for name in SETTINGS_LIST_FIELDS:
        if name in data:
            try:
                cfg[name] = normalize_ipv4_networks(data.get(name, []))
            except NetworkValidationError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
    for name in SETTINGS_INT_FIELDS:
        if name in data:
            cfg[name] = _validate_int_setting(name, data.get(name))
    for name in SETTINGS_BOOL_FIELDS:
        if name in data:
            cfg[name] = as_bool(data.get(name), False)
    if int(cfg.get("site_ip_start", 2)) > int(cfg.get("site_ip_end", 49)):
        raise HTTPException(status_code=400, detail="site_ip_start 不能大于 site_ip_end")
    if int(cfg.get("user_ip_start", 50)) > int(cfg.get("user_ip_end", 200)):
        raise HTTPException(status_code=400, detail="user_ip_start 不能大于 user_ip_end")
    for name, value in cfg.items():
        if before.get(name) != value:
            changed.append(name)
    write_platform_config(cfg)
    runtime_updated = apply_runtime_security_settings(cfg)
    apply_required = bool(set(changed) & SETTINGS_APPLY_FIELDS)
    restart_required = bool(set(changed) & SETTINGS_RESTART_FIELDS)
    skip_apply_pending = bool(data.get("skip_apply_pending") and data.get("confirm_critical"))
    if skip_apply_pending:
        apply_required = False
    if apply_required:
        mark_apply_pending("系统配置中心已保存影响 WireGuard/客户端配置的设置，请点击应用配置刷新")
    return {
        "ok": True,
        "changed": changed,
        "apply_required": apply_required,
        "restart_required": restart_required,
        "runtime_updated": runtime_updated,
        "config": _config_for_ui(),
        "message": "系统配置已保存",
    }


@app.get("/api/security/account")
def api_get_account_security(_: str = Depends(require_auth)):
    return {
        "ok": True,
        "username": _current_webui_user(),
        "default_password_active": _default_password_active(),
        "env_locked": _account_env_locked(),
        "message": "账号已配置",
    }


@app.post("/api/security/account")
def api_update_account_security(data: Dict, _: str = Depends(require_auth)):
    if _account_env_locked():
        raise HTTPException(status_code=400, detail="当前账号由服务环境变量管理，不能在 WebUI 中修改")
    current_password = str(data.get("current_password") or "")
    if not _verify_webui_credentials(_current_webui_user(), current_password):
        raise HTTPException(status_code=400, detail="当前密码不正确")
    username = str(data.get("username") or _current_webui_user()).strip()
    new_password = str(data.get("new_password") or "")
    confirm_password = str(data.get("confirm_password") or "")
    if not re.match(r"^[A-Za-z0-9_.@-]{3,64}$", username):
        raise HTTPException(status_code=400, detail="用户名只能使用 3-64 位字母、数字、点、横线、下划线或 @")
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="新密码至少 8 位")
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="两次输入的新密码不一致")
    cfg = read_platform_config()
    cfg["webui_user"] = username
    cfg["webui_password_hash"] = _hash_password(new_password)
    write_platform_config(cfg)
    return {"ok": True, "username": username, "default_password_active": False, "message": "账号安全配置已更新，请重新登录"}


@app.get("/api/system")
def api_system(_: str = Depends(require_auth)):
    return system_info()


@app.get("/api/ip-pools")
def api_ip_pools(_: str = Depends(require_auth)):
    ensure_env()
    return {
        "wg_net": WG_NET,
        "site": ip_pool_status(SITE_IP_START, SITE_IP_END, "site"),
        "user": ip_pool_status(USER_IP_START, USER_IP_END, "user"),
    }


@app.get("/api/diagnostics")
def api_diagnostics(_: str = Depends(require_auth)):
    return config_audit()


@app.post("/api/routes/sync")
def api_sync_site_routes(_: str = Depends(require_auth)):
    return sync_all_site_lan_routes()


@app.get("/api/config/apply-status")
def api_config_apply_status(_: str = Depends(require_auth)):
    st = config_apply_status()
    st["acl"] = acl_status()
    return st


@app.get("/api/access-control/status")
def api_access_control_status(_: str = Depends(require_auth)):
    return acl_status()


@app.post("/api/config/apply")
def api_config_apply(_: str = Depends(require_auth)):
    result = apply_config_and_routes()
    if not result.get("ok"):
        raise HTTPException(status_code=500, detail=result)
    return result


@app.get("/api/version")
def api_version(_: str = Depends(require_auth)):
    return {"version": APP_VERSION}




def _safe_version_tag() -> str:
    return APP_VERSION[1:] if APP_VERSION.startswith("v") else APP_VERSION


def _find_release_package(kind: str) -> Optional[Path]:
    if kind not in {"app", "full", "bundle", "deploy", "transition"}:
        return None
    patterns = {
        "app": ["wg-webui-app-v*.tar.gz"],
        "full": ["wg-webui-v*.tar.gz", "wg-webui-full-v*.tar.gz", "wg-webui-bundle-v*.tar.gz"],
        "bundle": ["wg-webui-v*.tar.gz", "wg-webui-full-v*.tar.gz", "wg-webui-bundle-v*.tar.gz"],
        "deploy": ["wg-webui-v*.tar.gz", "wg-webui-deploy-v*.tar.gz"],
        "transition": ["wg-webui-v*.tar.gz"],
    }[kind]
    for pat in patterns:
        files = sorted(RELEASE_DIR.glob(pat), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        if files:
            return files[0]
    return None


def _build_current_full_package() -> Path:
    import io
    import tarfile
    ensure_upgrade_env()
    ver = _safe_version_tag()
    out = UPGRADE_PACKAGE_DIR / f"wg-webui-v{ver}-current.tar.gz"
    root_name = f"wg-webui-v{ver}"
    root_files = ["README.md", "VERSION"]
    bundle_files = [
        "VERSION", "PACKAGE_TYPE", "README.md", "SECURITY.md", ".gitignore",
        "wg-webui.sh", "install.sh", "upgrade.sh", "doctor.sh", "uninstall.sh",
        "release/manifest.json",
        "app/app.py", "app/requirements.txt", "app/core/__init__.py", "app/core/networks.py", "app/core/security.py", "app/templates/index.html", "app/static/css/app.css", "app/static/js/app.js",
        "config/config.json.sample",
        "scripts/install.sh", "scripts/upgrade.sh", "scripts/doctor.sh", "scripts/uninstall.sh",
        "tools/repair_allowedips.py", "tools/sync_allowedips.py", "tools/repair_wg_nat.py", "tools/cleanup.py", "tools/release_check.sh", "tools/build_release.py",
        "tools/wireguard-userspace-compat-v0.5.0.tar.gz",
        "tests/test_core_networks.py", "tests/test_core_security.py",
        "docs/INSTALL.md", "docs/CONFIGURATION.md", "docs/OPERATIONS.md",
    ]
    root_entry = r'''#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/bundle" ]; then
  CORE_DIR="$SCRIPT_DIR/bundle"
else
  CORE_DIR="$SCRIPT_DIR"
fi
export WG_WEBUI_SOURCE_DIR="$CORE_DIR"
SERVICE="wg-webui"

if [ -t 1 ]; then
  C_BLUE="\033[1;34m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"; C_RED="\033[1;31m"; C_DIM="\033[2m"; C_RESET="\033[0m"
else
  C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; C_RESET=""
fi

line(){ printf '%*s\n' "${COLUMNS:-72}" '' | tr ' ' '-'; }
ok(){ echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[提示]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[错误]${C_RESET} $*"; }
pause(){ echo; read -r -p "按回车返回菜单..." _ || true; }

need_core(){
  [ -d "$CORE_DIR" ] || { err "未找到核心目录，请在完整发布包根目录执行。"; exit 1; }
  [ -d "$CORE_DIR/scripts" ] || { err "未找到 bundle/scripts 目录，发布包不完整。"; exit 1; }
}
need_root_hint(){
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    warn "当前不是 root，安装、升级、卸载和诊断建议使用：sudo bash wg-webui.sh"
  fi
}
run_script(){
  local script="$1"; shift || true
  need_core
  [ -f "$CORE_DIR/scripts/$script" ] || { err "缺少脚本：bundle/scripts/$script"; return 1; }
  bash "$CORE_DIR/scripts/$script" "$@"
}
run_install(){ run_script install.sh "$@"; }
run_upgrade(){ run_script upgrade.sh "$@"; }
run_doctor(){ run_script doctor.sh "$@"; }
run_uninstall(){ run_script uninstall.sh "$@"; }
service_status(){
  if command -v systemctl >/dev/null 2>&1; then
    systemctl status "$SERVICE" --no-pager || true
  else
    warn "当前系统未检测到 systemctl。"
  fi
}
service_restart(){
  if command -v systemctl >/dev/null 2>&1; then
    need_root_hint
    systemctl restart "$SERVICE"
    ok "WebUI 服务已重启。WireGuard 隧道不会被重启。"
    systemctl status "$SERVICE" --no-pager || true
  else
    warn "当前系统未检测到 systemctl。"
  fi
}
show_logs(){
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u "$SERVICE" -n 120 --no-pager || true
  else
    warn "当前系统未检测到 journalctl。"
  fi
}
select_upgrade_pkg(){
  local pkg="${1:-}"
  if [ -n "$pkg" ]; then echo "$pkg"; return 0; fi
  echo
  echo "请输入升级包完整路径。也可以把升级包放在当前目录后直接输入文件名。"
  echo "输入 0 返回菜单。"
  local candidates=()
  while IFS= read -r f; do candidates+=("$f"); done < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -name 'wg-webui-v*.tar.gz' 2>/dev/null | sort -V || true)
  if [ "${#candidates[@]}" -gt 0 ]; then
    echo
    echo "当前目录检测到升级包："
    local i=1
    for f in "${candidates[@]}"; do echo "  $i) $(basename "$f")"; i=$((i+1)); done
    echo "  0) 返回菜单"
    read -r -p "请选择升级包编号，或直接输入路径: " pkg || true
    if [[ "$pkg" =~ ^[0-9]+$ ]] && [ "$pkg" -ge 1 ] && [ "$pkg" -le "${#candidates[@]}" ]; then
      echo "${candidates[$((pkg-1))]}"; return 0
    fi
  else
    read -r -p "升级包路径: " pkg || true
  fi
  [ "$pkg" = "0" ] && return 1
  [ -n "$pkg" ] || return 1
  if [ -f "$SCRIPT_DIR/$pkg" ]; then pkg="$SCRIPT_DIR/$pkg"; fi
  echo "$pkg"
}
show_help(){
  cat <<'HELP'
用法：
  sudo bash wg-webui.sh

说明：
  直接执行会打开交互菜单。菜单里可以安装、升级、诊断、卸载、查看状态、重启 WebUI 和查看日志。
  也兼容高级参数：install / upgrade <包路径> / doctor / uninstall / status / restart / logs。
HELP
}
print_header(){
  clear 2>/dev/null || true
  line
  echo -e "${C_BLUE}WireGuard WebUI Lite 管理工具${C_RESET}"
  echo "目录：$SCRIPT_DIR"
  echo "核心：$CORE_DIR"
  line
}
menu(){
  need_core
  while true; do
    print_header
    echo "1) 安装 / 首次部署"
    echo "2) 升级 WebUI"
    echo "3) 运行诊断"
    echo "4) 查看 WebUI 服务状态"
    echo "5) 重启 WebUI 服务"
    echo "6) 查看 WebUI 日志"
    echo "7) 卸载 / 清理"
    echo "0) 退出"
    line
    read -r -p "请选择 [0-7]: " ans || true
    case "$ans" in
      1) need_root_hint; run_install; pause ;;
      2)
        need_root_hint
        if pkg="$(select_upgrade_pkg)"; then
          [ -f "$pkg" ] || { err "升级包不存在：$pkg"; pause; continue; }
          run_upgrade "$pkg" || true
        else
          warn "已返回菜单。"
        fi
        pause
        ;;
      3) need_root_hint; run_doctor || true; pause ;;
      4) service_status; pause ;;
      5) service_restart || true; pause ;;
      6) show_logs; pause ;;
      7) need_root_hint; run_uninstall || true; pause ;;
      0) echo "已退出。"; exit 0 ;;
      *) warn "无效选择，请输入 0-7。"; pause ;;
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
  *) err "未知参数：$1"; show_help; exit 1 ;;
esac
'''
    with tarfile.open(out, "w:gz") as tf:
        data = root_entry.encode("utf-8")
        info = tarfile.TarInfo(f"{root_name}/wg-webui.sh")
        info.size = len(data)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(data))
        for rel in root_files:
            p = INSTALL_DIR / rel
            if p.exists() and p.is_file():
                tf.add(p, arcname=f"{root_name}/{rel}")
        manifest = INSTALL_DIR / "release" / "manifest.json"
        if manifest.exists() and manifest.is_file():
            tf.add(manifest, arcname=f"{root_name}/manifest.json")
        for rel in bundle_files:
            p = INSTALL_DIR / rel
            if p.exists() and p.is_file():
                tf.add(p, arcname=f"{root_name}/bundle/{rel}")
    return out

def _uninstall_tool_script() -> str:
    return f'''#!/usr/bin/env bash
set -euo pipefail

VERSION="{APP_VERSION}"
MODE="${{1:-}}"
WEBUI_SERVICE="${{WEBUI_SERVICE:-wg-webui}}"
WEBUI_DIRS=(/opt/wg-webui /etc/wg-webui /var/lib/wg-webui /var/log/wg-webui /opt/wg-webui-upgrade /opt/wg-webui-backups)
WG_DIR="${{WG_DIR:-/etc/wireguard}}"
SYSCTL_GLOB="/etc/sysctl.d/99-wireguard-site*.conf"

need_root() {{
  if [ "${{EUID:-$(id -u)}}" -ne 0 ]; then
    echo "请使用 root 执行：sudo bash site.sh"
    exit 1
  fi
}}

has_cmd() {{ command -v "$1" >/dev/null 2>&1; }}

read_state() {{
  if [ -f /etc/wg-webui/install_state.env ]; then
    # shellcheck disable=SC1091
    . /etc/wg-webui/install_state.env || true
  fi
}}

detect_wg_ifaces() {{
  {{
    if [ -d "$WG_DIR" ]; then
      find "$WG_DIR" -maxdepth 1 -type f -name '*.conf' -printf '%f\\n' 2>/dev/null | sed 's/[.]conf$//'
    fi
    if has_cmd systemctl; then
      systemctl list-units --all 'wg-quick@*.service' --no-legend --no-pager 2>/dev/null | awk '{{print $1}}' | sed -n 's/^wg-quick@\\(.*\\)[.]service$/\\1/p'
      systemctl list-unit-files 'wg-quick@*.service' --no-legend --no-pager 2>/dev/null | awk '{{print $1}}' | sed -n 's/^wg-quick@\\(.*\\)[.]service$/\\1/p'
    fi
    ip -o link show 2>/dev/null | awk -F': ' '/: wg/ {{print $2}}' | cut -d@ -f1
  }} | awk 'NF && !seen[$0]++'
}}

intro() {{
  echo "WireGuard WebUI 卸载清理工具 $VERSION"
  echo "用于清理 WebUI 服务、升级服务、数据目录，以及本机检测到的 WireGuard 配置/接口。"
  echo "说明：系统自带的 wg-quick@.service 模板不会删除。"
}}

print_items() {{
  local title="$1"; shift
  echo "$title"
  if [ "$#" -eq 0 ]; then
    echo "- 未检测到"
  else
    printf -- "- %s\\n" "$@"
  fi
}}

webui_targets() {{
  for d in "${{WEBUI_DIRS[@]}}"; do [ -e "$d" ] && echo "$d"; done
  [ -f "/etc/systemd/system/$WEBUI_SERVICE.service" ] && echo "/etc/systemd/system/$WEBUI_SERVICE.service"
  [ -f /etc/systemd/system/wg-webui-upgrade.service ] && echo "/etc/systemd/system/wg-webui-upgrade.service"
}}

wg_targets() {{
  local iface conf
  for iface in $(detect_wg_ifaces); do
    echo "接口 $iface"
    conf="$WG_DIR/$iface.conf"
    [ -f "$conf" ] && echo "$conf"
  done
  [ -d "$WG_DIR/clients" ] && echo "$WG_DIR/clients"
  [ -d "$WG_DIR/qr" ] && echo "$WG_DIR/qr"
  [ -d "$WG_DIR/site-configs" ] && echo "$WG_DIR/site-configs"
  for f in $SYSCTL_GLOB; do [ -e "$f" ] && echo "$f"; done
}}

show_webui_confirm() {{
  local items=()
  mapfile -t items < <(webui_targets)
  echo
  print_items "将删除 WebUI 相关内容：" "${{items[@]}}"
}}

show_purge_confirm() {{
  local webui_items=() wg_items=()
  mapfile -t webui_items < <(webui_targets)
  mapfile -t wg_items < <(wg_targets)
  echo
  print_items "将删除 WebUI 相关内容：" "${{webui_items[@]}}"
  echo
  print_items "将删除 WireGuard 相关内容：" "${{wg_items[@]}}"
  echo
  echo "同时会清理这些接口匹配到的 NAT/FORWARD/ACL 残留规则。"
}}

remove_iptables_rule_repeated() {{
  local table="$1"; shift
  while iptables ${{table:+-t "$table"}} -D "$@" 2>/dev/null; do :; done
}}

delete_forward_rules_for_iface() {{
  local iface="$1" line hay deleted=0
  has_cmd iptables || return 0
  while IFS= read -r line; do
    hay=" $line "
    [[ "$line" == "-A FORWARD "* ]] || continue
    [[ "$hay" == *" -i $iface "* || "$hay" == *" -o $iface "* ]] || continue
    while true; do
      read -r -a parts <<< "$line"
      parts[0]="-D"
      iptables "${{parts[@]}}" 2>/dev/null || break
      deleted=$((deleted + 1))
    done
  done < <(iptables -S FORWARD 2>/dev/null || true)
  [ "$deleted" -gt 0 ] && echo "已删除 $iface 相关 FORWARD 规则 $deleted 条"
}}

delete_nat_rules_from_conf() {{
  local conf="$1" cidr outif
  has_cmd iptables || return 0
  [ -f "$conf" ] || return 0
  while IFS= read -r cidr; do
    while IFS= read -r outif; do
      [ -n "$cidr" ] && [ -n "$outif" ] || continue
      remove_iptables_rule_repeated nat POSTROUTING -s "$cidr" -o "$outif" -j MASQUERADE || true
    done < <(grep -Eo -- '-o[[:space:]]+[^[:space:];]+' "$conf" 2>/dev/null | awk '{{print $2}}' | awk '!seen[$0]++')
  done < <(grep -Eo -- '-[sd][[:space:]]+[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/[0-9]+' "$conf" 2>/dev/null | awk '{{print $2}}' | awk '!seen[$0]++')
}}

delete_acl_chain() {{
  has_cmd iptables || return 0
  iptables -D FORWARD -j WG_WEBUI_ACL 2>/dev/null || true
  for iface in $(detect_wg_ifaces); do
    iptables -D FORWARD -i "$iface" -j WG_WEBUI_ACL 2>/dev/null || true
  done
  iptables -F WG_WEBUI_ACL 2>/dev/null || true
  iptables -X WG_WEBUI_ACL 2>/dev/null || true
}}

stop_webui() {{
  systemctl stop "$WEBUI_SERVICE" 2>/dev/null || true
  systemctl disable "$WEBUI_SERVICE" 2>/dev/null || true
  systemctl stop wg-webui-upgrade 2>/dev/null || true
  systemctl disable wg-webui-upgrade 2>/dev/null || true
  rm -f "/etc/systemd/system/$WEBUI_SERVICE.service" /etc/systemd/system/wg-webui-upgrade.service
  systemctl reset-failed "$WEBUI_SERVICE" 2>/dev/null || true
  systemctl reset-failed wg-webui-upgrade 2>/dev/null || true
}}

stop_and_remove_iface() {{
  local iface="$1" conf="$WG_DIR/$iface.conf"
  echo "清理 WireGuard 接口：$iface"
  systemctl stop "wg-quick@$iface" 2>/dev/null || true
  wg-quick down "$iface" >/dev/null 2>&1 || true
  ip link delete "$iface" >/dev/null 2>&1 || true
  systemctl disable "wg-quick@$iface" 2>/dev/null || true
  systemctl reset-failed "wg-quick@$iface" 2>/dev/null || true
  delete_nat_rules_from_conf "$conf"
  delete_forward_rules_for_iface "$iface"
  rm -f "$conf"
}}

remove_webui_files() {{
  rm -rf "${{WEBUI_DIRS[@]}}"
  rm -rf "$WG_DIR/clients" "$WG_DIR/qr" "$WG_DIR/site-configs"
  rm -f $SYSCTL_GLOB 2>/dev/null || true
  rmdir "$WG_DIR" 2>/dev/null || true
}}

purge_all() {{
  local ifaces
  mapfile -t ifaces < <(detect_wg_ifaces)
  stop_webui
  delete_acl_chain
  for iface in "${{ifaces[@]}}"; do
    [ -n "$iface" ] && stop_and_remove_iface "$iface"
  done
  remove_webui_files
  systemctl daemon-reload 2>/dev/null || true
  echo
  echo "卸载清理完成。建议执行以下命令复查："
  echo "  systemctl list-units --all 'wg-webui*' 'wg-quick@*' --no-pager"
  echo "  ls -la /etc/wireguard 2>/dev/null || true"
  echo "  iptables -S FORWARD"
  echo "  iptables -t nat -S POSTROUTING"
}}

webui_only() {{
  stop_webui
  rm -rf /opt/wg-webui /etc/wg-webui /var/lib/wg-webui /var/log/wg-webui /opt/wg-webui-upgrade /opt/wg-webui-backups
  systemctl daemon-reload 2>/dev/null || true
  echo "已仅卸载 WebUI，WireGuard 接口和 /etc/wireguard 已保留。"
}}

need_root
read_state
case "$MODE" in
  --webui-only)
    intro
    show_webui_confirm
    read -r -p "确认仅卸载 WebUI，保留 WireGuard？[y/N]: " yn
    case "$yn" in y|Y|yes|YES) webui_only ;; *) echo "已取消"; exit 0 ;; esac
    ;;
  --purge|--all)
    intro
    show_purge_confirm
    read -r -p "确认删除 WebUI 和检测到的 WireGuard 配置/接口？请输入 DELETE-WG-WEBUI: " yn
    [ "$yn" = "DELETE-WG-WEBUI" ] || {{ echo "确认不匹配，已取消"; exit 1; }}
    purge_all
    ;;
  -h|--help)
    echo "用法：sudo ./uninstall.sh [--webui-only|--purge]"
    ;;
  *)
    intro
    echo
    echo "1) 仅卸载 WebUI，保留 WireGuard"
    echo "2) 完全清理 WebUI 和检测到的 WireGuard 配置/接口"
    echo "0) 退出"
    read -r -p "请选择: " ans
    case "$ans" in
      1) show_webui_confirm; read -r -p "确认仅卸载 WebUI，保留 WireGuard？[y/N]: " yn; case "$yn" in y|Y|yes|YES) webui_only ;; *) echo "已取消"; exit 0 ;; esac ;;
      2) show_purge_confirm; read -r -p "请输入 DELETE-WG-WEBUI 确认继续: " yn; [ "$yn" = "DELETE-WG-WEBUI" ] || {{ echo "已取消"; exit 1; }}; purge_all ;;
      0) echo "已退出" ;;
      *) echo "无效选择"; exit 1 ;;
    esac
    ;;
esac
'''


def _build_uninstall_tool_package() -> Path:
    import tarfile
    ensure_upgrade_env()
    ver = _safe_version_tag()
    out = UPGRADE_PACKAGE_DIR / f"wg-webui-uninstaller-v{ver}.tar.gz"
    root_name = f"wg-webui-uninstaller-v{ver}"
    readme = f"""# WireGuard WebUI 一键卸载清理工具

适用场景：原来的 WebUI 部署包或站点部署包目录已经删除，但服务器上仍有 WebUI 服务、WireGuard 接口、配置文件或 systemd 残留。

使用方法：

```bash
tar -xzf wg-webui-uninstaller-v{ver}.tar.gz
cd wg-webui-uninstaller-v{ver}
chmod +x uninstall.sh
sudo ./uninstall.sh
```

脚本会先展示将要清理的 WebUI 服务、升级服务、WireGuard 配置和目录。完全清理需要输入 `DELETE-WG-WEBUI` 二次确认。

如果只想卸载 WebUI、保留 WireGuard：

```bash
sudo ./uninstall.sh --webui-only
```
"""
    script = _uninstall_tool_script()
    with tarfile.open(out, "w:gz") as tf:
        data = script.encode("utf-8")
        info = tarfile.TarInfo(f"{root_name}/uninstall.sh")
        info.size = len(data)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(data))
        data = readme.encode("utf-8")
        info = tarfile.TarInfo(f"{root_name}/README.md")
        info.size = len(data)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(data))
    return out


@app.get("/api/packages/download/{kind}")
def api_package_download(kind: str, _: str = Depends(require_auth)):
    kind = kind.strip().lower()
    # v1.10.18 起不再要求包内自带 release/wg-webui-v*.tar.gz。
    # 如果找不到历史发布包，就按当前安装目录动态生成一个完整包，确保“下载当前完整包”可用。
    if kind == "uninstaller":
        pkg = _build_uninstall_tool_package()
    elif kind in {"full", "bundle", "deploy", "transition", "app"}:
        pkg = _find_release_package(kind)
        if not pkg:
            pkg = _build_current_full_package()
    else:
        raise HTTPException(status_code=400, detail="类型必须是 full 或 uninstaller")
    return FileResponse(str(pkg), filename=pkg.name, media_type="application/gzip")



def _run_cleanup_tool(apply: bool = False) -> Dict:
    tool = INSTALL_DIR / "tools" / "cleanup.py"
    if not tool.exists():
        raise HTTPException(status_code=404, detail="未找到 tools/cleanup.py")
    cmd = [sys.executable, str(tool), "--config", str(CONFIG_FILE), "--json"]
    cmd.append("--apply" if apply else "--dry-run")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"执行 cleanup.py 失败：{e}")
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=(p.stderr or p.stdout or "cleanup.py 执行失败").strip())
    try:
        return json.loads(p.stdout or "{}")
    except Exception:
        return {"raw": p.stdout, "stderr": p.stderr}


@app.get("/api/cleanup/preview")
def api_cleanup_preview(_: str = Depends(require_auth)):
    return _run_cleanup_tool(apply=False)


@app.post("/api/cleanup/apply")
def api_cleanup_apply(_: str = Depends(require_auth)):
    return _run_cleanup_tool(apply=True)



def _safe_backup_name(name: str) -> str:
    name = str(name or "").strip()
    if not re.match(r"^[A-Za-z0-9_.:-]+$", name):
        raise HTTPException(status_code=400, detail="备份名称不合法")
    return name


def _backup_dir_by_name(name: str) -> Path:
    safe = _safe_backup_name(name)
    path = (BACKUP_ROOT_WEBUI / safe).resolve()
    root = BACKUP_ROOT_WEBUI.resolve()
    if root not in path.parents and path != root:
        raise HTTPException(status_code=400, detail="备份路径不合法")
    if not path.exists() or not path.is_dir():
        raise HTTPException(status_code=404, detail="备份不存在")
    return path


def _create_webui_backup(reason: str = "manual") -> Dict[str, object]:
    BACKUP_ROOT_WEBUI.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    target = BACKUP_ROOT_WEBUI / f"{ts}-{reason}"
    source = INSTALL_DIR
    if not source.exists():
        raise HTTPException(status_code=404, detail=f"安装目录不存在：{source}")
    shutil.copytree(source, target / "wg-webui", symlinks=True)
    size = 0
    try:
        size = int(subprocess.check_output(["du", "-sb", str(target)], text=True).split()[0])
    except Exception:
        pass
    return {"ok": True, "name": target.name, "path": str(target), "size": size, "size_human": human_bytes(size)}

@app.get("/api/upgrade/info")
def api_upgrade_info(_: str = Depends(require_auth)):
    ensure_upgrade_env()
    return upgrade_info()



@app.post("/api/backups/create")
def api_backup_create(_: str = Depends(require_auth)):
    return _create_webui_backup("manual")


@app.get("/api/backups/download/{name}")
def api_backup_download(name: str, _: str = Depends(require_auth)):
    backup_dir = _backup_dir_by_name(name)
    out = UPGRADE_PACKAGE_DIR / f"{backup_dir.name}.tar.gz"
    UPGRADE_PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    if out.exists():
        try:
            out.unlink()
        except Exception:
            pass
    import tarfile
    with tarfile.open(out, "w:gz") as tf:
        tf.add(backup_dir, arcname=backup_dir.name)
    return FileResponse(str(out), filename=out.name, media_type="application/gzip")


@app.delete("/api/backups/{name}")
def api_backup_delete(name: str, _: str = Depends(require_auth)):
    backup_dir = _backup_dir_by_name(name)
    shutil.rmtree(backup_dir)
    return {"ok": True, "deleted": backup_dir.name}


@app.post("/api/backups/restore")
def api_backup_restore(req: BackupRestoreRequest, _: str = Depends(require_auth)):
    if req.confirm != "RESTORE-WEBUI":
        raise HTTPException(status_code=400, detail="确认字符串不匹配")
    backup_dir = _backup_dir_by_name(req.name)
    source = backup_dir / "wg-webui"
    if not source.exists() or not source.is_dir():
        # 兼容手工备份：备份目录本身就是 wg-webui 内容
        source = backup_dir
    before = _create_webui_backup("before-restore")
    if not INSTALL_DIR.exists():
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = INSTALL_DIR / item.name
        if item.name in {"data", ".runtime"}:
            continue
        if target.exists():
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
        if item.is_dir() and not item.is_symlink():
            shutil.copytree(item, target, symlinks=True)
        else:
            shutil.copy2(item, target)
    return {"ok": True, "restored": backup_dir.name, "backup_before_restore": before, "message": "WebUI 文件已恢复。请重启 wg-webui 或刷新页面验证。"}


@app.post("/api/doctor/run")
def api_doctor_run(_: str = Depends(require_auth)):
    candidates = [INSTALL_DIR / "doctor.sh", INSTALL_DIR / "scripts" / "doctor.sh"]
    script = next((p for p in candidates if p.exists()), None)
    if not script:
        raise HTTPException(status_code=404, detail="未找到 doctor.sh")
    try:
        script.chmod(script.stat().st_mode | 0o111)
    except Exception:
        pass
    try:
        p = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=180, cwd=str(INSTALL_DIR))
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + "\n" + (e.stderr or "")
        return {"ok": False, "timeout": True, "returncode": 124, "output": out.strip() or "doctor.sh 执行超时"}
    output = ((p.stdout or "") + ("\n" + p.stderr if p.stderr else "")).strip()
    return {"ok": p.returncode == 0, "returncode": p.returncode, "output": output}




def _ops_run_one(title: str, cmd: List[str], timeout: int = 12) -> str:
    """Run a fixed diagnostic command and return readable text; never expose arbitrary command execution."""
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        body = out or err or "无输出"
        status = "OK" if p.returncode == 0 else f"ERR {p.returncode}"
        return f"## {title} [{status}]\n$ {' '.join(cmd)}\n{body}"
    except subprocess.TimeoutExpired:
        return f"## {title} [TIMEOUT]\n$ {' '.join(cmd)}\n命令执行超时"
    except FileNotFoundError:
        return f"## {title} [MISSING]\n$ {' '.join(cmd)}\n命令不存在"
    except Exception as e:
        return f"## {title} [ERROR]\n$ {' '.join(cmd)}\n{e}"


def _ops_quick_commands() -> str:
    svc = f"wg-quick@{WG_IF}"
    return f"""常用快捷指令\n\n# 1) WebUI 服务与日志\nsystemctl status wg-webui --no-pager -l\njournalctl -u wg-webui -n 150 --no-pager\njournalctl -u wg-webui -f\n\n# 2) WireGuard 服务与日志\nsystemctl status {svc} --no-pager -l\njournalctl -u {svc} -n 150 --no-pager\nwg-quick strip {WG_IF}\n\n# 3) WireGuard 运行快照\nwg show {WG_IF}\nwg show {WG_IF} dump\nip -br addr show {WG_IF}\nip route show table main\nip route get 10.8.0.1\n\n# 4) 应用配置 / 热刷新内核 Peer 和 AllowedIPs\nwg syncconf {WG_IF} <(wg-quick strip {WG_IF})\nwg show {WG_IF} allowed-ips\n\n# 5) IPv4 转发、FORWARD 和 NAT\nsysctl net.ipv4.ip_forward\niptables -S FORWARD\niptables -L FORWARD -v -n --line-numbers\niptables -t nat -S POSTROUTING\niptables -t nat -L POSTROUTING -v -n --line-numbers\n\n# 6) WebUI ACL 访问控制链\niptables -S WG_WEBUI_ACL\niptables -L WG_WEBUI_ACL -v -n --line-numbers\niptables -S FORWARD | grep WG_WEBUI_ACL\niptables -L FORWARD -v -n --line-numbers | grep WG_WEBUI_ACL\n\n# 7) 快速排故：用户/站点不通时按顺序看\n# 替换 <客户端VPN_IP>、<现场内网IP>、<出口网卡> 后执行\nping -c 4 <客户端VPN_IP>\nping -c 4 <现场内网IP>\nip route get <现场内网IP>\niptables -C FORWARD -i {WG_IF} -j WG_WEBUI_ACL\niptables -C FORWARD -i {WG_IF} -o <出口网卡> -j ACCEPT\niptables -C FORWARD -o {WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\n# 8) 防火墙/系统基础检查\nss -lunp | grep -E ':<WireGuard端口>|wireguard'\nlsmod | grep wireguard || true\nmodprobe wireguard || true\n\n# 9) 重启管理页面，不影响 WireGuard 隧道\nsystemctl restart wg-webui\n""".strip()


def _ops_validate_network_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="请输入要检测的 IP、域名或 CIDR 网段")
    if len(target) > 253:
        raise HTTPException(status_code=400, detail="目标地址过长")
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            if net.version != 4:
                raise HTTPException(status_code=400, detail="暂只支持 IPv4 网段检测")
            # Keep web scan bounded so the WebUI cannot become a heavy scanner.
            if net.num_addresses > 256:
                raise HTTPException(status_code=400, detail="网段过大，网页检测最多支持 /24 或 256 个地址以内")
            return str(net)
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    # Domain-only fallback. Keep strict to avoid shell metacharacters even though subprocess uses argv list.
    if not re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", target):
        raise HTTPException(status_code=400, detail="目标只能是 IP 地址、CIDR 网段或域名")
    return target


def _ops_parse_ports(raw: str) -> List[int]:
    raw = (raw or "").strip()
    if not raw:
        return []
    ports: List[int] = []
    for part in re.split(r"[,，\s]+", raw):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if not (a.isdigit() and b.isdigit()):
                raise HTTPException(status_code=400, detail="端口范围格式错误，例如 80,443 或 8000-8010")
            start, endp = int(a), int(b)
            if start > endp:
                start, endp = endp, start
            for port in range(start, endp + 1):
                ports.append(port)
        else:
            if not part.isdigit():
                raise HTTPException(status_code=400, detail="端口只能是数字、逗号或短范围")
            ports.append(int(part))
    uniq = []
    for port in ports:
        if port < 1 or port > 65535:
            raise HTTPException(status_code=400, detail="端口范围必须是 1-65535")
        if port not in uniq:
            uniq.append(port)
    if len(uniq) > 40:
        raise HTTPException(status_code=400, detail="一次最多检测 40 个端口，避免网页任务过重")
    return uniq


def _ops_ping_target(target: str, count: int = 1, timeout: int = 1) -> Dict[str, object]:
    """固定参数 Ping。默认 1 包快速检测；普通 Ping 可由前端选择 1/2/4 包。"""
    count = max(1, min(int(count or 1), 4))
    timeout = max(1, min(int(timeout or 1), 3))
    started = time.monotonic()
    try:
        p = subprocess.run(
            ["ping", "-n", "-c", str(count), "-W", str(timeout), target],
            text=True,
            capture_output=True,
            timeout=max(3, count * (timeout + 1) + 1),
        )
        out = ((p.stdout or "") + ("\n" + p.stderr if p.stderr else "")).strip()
        return {"target": target, "ok": p.returncode == 0, "returncode": p.returncode, "output": out, "elapsed_ms": int((time.monotonic() - started) * 1000)}
    except subprocess.TimeoutExpired:
        return {"target": target, "ok": False, "returncode": 124, "output": "ping 执行超时", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    except FileNotFoundError:
        return {"target": target, "ok": False, "returncode": 127, "output": "系统缺少 ping 命令", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    except Exception as e:
        return {"target": target, "ok": False, "returncode": 1, "output": str(e), "elapsed_ms": int((time.monotonic() - started) * 1000)}


def _ops_fast_ping_alive(host: str, timeout: int = 1) -> Dict[str, object]:
    r = _ops_ping_target(host, count=1, timeout=timeout)
    return {"host": host, "alive": bool(r.get("ok")), "elapsed_ms": r.get("elapsed_ms", 0)}


def _ops_tcp_connect(host: str, port: int, timeout: float = 1.0) -> Dict[str, object]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"port": port, "open": True, "message": "open", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    except socket.timeout:
        return {"port": port, "open": False, "message": "timeout", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    except ConnectionRefusedError:
        return {"port": port, "open": False, "message": "refused", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    except OSError as e:
        return {"port": port, "open": False, "message": str(e), "elapsed_ms": int((time.monotonic() - started) * 1000)}


def _ops_format_ping_port_test(target: str, ports: List[int], ping_count: int, do_ping: bool, do_ports: bool) -> str:
    normalized = _ops_validate_network_target(target)
    if "/" in normalized:
        raise HTTPException(status_code=400, detail="Ping / 端口检测只支持单个 IP 或域名；网段请使用“网段快速扫描”。")
    lines: List[str] = []
    lines.append("Ping / 端口检测结果")
    lines.append(f"目标：{normalized}")
    lines.append("")

    if do_ping:
        count = max(1, min(int(ping_count or 1), 4))
        lines.append("## Ping 检测")
        lines.append(f"模式：{count} 包，超时 1 秒/包")
        r = _ops_ping_target(normalized, count=count, timeout=1)
        lines.append("状态：" + ("可达" if r.get("ok") else "不可达"))
        lines.append(f"耗时：{r.get('elapsed_ms', 0)} ms")
        if r.get("output"):
            lines.append(str(r.get("output")))
        lines.append("")

    if do_ports and ports:
        lines.append("## TCP 端口检测")
        for port in ports:
            r = _ops_tcp_connect(normalized, port, timeout=1.0)
            status = "开放" if r.get("open") else "未开放/不可达"
            lines.append(f"{normalized}:{port:<5} {status} ({r.get('message')}, {r.get('elapsed_ms', 0)} ms)")
        lines.append("")

    if not do_ping and not (do_ports and ports):
        lines.append("未选择检测项目。请至少启用 Ping 或填写端口。")
    return "\n".join(lines).strip()


def _ops_format_network_scan(target: str, show_dead: bool = False, workers: int = 64) -> str:
    normalized = _ops_validate_network_target(target)
    if "/" not in normalized:
        raise HTTPException(status_code=400, detail="网段快速扫描请输入 CIDR，例如 192.168.1.0/24。单个地址请使用 Ping / 端口检测。")
    net = ipaddress.ip_network(normalized, strict=False)
    hosts = [str(x) for x in net.hosts()]
    if not hosts and net.num_addresses == 1:
        hosts = [str(net.network_address)]
    if len(hosts) > 256:
        raise HTTPException(status_code=400, detail="网段过大，网页快速扫描最多支持 /24 或 256 个地址以内")

    workers = max(8, min(int(workers or 64), 96, len(hosts) or 1))
    started = time.monotonic()
    results: Dict[str, Dict[str, object]] = {}
    lines: List[str] = []
    lines.append("网段快速扫描结果")
    lines.append(f"目标网段：{normalized}")
    lines.append(f"扫描方式：并发 {workers} 线程，每个地址 1 个 ICMP 包，1 秒超时")
    lines.append("")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(_ops_fast_ping_alive, host, 1): host for host in hosts}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                results[host] = future.result()
            except Exception as e:
                results[host] = {"host": host, "alive": False, "elapsed_ms": 0, "error": str(e)}

    alive = [h for h in hosts if results.get(h, {}).get("alive")]
    elapsed = int((time.monotonic() - started) * 1000)
    lines.append(f"汇总：在线 {len(alive)} / 检测 {len(hosts)}，总耗时 {elapsed} ms")
    lines.append("")
    lines.append("## 在线地址")
    if alive:
        for h in alive:
            lines.append(f"{h:<15} 在线  {results[h].get('elapsed_ms', 0)} ms")
    else:
        lines.append("未发现在线地址")

    if show_dead:
        lines.append("")
        lines.append("## 无响应地址")
        for h in hosts:
            if h not in alive:
                lines.append(f"{h:<15} 无响应")
    return "\n".join(lines).strip()


# Backward-compatible wrapper for older callers.
def _ops_format_network_test(target: str, ports: List[int], do_ping: bool, do_ports: bool) -> str:
    normalized = _ops_validate_network_target(target)
    if "/" in normalized:
        return _ops_format_network_scan(normalized, show_dead=False, workers=64)
    return _ops_format_ping_port_test(normalized, ports, 1, do_ping, do_ports)


@app.get("/api/ops/ping", response_class=PlainTextResponse)
def api_ops_ping(target: str = "", _: str = Depends(require_auth)):
    target = _ops_validate_network_target(target)
    if "/" in target:
        return _ops_format_network_scan(target, show_dead=False, workers=64)
    r = _ops_ping_target(target, count=1, timeout=1)
    status = "OK" if r.get("ok") else f"ERR {r.get('returncode')}"
    return f"## 快速 Ping：{target} [{status}]\n$ ping -n -c 1 -W 1 {target}\n耗时：{r.get('elapsed_ms', 0)} ms\n{r.get('output') or '无输出'}"


@app.post("/api/ops/network-test", response_class=PlainTextResponse)
def api_ops_network_test(data: Dict[str, object], _: str = Depends(require_auth)):
    target = str(data.get("target", "")).strip()
    ports = _ops_parse_ports(str(data.get("ports", "")).strip())
    do_ping = bool(data.get("ping", True))
    do_ports = bool(data.get("ports_enabled", True))
    ping_count = int(data.get("ping_count", 1) or 1)
    return _ops_format_ping_port_test(target, ports, ping_count, do_ping, do_ports)


@app.post("/api/ops/network-scan", response_class=PlainTextResponse)
def api_ops_network_scan(data: Dict[str, object], _: str = Depends(require_auth)):
    target = str(data.get("target", "")).strip()
    show_dead = bool(data.get("show_dead", False))
    workers = int(data.get("workers", 64) or 64)
    return _ops_format_network_scan(target, show_dead=show_dead, workers=workers)


@app.get("/api/ops/{kind}", response_class=PlainTextResponse)
def api_ops(kind: str, _: str = Depends(require_auth)):
    kind = (kind or "").strip().lower()
    if kind == "service":
        parts = [
            _ops_run_one("WebUI 服务状态", ["systemctl", "status", "wg-webui", "--no-pager", "-l"], 15),
            _ops_run_one("WireGuard 服务状态", ["systemctl", "status", f"wg-quick@{WG_IF}", "--no-pager", "-l"], 15),
        ]
        return "\n\n".join(parts)
    if kind == "network":
        parts = [
            _ops_run_one("IPv4 转发", ["sysctl", "net.ipv4.ip_forward"], 8),
            _ops_run_one("路由表", ["ip", "route", "show"], 8),
            _ops_run_one("FORWARD 规则", ["iptables", "-S", "FORWARD"], 10),
            _ops_run_one("FORWARD 命中计数", ["iptables", "-L", "FORWARD", "-v", "-n", "--line-numbers"], 10),
            _ops_run_one("WG_WEBUI_ACL 规则", ["iptables", "-S", "WG_WEBUI_ACL"], 10),
            _ops_run_one("WG_WEBUI_ACL 命中计数", ["iptables", "-L", "WG_WEBUI_ACL", "-v", "-n", "--line-numbers"], 10),
            _ops_run_one("NAT POSTROUTING", ["iptables", "-t", "nat", "-S", "POSTROUTING"], 10),
            _ops_run_one("NAT 命中计数", ["iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n", "--line-numbers"], 10),
        ]
        return "\n\n".join(parts)
    if kind == "commands":
        return _ops_quick_commands()
    raise HTTPException(status_code=400, detail="运维工具类型必须是 service、network、commands 或 ping")


@app.get("/api/upgrade/status")
def api_upgrade_status(_: str = Depends(require_auth)):
    ensure_upgrade_env()
    status_file = UPGRADE_ROOT / "status.json"
    data = {"status": "idle", "message": "暂无升级任务", "log": tail_file(UPGRADE_ROOT / "latest.log", max_bytes=60000)}
    if status_file.exists():
        try:
            import json
            data.update(json.loads(status_file.read_text(errors="ignore")))
        except Exception:
            data["status"] = "unknown"
            data["message"] = "升级状态文件读取失败"
    data["upgrade_running"] = upgrade_info().get("upgrade_running", False)
    return data


@app.post("/api/upgrade/upload")
async def api_upgrade_upload(file: UploadFile = File(...), _: str = Depends(require_auth)):
    ensure_upgrade_env()
    filename = Path(file.filename or "").name
    if not filename.endswith(".tar.gz") or not (filename.startswith("wg-webui-v") or filename.startswith("wg-webui-app-v") or filename.startswith("wg-webui-full-v") or filename.startswith("wg-webui-bundle-v")):
        raise HTTPException(status_code=400, detail="请上传统一完整升级包 wg-webui-v*.tar.gz")
    dest = UPGRADE_PACKAGE_DIR / filename
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    upgrade_pkg = extract_app_package_if_full(dest)
    pre = inspect_upgrade_package(upgrade_pkg)
    if not pre.get("ok"):
        # 上传保留，方便查看预检报告；但不允许开始升级。
        return {"ok": False, "package": str(upgrade_pkg), "stored_package": str(dest), "filename": filename, "precheck": pre}
    return {"ok": True, "package": str(upgrade_pkg), "stored_package": str(dest), "filename": filename, "precheck": pre}


@app.post("/api/upgrade/precheck")
def api_upgrade_precheck(data: Dict[str, str], _: str = Depends(require_auth)):
    ensure_upgrade_env()
    package = Path(data.get("package", "")).resolve()
    pkg_root = UPGRADE_PACKAGE_DIR.resolve()
    if not package.exists() or not str(package).startswith(str(pkg_root)):
        raise HTTPException(status_code=400, detail="升级包不存在或路径非法")
    package = extract_app_package_if_full(package)
    return inspect_upgrade_package(package)


@app.post("/api/upgrade/start")
def api_upgrade_start(data: Dict[str, str], _: str = Depends(require_auth)):
    ensure_upgrade_env()
    package = Path(data.get("package", "")).resolve()
    pkg_root = UPGRADE_PACKAGE_DIR.resolve()
    if not package.exists() or not str(package).startswith(str(pkg_root)):
        raise HTTPException(status_code=400, detail="升级包不存在或路径非法")
    script = UPGRADE_ROOT / "upgrade.sh"

    package = extract_app_package_if_full(package)
    pre = inspect_upgrade_package(package)
    if not pre.get("ok"):
        return JSONResponse({"ok": False, "error": "升级包预检未通过", "precheck": pre}, status_code=400)

    # 关键修复：网页升级时必须优先使用“升级包内的新 upgrade.sh”。
    # 旧逻辑一直调用 /opt/wg-webui-upgrade/upgrade.sh，导致包里的迁移/重启修复根本没有执行。
    try:
        import tarfile
        tmp_upgrade = UPGRADE_ROOT / "upgrade.sh.next"
        tmp_core = UPGRADE_ROOT / "scripts" / "upgrade.sh.next"
        (UPGRADE_ROOT / "scripts").mkdir(parents=True, exist_ok=True)
        with tarfile.open(package, "r:gz") as tf:
            wrapper = None
            core = None
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                name = m.name
                if name.endswith("/bundle/upgrade.sh") or name == "bundle/upgrade.sh":
                    wrapper = m
                elif wrapper is None and (name.endswith("/upgrade.sh") or name == "upgrade.sh") and "/scripts/" not in name:
                    wrapper = m
                if name.endswith("/bundle/scripts/upgrade.sh") or name == "bundle/scripts/upgrade.sh":
                    core = m
                elif core is None and (name.endswith("/scripts/upgrade.sh") or name == "scripts/upgrade.sh"):
                    core = m
            if wrapper is None:
                raise RuntimeError("升级包内未找到 upgrade.sh")
            src = tf.extractfile(wrapper)
            if src is None:
                raise RuntimeError("upgrade.sh 无法读取")
            tmp_upgrade.write_bytes(src.read())
            if core is not None:
                src2 = tf.extractfile(core)
                if src2 is not None:
                    tmp_core.write_bytes(src2.read())
        tmp_upgrade.chmod(0o755)
        shutil.move(str(tmp_upgrade), str(script))
        if tmp_core.exists():
            tmp_core.chmod(0o755)
            shutil.move(str(tmp_core), str(UPGRADE_ROOT / "scripts" / "upgrade.sh"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新升级脚本失败：{e}")

    unit = "wg-webui-upgrade"
    active_unit = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=8)
    if active_unit.returncode == 0 and (active_unit.stdout or "").strip() == "active":
        raise HTTPException(status_code=409, detail="已有升级任务正在运行，请等待完成")
    subprocess.run(["systemctl", "reset-failed", unit], capture_output=True, text=True, timeout=8)

    env_file = UPGRADE_ROOT / "run.env"
    env_file.write_text("\n".join([
        f"PACKAGE={package}",
        f"UPGRADE_SCRIPT={script}",
        f"INSTALL_DIR={INSTALL_DIR}",
        f"BACKUP_ROOT={BACKUP_ROOT_WEBUI}",
        f"UPGRADE_ROOT={UPGRADE_ROOT}",
        f"SERVICE=wg-webui",
        f"BACKUP_KEEP={WEBUI_BACKUP_KEEP}",
        f"WEBUI_BACKUP_KEEP={WEBUI_BACKUP_KEEP}",
        ""
    ]))
    env_file.chmod(0o600)

    # v1.6.1：使用持久化 wg-webui-upgrade.service，而不是 systemd-run 临时任务。
    # 这能避免不同系统上 systemd-run 行为差异，也能确保 WebUI 停止后升级仍继续。
    p = subprocess.run(["systemctl", "start", unit], text=True, capture_output=True, timeout=20)
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail="启动独立升级服务失败：" + ((p.stderr or p.stdout or "").strip()))

    return {"ok": True, "message": "升级任务已交给独立 systemd 服务执行。页面可能会短暂断开，稍后刷新即可。", "unit": unit, "precheck": pre, "output": (p.stdout or p.stderr).strip()}


if __name__ == "__main__":
    # 兼容旧 systemd 仍使用 `python app.py` 的运行方式，避免升级后服务无法自动启动。
    import uvicorn
    host = str(_cfg("listen_host", "", "0.0.0.0"))
    port = int(_cfg("listen_port", "", 8080))
    uvicorn.run("app:app", host=host, port=port)
