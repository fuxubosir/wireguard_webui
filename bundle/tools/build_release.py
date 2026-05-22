#!/usr/bin/env python3
"""Build the clean WireGuard WebUI Lite release package.

The source tree may contain local test output, old release archives, or cache
directories. This builder packages only the files needed by the installer and
the WebUI online-upgrade flow.
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = ROOT / "release"

ROOT_FILES = [
    "README.md",
    "VERSION",
]

BUNDLE_FILES = [
    "VERSION",
    "PACKAGE_TYPE",
    "README.md",
    "SECURITY.md",
    ".gitignore",
    "wg-webui.sh",
    "install.sh",
    "upgrade.sh",
    "doctor.sh",
    "uninstall.sh",
    "release/manifest.json",
    "app/app.py",
    "app/requirements.txt",
    "app/core/__init__.py",
    "app/core/networks.py",
    "app/core/security.py",
    "app/templates/index.html",
    "app/static/css/app.css",
    "app/static/js/app.js",
    "config/config.json.sample",
    "scripts/install.sh",
    "scripts/upgrade.sh",
    "scripts/doctor.sh",
    "scripts/uninstall.sh",
    "tools/repair_allowedips.py",
    "tools/sync_allowedips.py",
    "tools/repair_wg_nat.py",
    "tools/cleanup.py",
    "tools/release_check.sh",
    "tools/build_release.py",
    "tools/wireguard-userspace-compat-v0.5.0.tar.gz",
    "tests/test_core_networks.py",
    "tests/test_core_security.py",
    "docs/INSTALL.md",
    "docs/CONFIGURATION.md",
    "docs/OPERATIONS.md",
]

IGNORE_PATTERNS = shutil.ignore_patterns(
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "venv",
    ".venv",
)


def copy_file(rel: str, dst_root: Path) -> None:
    src = ROOT / rel
    if not src.exists() or not src.is_file():
        return
    dst = dst_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


ROOT_ENTRY = r'''#!/usr/bin/env bash
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

def main() -> None:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    version_num = version[1:] if version.startswith("v") else version
    package_name = f"wg-webui-v{version_num}"
    build_root = RELEASE_DIR / "build" / package_name
    package_path = RELEASE_DIR / f"{package_name}.tar.gz"

    if build_root.exists():
        shutil.rmtree(build_root)
    build_root.mkdir(parents=True)

    root_entry = build_root / "wg-webui.sh"
    root_entry.write_text(ROOT_ENTRY, encoding="utf-8")
    root_entry.chmod(0o755)
    for rel in ROOT_FILES:
        copy_file(rel, build_root)
    copy_file("release/manifest.json", build_root)
    manifest = build_root / "release" / "manifest.json"
    if manifest.exists():
        manifest.replace(build_root / "manifest.json")
        shutil.rmtree(build_root / "release", ignore_errors=True)

    bundle_root = build_root / "bundle"
    bundle_root.mkdir()
    for rel in BUNDLE_FILES:
        copy_file(rel, bundle_root)

    if package_path.exists():
        package_path.unlink()
    with tarfile.open(package_path, "w:gz") as tar:
        tar.add(build_root, arcname=package_name, recursive=True, filter=lambda info: info)

    shutil.rmtree(build_root)
    build_parent = RELEASE_DIR / "build"
    if build_parent.exists() and not any(build_parent.iterdir()):
        build_parent.rmdir()
    print(package_path)


if __name__ == "__main__":
    main()
