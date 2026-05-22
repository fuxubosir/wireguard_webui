#!/usr/bin/env python3
"""WireGuard WebUI backup/log/package cleanup tool.

Safe by default: dry-run only unless --apply is passed.
It protects current config, current WireGuard config, the newest rollback backup,
and keeps the configured number of recent backups/packages.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_CONFIG = Path(os.getenv("WEBUI_CONFIG", "/etc/wg-webui/config.json"))
INSTALL_DIR = Path(os.getenv("WEBUI_INSTALL_DIR", "/opt/wg-webui"))


@dataclass
class Item:
    path: Path
    kind: str
    size: int
    reason: str


def load_config(path: Path) -> dict:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def size_of(path: Path) -> int:
    try:
        if path.is_symlink():
            return 0
        if path.is_file():
            return path.stat().st_size
        total = 0
        for p in path.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    total += p.stat().st_size
            except Exception:
                pass
        return total
    except Exception:
        return 0


def list_children(paths: Iterable[Path], files_glob: str | None = None, dirs_only: bool = False) -> list[Path]:
    out: list[Path] = []
    for base in paths:
        if not base.exists():
            continue
        try:
            entries = list(base.glob(files_glob or "*"))
        except Exception:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if dirs_only and not p.is_dir():
                continue
            if not dirs_only and not (p.is_file() or p.is_dir()):
                continue
            out.append(p)
    return out


def newest_keep(paths: list[Path], keep: int) -> tuple[list[Path], list[Path]]:
    keep = max(0, int(keep))
    paths = sorted(paths, key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return paths[:keep], paths[keep:]


def older_than(paths: list[Path], days: int) -> list[Path]:
    if days <= 0:
        return []
    cutoff = time.time() - days * 86400
    old: list[Path] = []
    for p in paths:
        try:
            if p.stat().st_mtime < cutoff:
                old.append(p)
        except Exception:
            pass
    return old


def collect(config_path: Path) -> tuple[dict, list[Item], list[dict]]:
    cfg = load_config(config_path)
    backup_keep = int(cfg.get("backup_keep", 5) or 5)
    config_backup_keep = int(cfg.get("config_backup_keep", 20) or 20)
    log_keep_days = int(cfg.get("log_keep_days", 30) or 30)
    package_keep = int(cfg.get("package_keep", 3) or 3)

    summary = {
        "backup_keep": backup_keep,
        "config_backup_keep": config_backup_keep,
        "log_keep_days": log_keep_days,
        "package_keep": package_keep,
    }
    items: list[Item] = []
    protected: list[dict] = []

    # Upgrade backups: keep newest N and always keep newest one.
    backup_dirs = list_children([
        Path("/opt/wg-webui-backups"),
        Path("/var/lib/wg-webui/backups"),
    ], dirs_only=True)
    kept, removable = newest_keep(backup_dirs, max(1, backup_keep))
    for p in kept:
        protected.append({"path": str(p), "kind": "upgrade_backup", "reason": "recent rollback backup"})
    for p in removable:
        items.append(Item(p, "upgrade_backup", size_of(p), f"保留最近 {backup_keep} 个升级备份"))

    # Release packages: keep newest N tarballs from common dirs.
    pkg_files = list_children([
        INSTALL_DIR / "release",
        Path("/var/lib/wg-webui/packages"),
        Path("/opt/wg-webui-upgrade/packages"),
    ], files_glob="wg-webui*.tar.gz")
    kept, removable = newest_keep(pkg_files, max(1, package_keep))
    for p in kept:
        protected.append({"path": str(p), "kind": "package", "reason": "recent release package"})
    for p in removable:
        items.append(Item(p, "package", size_of(p), f"保留最近 {package_keep} 个发布包"))

    # Logs: remove files older than N days, skip latest symlink.
    log_files = list_children([
        Path("/var/log/wg-webui"),
        Path("/opt/wg-webui-upgrade/logs"),
    ])
    for p in older_than([x for x in log_files if x.is_file()], log_keep_days):
        items.append(Item(p, "log", size_of(p), f"日志超过 {log_keep_days} 天"))

    # Config backups, but never current config.json or current wg0.conf.
    cfg_backups = list_children([Path("/etc/wg-webui")], files_glob="*.bak*")
    kept, removable = newest_keep(cfg_backups, config_backup_keep)
    for p in kept:
        protected.append({"path": str(p), "kind": "config_backup", "reason": "recent config backup"})
    for p in removable:
        items.append(Item(p, "config_backup", size_of(p), f"保留最近 {config_backup_keep} 个配置备份"))

    wg_backups = []
    for pat in ("*.bak*", "*.conf.bak*", "*.bak.nat.*"):
        wg_backups.extend(list_children([Path("/etc/wireguard")], files_glob=pat))
    # unique
    seen = set(); wg_unique=[]
    for p in wg_backups:
        if p not in seen and p.name != "wg0.conf":
            seen.add(p); wg_unique.append(p)
    kept, removable = newest_keep(wg_unique, config_backup_keep)
    for p in kept:
        protected.append({"path": str(p), "kind": "wireguard_backup", "reason": "recent WireGuard backup"})
    for p in removable:
        items.append(Item(p, "wireguard_backup", size_of(p), f"保留最近 {config_backup_keep} 个 WireGuard 备份"))

    return summary, items, protected


def apply(items: list[Item]) -> list[dict]:
    deleted=[]
    for item in items:
        p = item.path
        ok = False
        err = ""
        try:
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)
            elif p.exists() and not p.is_symlink():
                p.unlink()
            ok = True
        except Exception as e:
            err = str(e)
        deleted.append({"path": str(p), "kind": item.kind, "ok": ok, "error": err})
    return deleted


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.apply and args.dry_run:
        raise SystemExit("--apply and --dry-run cannot be used together")
    summary, items, protected = collect(Path(args.config))
    data = {
        "mode": "apply" if args.apply else "dry-run",
        "policy": summary,
        "count": len(items),
        "bytes": sum(i.size for i in items),
        "items": [{"path": str(i.path), "kind": i.kind, "size": i.size, "reason": i.reason} for i in items],
        "protected": protected[:50],
    }
    if args.apply:
        data["deleted"] = apply(items)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(f"mode={data['mode']} count={data['count']} bytes={data['bytes']}")
        for i in data["items"]:
            print(f"{i['kind']} {i['size']} {i['path']} # {i['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
