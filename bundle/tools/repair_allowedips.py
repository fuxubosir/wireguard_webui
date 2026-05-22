#!/usr/bin/env python3
"""Repair existing WireGuard user client AllowedIPs for a running installation.

This script is intentionally independent from FastAPI runtime state. It reads:
- /etc/wg-webui/config.json
- package config.json.sample
- /etc/wireguard/wg0.conf site peers
and then rewrites /etc/wireguard/clients/*.conf.
"""
import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime
from ipaddress import ip_network
from pathlib import Path

DEFAULT_CONFIG = {
    "wg_net": "10.6.0",
    "wg_cidr": "10.6.0.0/24",
    "client_allowed_ips": [],
    "reserved_client_allowed_ips": [],
    "client_dir": "/etc/wireguard/clients",
    "wg_conf": "/etc/wireguard/wg0.conf",
    "backup_keep": 5,
}

def load_json(path: Path):
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"WARN: failed to read json {path}: {e}")
    return {}

def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass

def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value).split(",") if x.strip()]

def norm_cidr(value: str):
    try:
        net = ip_network(str(value).strip(), strict=False)
        if net.version == 4:
            return str(net)
    except Exception:
        return ""
    return ""

def unique_cidrs(items):
    out = []
    seen = set()
    for item in items:
        n = norm_cidr(item)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out

def merge_reserved(config_path: Path, sample_path: Path):
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(load_json(config_path))
    sample = load_json(sample_path)
    reserved = as_list(cfg.get("reserved_client_allowed_ips", []))
    # Merge sample only as deploy-time config source, not as app business logic.
    reserved += as_list(sample.get("reserved_client_allowed_ips", []))
    if os.getenv("RESERVED_CLIENT_ALLOWED_IPS"):
        reserved += as_list(os.getenv("RESERVED_CLIENT_ALLOWED_IPS"))
    if os.getenv("COMPANY_LAN_CIDR"):
        reserved += as_list(os.getenv("COMPANY_LAN_CIDR"))
    normalized = unique_cidrs(reserved)
    if cfg.get("reserved_client_allowed_ips") != normalized:
        cfg["reserved_client_allowed_ips"] = normalized
        write_json(config_path, cfg)
    return cfg

def site_lans_from_wg(wg_conf: Path, wg_net: str, wg_cidr: str):
    if not wg_conf.exists():
        return []
    current_type = ""
    in_peer = False
    lans = []
    for raw in wg_conf.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("# "):
            label = line[2:].strip()
            current_type = "site" if label.startswith("site-") else ("user" if label.startswith("user-") else "")
            in_peer = False
            continue
        if line == "[Peer]":
            in_peer = True
            continue
        if not in_peer or current_type != "site":
            continue
        if line.startswith("AllowedIPs") and "=" in line:
            value = line.split("=", 1)[1]
            for part in value.split(","):
                ip = part.strip()
                if not ip:
                    continue
                if ip == wg_cidr:
                    continue
                # site peer VPN /32 should not be pushed to user clients
                if ip.startswith(f"{wg_net}."):
                    continue
                n = norm_cidr(ip)
                if n:
                    lans.append(n)
    return unique_cidrs(lans)

def read_allowed(path: Path):
    m = re.search(r"(?m)^AllowedIPs\s*=\s*(.*)$", path.read_text(errors="ignore"))
    return m.group(1).strip() if m else None

def update_allowed(path: Path, allowed: str):
    text = path.read_text(errors="ignore")
    new, n = re.subn(r"(?m)^AllowedIPs\s*=.*$", f"AllowedIPs = {allowed}", text, count=1)
    if n == 0:
        return False, "missing AllowedIPs"
    if new != text:
        path.write_text(new)
        return True, "updated"
    return False, "unchanged"

def backup_client_dir(client_dir: Path, keep: int):
    if not client_dir.exists():
        return ""
    ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    dest = client_dir.parent / f"clients.bak.repair.{ts}"
    shutil.copytree(client_dir, dest)
    backups = sorted(client_dir.parent.glob("clients.bak.repair.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[keep:]:
        shutil.rmtree(old, ignore_errors=True)
    return str(dest)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.getenv("WEBUI_CONFIG", "/etc/wg-webui/config.json"))
    ap.add_argument("--sample", default=str(Path(__file__).resolve().parents[1] / "config" / "config.json.sample"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    config_path = Path(args.config)
    sample_path = Path(args.sample)
    cfg = merge_reserved(config_path, sample_path)

    wg_net = str(cfg.get("wg_net") or DEFAULT_CONFIG["wg_net"])
    wg_cidr = str(cfg.get("wg_cidr") or DEFAULT_CONFIG["wg_cidr"])
    wg_conf = Path(os.getenv("WG_CONF") or cfg.get("wg_conf") or f"/etc/wireguard/{cfg.get('wg_if','wg0')}.conf")
    client_dir = Path(str(cfg.get("client_dir") or DEFAULT_CONFIG["client_dir"]))
    keep = int(cfg.get("backup_keep") or DEFAULT_CONFIG["backup_keep"])

    fixed = as_list(cfg.get("reserved_client_allowed_ips", [])) + as_list(cfg.get("client_allowed_ips", []))
    sites = site_lans_from_wg(wg_conf, wg_net, wg_cidr)
    allowed_items = unique_cidrs(fixed + sites)
    allowed = ",".join(allowed_items) or wg_cidr

    print(f"config={config_path}")
    print(f"sample={sample_path}")
    print(f"wg_conf={wg_conf}")
    print(f"client_dir={client_dir}")
    print(f"reserved={','.join(unique_cidrs(as_list(cfg.get('reserved_client_allowed_ips', []))))}")
    print(f"site_lans={','.join(sites)}")
    print(f"final_allowed_ips={allowed}")

    if not client_dir.exists():
        print("client_dir_missing=1")
        return 0
    files = sorted(client_dir.glob("*.conf"))
    if not files:
        print("client_conf_count=0")
        return 0

    changes = []
    for f in files:
        cur = read_allowed(f)
        cur_norm = ",".join(unique_cidrs(as_list(cur))) if cur is not None else ""
        if cur_norm != allowed:
            changes.append(f)
    print(f"client_conf_count={len(files)} need_update={len(changes)}")
    if args.dry_run:
        for f in changes:
            print(f"DRY_UPDATE {f}")
        return 0
    backup = backup_client_dir(client_dir, keep) if changes else ""
    updated = 0
    failed = []
    for f in changes:
        ok, msg = update_allowed(f, allowed)
        if ok:
            updated += 1
            print(f"UPDATED {f}")
        elif msg != "unchanged":
            failed.append(f"{f}:{msg}")
    print(f"updated={updated} backup={backup}")
    if failed:
        print("failed=" + ";".join(failed))
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
