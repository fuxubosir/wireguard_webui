#!/usr/bin/env python3
"""Repair WireGuard NAT/FORWARD rules after the WG address pool changes.

This tool is intentionally conservative:
- derive the true WireGuard CIDR from /etc/wireguard/<wg_if>.conf [Interface] Address
- update /etc/wg-webui/config.json wg_cidr/wg_net
- rewrite old MASQUERADE source CIDRs in wg0.conf PostUp/PostDown
- add precise, idempotent FORWARD rules for wg_if <-> lan_if when NAT is configured
- optionally apply live iptables NAT/FORWARD rules without restarting wg-quick
"""
import argparse
import json
import os
import re
import subprocess
from datetime import datetime
from ipaddress import ip_network
from pathlib import Path

DEFAULT_CONFIG = {"wg_if": "wg0", "wg_cidr": "10.6.0.0/24", "wg_net": "10.6.0"}
NAT_RE = re.compile(r"(-t\s+nat\s+(?:-C|-A|-D)\s+POSTROUTING\s+-s\s+)(\d+\.\d+\.\d+\.\d+/\d+)(\s+-o\s+(\S+)\s+-j\s+MASQUERADE)")
CIDR_RE = re.compile(r"(?P<prefix>\s(?:-s|-d)\s+)(?P<cidr>\d+\.\d+\.\d+\.\d+/\d+)")


def load_json(path: Path) -> dict:
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"WARN: failed to read {path}: {e}")
    return {}


def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except Exception:
        pass


def derive_from_address(addr: str):
    net = ip_network(str(addr).strip(), strict=False)
    if net.version != 4:
        raise ValueError("only IPv4 is supported")
    parts = str(net.network_address).split(".")
    return str(net), ".".join(parts[:3])


def read_interface_address(wg_conf: Path) -> str:
    if not wg_conf.exists():
        return ""
    in_interface = False
    for raw in wg_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_interface = line.lower() == "[interface]"
            if line.lower() == "[peer]":
                break
            continue
        if in_interface and line.lower().startswith("address") and "=" in line:
            return line.split("=", 1)[1].strip().split(",", 1)[0].strip()
    return ""


def run(cmd):
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def desired_forward_lines(wg_if: str, out_if: str, cidr: str):
    return [
        f"PostUp = iptables -C FORWARD -i {wg_if} -o {out_if} -s {cidr} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i {wg_if} -o {out_if} -s {cidr} -j ACCEPT",
        f"PostUp = iptables -C FORWARD -i {out_if} -o {wg_if} -d {cidr} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -i {out_if} -o {wg_if} -d {cidr} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        f"PostDown = iptables -D FORWARD -i {wg_if} -o {out_if} -s {cidr} -j ACCEPT 2>/dev/null || true",
        f"PostDown = iptables -D FORWARD -i {out_if} -o {wg_if} -d {cidr} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true",
    ]


def has_forward_pair(text: str, wg_if: str, out_if: str) -> bool:
    return (
        re.search(rf"FORWARD\s+.*-i\s+{re.escape(wg_if)}\s+.*-o\s+{re.escape(out_if)}", text) is not None
        and re.search(rf"FORWARD\s+.*-i\s+{re.escape(out_if)}\s+.*-o\s+{re.escape(wg_if)}", text) is not None
    )


def add_forward_rules_to_conf(text: str, wg_if: str, cidr: str, out_ifs: set[str]) -> str:
    lines = text.splitlines()
    for out_if in sorted(x for x in out_ifs if x):
        # If matching FORWARD rules already exist, normalize their CIDR and keep them.
        if has_forward_pair("\n".join(lines), wg_if, out_if):
            normalized = []
            for line in lines:
                if "FORWARD" in line and ((f"-i {wg_if}" in line and f"-o {out_if}" in line) or (f"-i {out_if}" in line and f"-o {wg_if}" in line)):
                    line = CIDR_RE.sub(lambda m: m.group('prefix') + cidr, line)
                    line = line.replace("-m state --state RELATED,ESTABLISHED", "-m conntrack --ctstate RELATED,ESTABLISHED")
                normalized.append(line)
            lines = normalized
            continue
        # Insert after last NAT PostDown/PostUp in Interface section, before first [Peer].
        insert_at = None
        for idx, line in enumerate(lines):
            if line.strip().lower() == "[peer]":
                insert_at = idx
                break
        if insert_at is None:
            insert_at = len(lines)
        block = desired_forward_lines(wg_if, out_if, cidr)
        if insert_at > 0 and lines[insert_at - 1].strip():
            block = [""] + block
        lines[insert_at:insert_at] = block + ([""] if insert_at < len(lines) and lines[insert_at:insert_at+1] != [""] else [])
    return "\n".join(lines).rstrip() + "\n"


def ensure_live_rules(new_cidr: str, wg_if: str, out_ifs: set[str], old_cidrs: set[str]):
    if os.geteuid() != 0:
        print("live_rules=skip_not_root")
        return
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    for out_if in sorted(out_ifs):
        if not out_if:
            continue
        rules = [
            (["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", new_cidr, "-o", out_if, "-j", "MASQUERADE"], ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", new_cidr, "-o", out_if, "-j", "MASQUERADE"]),
            (["iptables", "-C", "FORWARD", "-i", wg_if, "-o", out_if, "-s", new_cidr, "-j", "ACCEPT"], ["iptables", "-I", "FORWARD", "1", "-i", wg_if, "-o", out_if, "-s", new_cidr, "-j", "ACCEPT"]),
            (["iptables", "-C", "FORWARD", "-i", out_if, "-o", wg_if, "-d", new_cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], ["iptables", "-I", "FORWARD", "2", "-i", out_if, "-o", wg_if, "-d", new_cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        ]
        for check, add in rules:
            if run(check).returncode != 0:
                r = run(add)
                print(f"live_rule_add {' '.join(add)} rc={r.returncode}")
            else:
                print(f"live_rule_exists {' '.join(check)}")
        for old in sorted(old_cidrs):
            if old == new_cidr:
                continue
            # Remove stale NAT; old FORWARD is best-effort because exact rule variants may differ.
            delete = ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", old, "-o", out_if, "-j", "MASQUERADE"]
            removed = 0
            while run(delete).returncode == 0:
                removed += 1
            if removed:
                print(f"live_nat_removed {old} {out_if} count={removed}")


def repair(config_path: Path, apply_live: bool = False, dry_run: bool = False):
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(load_json(config_path))
    wg_if = str(cfg.get("wg_if") or "wg0")
    wg_conf = Path(os.getenv("WG_CONF") or cfg.get("wg_conf") or f"/etc/wireguard/{wg_if}.conf")
    addr = read_interface_address(wg_conf)
    if not addr:
        print(f"wg_conf_address_missing={wg_conf}")
        return 0
    new_cidr, new_net = derive_from_address(addr)
    print(f"wg_conf={wg_conf}")
    print(f"interface_address={addr}")
    print(f"derived_wg_cidr={new_cidr}")
    print(f"derived_wg_net={new_net}")

    changed_cfg = cfg.get("wg_cidr") != new_cidr or cfg.get("wg_net") != new_net
    if changed_cfg:
        cfg["wg_cidr"] = new_cidr
        cfg["wg_net"] = new_net
        if not dry_run:
            write_json(config_path, cfg)
        print(f"config_updated={changed_cfg} path={config_path}")
    else:
        print("config_updated=False")

    text = wg_conf.read_text(encoding="utf-8", errors="ignore")
    old_cidrs = set()
    out_ifs = set()

    def repl(m):
        old_cidr = m.group(2)
        out_if = m.group(4)
        old_cidrs.add(old_cidr)
        out_ifs.add(out_if)
        return f"{m.group(1)}{new_cidr}{m.group(3)}"

    new_text = NAT_RE.sub(repl, text)
    new_text = add_forward_rules_to_conf(new_text, wg_if, new_cidr, out_ifs)
    changed_conf = new_text != text
    if changed_conf and not dry_run:
        backup = wg_conf.with_name(wg_conf.name + ".bak.nat." + datetime.now().strftime("%Y%m%d-%H%M%S"))
        backup.write_text(text, encoding="utf-8")
        wg_conf.write_text(new_text, encoding="utf-8")
        try:
            wg_conf.chmod(0o600)
        except Exception:
            pass
        print(f"wg_conf_updated=True backup={backup}")
    else:
        print(f"wg_conf_updated={changed_conf}")

    print("nat_out_ifs=" + ",".join(sorted(out_ifs)))
    print("nat_old_cidrs=" + ",".join(sorted(old_cidrs)))
    if apply_live and out_ifs and not dry_run:
        ensure_live_rules(new_cidr, wg_if, out_ifs, old_cidrs)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.getenv("WEBUI_CONFIG", "/etc/wg-webui/config.json"))
    ap.add_argument("--apply-live", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    return repair(Path(args.config), apply_live=args.apply_live, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
