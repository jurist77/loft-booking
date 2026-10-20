#!/usr/bin/env python3
"""Read-only Linux snapshot. No network, config files, argv, logs or raw errors.

stdout is the anonymized report; the caller may redirect it on their computer.
Only fixed read-only subprocess argument lists below are allowed.
"""
import argparse
import collections
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


COMMANDS = {
    "services": ("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager", "--plain"),
    "installed_services": ("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"),
    "system_state": ("systemctl", "is-system-running"),
    "failed_services": ("systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--no-pager", "--plain"),
    "listeners": ("ss", "-H", "-lntup"),
    "ufw": ("ufw", "status"),
    "nft": ("nft", "list", "tables"),
    "iptables": ("iptables", "-S"),
    "ip6tables": ("ip6tables", "-S"),
    "node": ("node", "--version"),
}


def category(name):
    """Never echo unknown process/unit names (may contain client identifiers)."""
    name = name.lower().removesuffix(".service")
    for label, pattern in (
        ("3x-ui/x-ui", r"(?:3x-ui|3xui|x-ui|xui)(?:[.@_-].*)?"),
        ("xray", r"xray(?:[.@_-].*)?"),
        ("vpn-manager", r"vpn[-_]?manager(?:[.@_-].*)?"),
        ("nginx", r"nginx(?:[.@_-].*)?"),
        ("caddy", r"caddy(?:[.@_-].*)?"),
        ("apache", r"(?:apache2|httpd)(?:[.@_-].*)?"),
        ("haproxy", r"haproxy(?:[.@_-].*)?"),
        ("traefik", r"traefik(?:[.@_-].*)?"),
        ("wireguard", r"(?:wg-quick|wireguard)(?:[.@_-].*)?"),
        ("openvpn", r"openvpn(?:[.@_-].*)?"),
        ("tailscale", r"tailscaled?(?:[.@_-].*)?"),
        ("ipsec", r"(?:strongswan|charon|ipsec)(?:[.@_-].*)?"),
        ("node/next", r"(?:node|next-server|studio1925)(?:[ (@._-].*)?"),
        ("ssh", r"sshd?(?:[.@_-].*)?"),
        ("certificate-tool", r"(?:certbot|acme)(?:[.@_-].*)?"),
        ("system", r"(?:systemd|dbus|cron|rsyslog|journald|kthreadd)(?:[.@_-].*)?"),
    ):
        if re.fullmatch(pattern, name):
            return label
    return "other"


def run_command(key):
    args = COMMANDS[key]
    executable = shutil.which(args[0], path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        return {"status": "missing"}
    try:
        result = subprocess.run(
            [executable, *args[1:]], capture_output=True, text=True, timeout=8,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"},
            check=False,
        )
        # systemctl reports degraded/offline via nonzero exit with valid stdout.
        if result.returncode != 0 and key != "system_state":
            return {"status": "unavailable"}
        return {"status": "ok", "raw": result.stdout}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except (OSError, UnicodeError):
        return {"status": "unavailable"}


def read_text(path):
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


def numbers(raw):
    return {key: int(value) for key, value in re.findall(r"^(\w+):?\s+(\d+)(?:\s|$)", raw or "", re.M)}


def pressure(raw):
    result = {}
    for row in (raw or "").splitlines():
        parts = row.split()
        if not parts or parts[0] not in ("some", "full"):
            continue
        result[parts[0]] = {key: float(value) for key, value in
                            re.findall(r"\b(avg10|avg60|avg300|total)=(\d+(?:\.\d+)?)\b", row)}
    return result or None


def cpu_ticks(raw):
    match = re.search(r"^cpu\s+([\d ]+)$", raw or "", re.M)
    if not match:
        return None
    ticks = [int(x) for x in match[1].split()][:8]  # guest is already in user/nice
    return (sum(ticks), sum(ticks[3:5])) if len(ticks) >= 5 else None


def cpu_usage(before, after):
    if not before or not after or after[0] <= before[0]:
        return None
    return round(100 * (1 - (after[1] - before[1]) / (after[0] - before[0])), 2)


def services(raw):
    counts = collections.Counter()
    for line in (raw or "").splitlines():
        fields = line.split()
        if fields and fields[0].endswith(".service"):
            counts[category(fields[0])] += 1
    return dict(sorted(counts.items()))


def bind_scope(host):
    host = host.strip("[]").split("%", 1)[0]
    if host == "*":
        return "wildcard"
    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified:
            return "wildcard"
        return "loopback" if address.is_loopback else "specific-redacted"
    except ValueError:
        return "unknown"


def listeners(raw):
    result = []
    for line in (raw or "").splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            continue
        host, _, port = fields[4].rpartition(":")
        if not port.isdigit() or not 0 <= int(port) <= 65535:
            continue
        owners = sorted({category(name) for name in re.findall(r'\("([^"\n]+)"', line)})
        result.append({"protocol": fields[0], "port": int(port), "bind": bind_scope(host),
                       "owners": owners or ["unknown-permission-or-kernel"]})
    return sorted(result, key=lambda row: (row["port"], row["protocol"], row["bind"]))


def firewall(key, raw):
    if key == "ufw":
        match = re.search(r"^Status: (active|inactive)$", raw, re.M)
        return {"state": match[1] if match else "unknown"}
    if key == "nft":
        return {"table_count": sum(bool(re.match(r"^table\s+(?:ip|ip6|inet|arp|bridge|netdev)\s", row)) for row in raw.splitlines())}
    # Never output custom chain names, addresses, comments or rules.
    policies = dict(re.findall(r"^-P (INPUT|OUTPUT|FORWARD) (ACCEPT|DROP)$", raw, re.M))
    return {"default_policies": policies, "rule_count": sum(row.startswith("-A ") for row in raw.splitlines())}


def command_report(key, command):
    if command["status"] != "ok":
        return {"status": command["status"]}
    raw = command.get("raw", "")
    value = None
    if key in ("services", "installed_services", "failed_services"):
        value = services(raw)
    elif key == "system_state":
        value = raw.strip() if raw.strip() in ("running", "degraded", "starting", "initializing", "maintenance", "stopping", "offline") else "unknown"
    elif key == "listeners":
        value = listeners(raw)
    elif key == "node":
        match = re.fullmatch(r"v\d+\.\d+\.\d+\s*", raw)
        value = raw.strip() if match else "unknown"
    else:
        value = firewall(key, raw)
    return {"status": "ok", "value": value}


def process_memory(proc):
    rows = []
    unreadable = 0
    try:
        entries = list(proc.iterdir())
    except OSError:
        return {"status": "unavailable"}
    for entry in entries:
        if not entry.name.isdigit():
            continue
        status = read_text(entry / "status")
        comm = read_text(entry / "comm")
        if status is None or comm is None:
            unreadable += 1
            continue
        values = numbers(status)
        if values.get("VmRSS", 0):
            rows.append({"category": category(comm.strip()), "rss_kib": values["VmRSS"],
                         "lifetime_hwm_kib": values.get("VmHWM")})
    rows.sort(key=lambda row: row["rss_kib"], reverse=True)
    return {"status": "ok", "top_rss": rows[:20], "observed_processes": len(rows),
            "vpn_processes": [row for row in rows if row["category"] in
                              ("3x-ui/x-ui", "xray", "vpn-manager", "wireguard", "openvpn", "tailscale", "ipsec")],
            "unreadable_or_exited": unreadable,
            "peak_scope": "VmHWM per process lifetime; not total VPN peak; kernel VPN memory excluded"}


def snapshot(label, proc=Path("/proc"), runner=run_command, pause=time.sleep):
    first = cpu_ticks(read_text(proc / "stat"))
    pause(1)
    second = cpu_ticks(read_text(proc / "stat"))
    mem = numbers(read_text(proc / "meminfo"))
    vm = numbers(read_text(proc / "vmstat"))
    release = read_text(Path("/etc/os-release")) or ""
    version = re.search(r'^VERSION_ID="?(\d+(?:\.\d+)*)"?$', release, re.M)
    distro = re.search(r'^ID="?([a-z0-9_-]+)"?$', release, re.M)
    # ID has a closed list; a manipulated os-release cannot inject arbitrary text.
    distro_id = distro[1] if distro and distro[1] in ("ubuntu", "debian", "fedora", "alpine", "arch", "rocky") else "other-or-unknown"
    architecture = os.uname().machine
    if architecture not in ("x86_64", "aarch64", "armv7l", "riscv64", "s390x", "ppc64le"):
        architecture = "other-or-unknown"
    uptime_raw = read_text(proc / "uptime") or ""
    uptime_match = re.match(r"\d+(?:\.\d+)?", uptime_raw)
    disks = []
    # Fixed path roles; no mount/device names or arbitrary filesystem traversal.
    for path in ("/", "/opt", "/var/lib", "/var/backups"):
        try:
            stat = os.statvfs(path)
            disks.append({"path_role": path, "total_bytes": stat.f_blocks * stat.f_frsize,
                          "available_bytes": stat.f_bavail * stat.f_frsize,
                          "available_inodes": stat.f_favail, "read_only": bool(stat.f_flag & os.ST_RDONLY)})
        except OSError:
            disks.append({"path_role": path, "status": "unavailable"})
    return {
        "schema": 1, "server_label": label,
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "system": {"distribution": distro_id, "version": version[1] if version else None,
                   "architecture": architecture, "logical_cpus": os.cpu_count(),
                   "available_cpu_affinity": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
                   "uptime_seconds": float(uptime_match[0]) if uptime_match else None,
                   "load_1_5_15": list(os.getloadavg()), "cpu_busy_percent_sample_1s": cpu_usage(first, second)},
        "memory_kib": {key: mem.get(key) for key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")},
        "pressure": {key: pressure(read_text(proc / "pressure" / key)) for key in ("cpu", "memory", "io")},
        "vm_counters_since_boot": {key: vm.get(key) for key in ("oom_kill", "pswpin", "pswpout", "pgmajfault")},
        "disks": disks, "process_memory": process_memory(proc),
        "commands": {key: command_report(key, runner(key)) for key in COMMANDS},
        "limitations": ["One snapshot is not a peak-load guarantee.",
                        "No VPN/proxy configs, certificates, journal, argv or environment read.",
                        "Presence is heuristic: renamed services or containers can be missed.",
                        "HTTPS termination, renewal, cloud firewall and VPN peak traffic require owner confirmation.",
                        "Missing/denied tools are unknown, not evidence of absence."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True, choices=("sweden", "finland", "local-validation"))
    args = parser.parse_args()
    try:
        report = snapshot(args.label)
        print(json.dumps(report, indent=2, ensure_ascii=True))
        # Missing optional tools are recorded; essential missing data means incomplete audit.
        return 0 if report["memory_kib"]["MemTotal"] and report["system"]["uptime_seconds"] is not None else 2
    except (OSError, ValueError):
        print('{"error":"AUDIT_UNAVAILABLE","details":"No raw diagnostic output emitted"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
