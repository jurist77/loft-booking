#!/usr/bin/env python3
"""Fixed read-only inventory. No config contents, journals or direct DB reads.

Executed from SSH stdin together with the existing bounded command reader and
listener identity helpers. All raw values stay in memory on the remote host.
"""
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import stat
from types import FunctionType

if "read_command" not in globals():
    from probe_studio_network import (COMMANDS, read_command, read_health, service_summary,
                                     ufw_summary, deadline, READ_STATES, HEALTH_ERRORS)
if "listener_records" not in globals():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firewall"))
    from bindings import listener_records, listener_ownership, studio_owns, bind_proof

PROPERTIES = ("LoadState", "ActiveState", "SubState", "MainPID", "User", "RootDirectory",
              "WorkingDirectory", "PrivateNetwork", "NetworkNamespacePath", "DropInPaths")
HTTPS_COMMANDS = {
    **COMMANDS,
    "service": ("systemctl", "show", "studio1925.service", *("--property=" + p for p in PROPERTIES)),
    "sockets4": ("ss", "-H", "-O", "-4", "-lntpe", "sport", "=", ":3000"),
    "sockets6": ("ss", "-H", "-O", "-6", "-lntpe", "sport", "=", ":3000"),
    "web4": ("ss", "-H", "-O", "-4", "-lntpe", "( sport = :80 or sport = :443 )"),
    "web6": ("ss", "-H", "-O", "-6", "-lntpe", "( sport = :80 or sport = :443 )"),
    "units": ("systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager", "--type=service,timer"),
    # Query kernel time state, do not D-Bus activate systemd-timedated.
    "clock": ("adjtimex", "--print"),
    # All tables, including NAT; legacy and nf_tables layers can coexist.
    "iptables": ("iptables-save",), "ip6tables": ("ip6tables-save",),
    "legacy4": ("iptables-legacy-save",), "legacy6": ("ip6tables-legacy-save",),
}
UNITS = ("nginx.service", "caddy.service", "apache2.service", "haproxy.service", "traefik.service",
         "certbot.service", "certbot.timer", "snap.certbot.renew.timer", "acme-sh.service", "acme-sh.timer",
         "systemd-resolved.service", "named.service", "unbound.service", "dnsmasq.service", "ddclient.service", "duckdns.timer")
TOOLS = ("nginx", "caddy", "apache2", "haproxy", "traefik", "certbot", "acme.sh", "ddclient", "openssl")
PATHS = {"studio_config": "/etc/studio1925/server.env", "studio_unit": "/etc/systemd/system/studio1925.service",
         "studio_data": "/var/lib/studio1925", "letsencrypt": "/etc/letsencrypt", "caddy_data": "/var/lib/caddy",
         "root_acme": "/root/.acme.sh"}
META = ("private", "root_owned", "unsafe", "symlink", "missing", "unknown")
PROGRAMS = ("nginx", "caddy", "apache2", "haproxy", "traefik", "xray", "x-ui", "3x-ui", "node", "docker-proxy", "systemd")


def read_https(name):
    # The original reader retains bounded output, deadlines, isolated env and
    # cleanup; its command allowlist is replaced only in this local function.
    return FunctionType(read_command.__code__, {**read_command.__globals__, "COMMANDS": HTTPS_COMMANDS})(name)


def fixed_file(name):
    if name != "/usr/lib/os-release": raise ValueError()
    with open(name, "rb") as stream:
        value = stream.read(8193)
    if len(value) > 8192: raise ValueError()
    return value.decode("utf-8")


def metadata(path, inspect=os.lstat):
    # lstat only: never follow a symlink or read a key, config, cert, or DB.
    try:
        info = inspect(path)
        if stat.S_ISLNK(info.st_mode): return "symlink"
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)): return "unsafe"
        if info.st_mode & 0o022: return "unsafe"
        if info.st_mode & 0o077 == 0: return "private"
        return "root_owned" if info.st_uid == 0 else "unsafe"
    except FileNotFoundError: return "missing"
    except OSError: return "unknown"


def studio_permissions(inspect, account):
    try:
        user = account("studio1925")
        if user.pw_uid <= 0 or user.pw_gid <= 0: return False
        expected = (("/etc/studio1925", stat.S_ISDIR, 0, 0o700),
                    ("/etc/studio1925/server.env", stat.S_ISREG, 0, 0o600),
                    ("/var/lib/studio1925", stat.S_ISDIR, user.pw_uid, 0o700))
        for path, kind, owner, mode in expected:
            info = inspect(path)
            if not kind(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != mode: return False
        info = inspect("/etc/systemd/system/studio1925.service")
        return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    except (KeyError, OSError): return False


def web_sockets(state, raw, family):
    result = {"read": state, "listeners": [], "limited": False}
    if state != "ok": return result
    for line in raw.splitlines():
        parts = line.split()
        try:
            if len(parts) < 6 or parts[0] != "LISTEN": raise ValueError()
            address, port = parts[3].rsplit(":", 1)
            port = int(port)
            address = address.strip("[]").split("%", 1)[0]
            if address == "*": address = "0.0.0.0" if family == 4 else "::"
            import ipaddress
            ip = ipaddress.ip_address(address)
            if ip.version != family or port not in (80, 443): raise ValueError()
            # Never emit process names supplied by another application. Only
            # recognized labels; every occupied socket blocks use regardless.
            names = re.findall(r'\("([^"\\]*)",pid=', line)
            programs = sorted({name if name in PROGRAMS else "other" for name in names})
            clean = re.sub(r'"(?:[^"\\]|\\.)*"', "", line)
            options = re.findall(r"(?<!\S)v6only:([01])(?=\s|$)", clean)
            result["listeners"].append({"port": port, "bind": "wildcard" if ip.is_unspecified else "loopback" if ip.is_loopback else "specific",
                "programs": programs[:4] or ["unknown"], "v6only": options[0] if family == 6 and len(options) == 1 else "unknown"})
        except ValueError:
            result["read"] = "error"  # Malformed lines cannot prove a free port.
    result["limited"] = len(result["listeners"]) > 4
    result["listeners"] = result["listeners"][:4]
    return result


def mechanisms(state, raw, available, inspect):
    units = {name: "not_observed" for name in UNITS}
    if state == "ok":
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[0] in units:
                units[fields[0]] = fields[2] if fields[2] in ("active", "inactive", "failed", "activating", "deactivating", "reloading") else "unknown"
    return {"read": state, "units": units, "tools": {name: bool(available(name)) for name in TOOLS},
            "paths": {name: metadata(path, inspect) for name, path in PATHS.items()}, "custom_configuration": "not_inspected"}


def firewall_summary(name, state, raw):
    result = {"read": state, "policy": "unknown", "rules": 0, "indirect": False, "nat_or_other_hooks": False,
              "port_rules": {str(port): {"accept": 0, "drop": 0, "reject": 0, "unknown": 0} for port in (80, 443, 3000)}}
    if state != "ok": return result
    try:
        if name == "ufw":
            summary = ufw_summary(state, raw)
            result["policy"] = summary["default_incoming"] if summary["active"] == "active" else "inactive" if summary["active"] == "inactive" else "unknown"
            for line in raw.splitlines():
                match = re.match(r"^(\d+)(?:/tcp)?(?:\s+\(v6\))?\s+(ALLOW|DENY|REJECT)(?:\s+IN)?\s+", line)
                if match and match[1] in result["port_rules"]:
                    result["port_rules"][match[1]][{"ALLOW": "accept", "DENY": "drop", "REJECT": "reject"}[match[2]]] += 1
                if re.search(r"\b(?:ALLOW|DENY|REJECT|LIMIT)\b", line): result["rules"] += 1
            # Status does not expose before/after rules, NAT, ordering or sets.
            result["indirect"] = summary["active"] != "inactive"
        elif name == "nft":
            entries = json.loads(raw)["nftables"]
            if not isinstance(entries, list): raise ValueError()
            policies = set()
            for entry in entries:
                chain = entry.get("chain", {})
                if chain.get("hook") == "input": policies.add(chain.get("policy", "unknown"))
                elif chain.get("hook"): result["nat_or_other_hooks"] = True
                if any(key in entry for key in ("set", "map", "flowtable")): result["indirect"] = True
                rule = entry.get("rule")
                if rule is None: continue
                result["rules"] += 1
                expressions = rule.get("expr", [])
                if any(any(key in e for key in ("jump", "goto", "vmap", "lookup")) for e in expressions): result["indirect"] = True
                if any(any(key in e for key in ("dnat", "snat", "redirect", "tproxy", "masquerade")) for e in expressions): result["nat_or_other_hooks"] = True
                for e in expressions:
                    m = e.get("match", {})
                    if m.get("left") == {"payload": {"protocol": "tcp", "field": "dport"}} and m.get("op") == "==" and type(m.get("right")) is int and str(m["right"]) in result["port_rules"]:
                        verdict = next((k for k in ("accept", "drop", "reject") if any(k in x for x in expressions)), "unknown")
                        result["port_rules"][str(m["right"])][verdict] += 1
            result["policy"] = next(iter(policies)) if len(policies) == 1 and policies <= {"accept", "drop"} else "unknown"
        else:
            policies = re.findall(r"^:INPUT (ACCEPT|DROP)\s", raw, re.M)
            if len(policies) == 1: result["policy"] = policies[0].lower()
            result["nat_or_other_hooks"] = bool(re.search(r"^\*(?:nat|mangle|raw|security)$", raw, re.M))
            for line in raw.splitlines():
                args = shlex.split(line)
                if args[:1] != ["-A"]: continue
                result["rules"] += 1
                def value(flag):
                    try: return args[args.index(flag) + 1]
                    except (ValueError, IndexError): return ""
                verdict = (value("-j") or value("-g")).lower()
                if verdict not in ("accept", "drop", "reject", "return", "log"): result["indirect"] = True
                if verdict in ("dnat", "snat", "redirect", "tproxy", "masquerade"): result["nat_or_other_hooks"] = True
                if value("-p") == "tcp" and value("--dport") in result["port_rules"]:
                    result["port_rules"][value("--dport")][verdict if verdict in ("accept", "drop", "reject") else "unknown"] += 1
    except (ValueError, KeyError, TypeError, AttributeError): result["read"] = "error"
    return result  # Counts are an inventory, NEVER a packet-path proof.


def collect(run=read_https, health=read_health, inspect=os.lstat, readlink=os.readlink,
            available=lambda name: shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin"), files=fixed_file,
            machine=platform.machine, euid=os.geteuid, account=pwd.getpwnam):
    try: release = files("/usr/lib/os-release")
    except (OSError, ValueError, UnicodeError): release = ""
    clock_state, clock = run("clock")
    sync = re.search(r"^\s*status:\s*([0-9]{1,10})\s*$", clock, re.M) if clock_state == "ok" else None
    host = {"root": euid() == 0, "ubuntu24": bool(re.search(r"^ID=ubuntu$", release, re.M) and re.search(r'^VERSION_ID="24\.04"$', release, re.M)),
            "arch": {"x86_64": "x64", "aarch64": "arm64"}.get(machine(), "unsupported"),
            "clock_sync": ("no" if int(sync[1]) & 64 else "yes") if sync else "unknown"}
    state, raw = run("service"); service, pid = service_summary(state, raw)
    fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    identity = {"sockets4": run("sockets4"), "sockets6": run("sockets6")}
    owned = False; proof = "unconfirmed"
    try:
        if any(s != "ok" for s, _ in identity.values()): raise ValueError()
        data = {k: value[1] for k, value in identity.items()}
        records = listener_records(data); data["listener_ownership"] = listener_ownership(data, pid, readlink)
        owned = studio_owns(records, data, pid)
        if owned: proof = bind_proof(records, 4)
    except Exception: pass  # Unknown listener identity is never a positive proof.
    local = health("127.0.0.1", 3000)
    web = {str(family): web_sockets(*run("web" + str(family)), family) for family in (4, 6)}
    unit_state, units = run("units")
    inventory = mechanisms(unit_state, units, available, inspect)
    fresh_state, fresh_raw = run("service")
    stable = fresh_state == state == "ok" and raw == fresh_raw
    for key, value in identity.items(): stable = (run(key) == value) and stable
    return {"status": "OBSERVED", "host": host, "studio": {"service": service, "listener_owned": owned and stable,
            "snapshot_stable": stable, "bind_proof": proof if stable else "unconfirmed", "local_health": local,
            "permissions_compatible": studio_permissions(inspect, account),
            "isolated_user": fields.get("User") == "studio1925",
            "managed_rootfs": bool(re.fullmatch(r"/opt/studio1925/releases/[A-Za-z0-9_.-]+/root", fields.get("RootDirectory", ""))) and fields.get("WorkingDirectory") == "/app",
            "private_network": fields.get("PrivateNetwork") if fields.get("PrivateNetwork") in ("yes", "no") else "unknown",
            "network_namespace": bool(fields.get("NetworkNamespacePath")), "drop_ins": bool(fields.get("DropInPaths"))},
            "ports": web, "mechanisms": inventory,
            "firewall": {name: firewall_summary(name, *run(name)) for name in ("ufw", "nft", "iptables", "ip6tables", "legacy4", "legacy6")}}


if __name__ == "__main__":
    # Never run automatically on import; normal workflow uses the embedded probe.
    try: print(json.dumps(collect(), sort_keys=True))
    except Exception: print('{"status":"PROBE_UNAVAILABLE"}')
