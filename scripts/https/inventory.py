"""Read-only admission: only a proved empty host firewall, never a summary bypass."""
import hashlib
import ipaddress
import json
import os
import re
from types import FunctionType
import studio_installer as I
from probe_studio_network import read_command, service_summary, ufw_summary
from rules import empty_tables, saved_tables, Unsafe
from bindings import listener_records, listener_ownership, studio_owns
from configuration import SERVICE
from checks import require, HttpsError, acme_ready

COMMANDS = {
    "service": ("systemctl", "show", I.SERVICE, "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID"),
    "caddy": ("systemctl", "show", SERVICE, "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID"),
    "sockets4": ("ss", "-H", "-O", "-4", "-lntpe", "sport", "=", ":3000"),
    "sockets6": ("ss", "-H", "-O", "-6", "-lntpe", "sport", "=", ":3000"),
    "web4": ("ss", "-H", "-O", "-4", "-lntpe", "( sport = :80 or sport = :443 )"),
    "web6": ("ss", "-H", "-O", "-6", "-lntpe", "( sport = :80 or sport = :443 )"),
    "interfaces": ("ip", "-j", "address", "show", "scope", "global"),
    "ufw": ("ufw", "status", "verbose"), "nft": ("nft", "-j", "list", "ruleset"),
    "ip4": ("iptables-save", "-M", "/bin/false"), "ip6": ("ip6tables-save", "-M", "/bin/false"),
    "legacy4": ("iptables-legacy-save", "-M", "/bin/false"), "legacy6": ("ip6tables-legacy-save", "-M", "/bin/false"),
}


def read(name, port=3000):
    commands = {**COMMANDS, **{f"sockets{f}": tuple(str(port) if arg == "3000" else ":" + str(port) if arg == ":3000" else arg for arg in COMMANDS[f"sockets{f}"]) for f in (4, 6)}}
    return FunctionType(read_command.__code__, {**read_command.__globals__, "COMMANDS": commands})(name)


def empty_firewall(data):
    try:
        require(ufw_summary("ok", data["ufw"])["active"] == "inactive", "ACTIVE_UFW_REQUIRES_SEPARATE_PLAN")
        canonical = {}
        for key in ("ip4", "ip6", "legacy4", "legacy6"):
            empty_tables(data[key]); canonical[key] = saved_tables(data[key])
        entries = json.loads(data["nft"])["nftables"]
        require(isinstance(entries, list), "FIREWALL_PATH_UNPROVEN")
        clean = []
        for e in entries:
            require(isinstance(e, dict) and len(e) == 1, "FIREWALL_PATH_UNPROVEN")
            key, item = next(iter(e.items()))
            require(key in ("metainfo", "table", "chain"), "ADDITIONAL_FIREWALL_RULES")
            if key == "metainfo": continue
            if key == "chain": require(item.get("policy") == "accept" and item.get("hook") in ("input", "output", "forward", "prerouting", "postrouting", "ingress", "egress"), "FIREWALL_PATH_UNPROVEN")
            clean.append({key: {k: v for k, v in item.items() if k != "handle"}})
        canonical["nft"] = clean
        return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()
    except HttpsError: raise
    except Exception: raise HttpsError("FIREWALL_PATH_UNPROVEN") from None


def select_port(raw, port):
    selected = []
    for line in raw.splitlines():
        parts = line.split()
        require(len(parts) >= 6 and parts[0] == "LISTEN", "LISTENER_UNCONFIRMED")
        value = parts[3].rsplit(":", 1)[-1]
        require(value in ("80", "443"), "LISTENER_UNCONFIRMED")
        if value == str(port): selected.append(line)
    return "\n".join(selected)


def own_listeners(data, pid, port, readlink=os.readlink):
    records = listener_records(data, expected_port=port)
    data["listener_ownership"] = listener_ownership(data, pid, readlink, expected_port=port)
    require(studio_owns(records, data, pid), "LISTENER_NOT_EXCLUSIVELY_MANAGED")
    return records


def snapshot(state, addresses, managed_tls=False, run=read, outbound=acme_ready, allow_stopped=False):
    I.host_facts(); account = I.managed_account(state)
    require(I.shutil.which("runuser", path="/usr/sbin:/usr/bin:/sbin:/bin"), "RUNUSER_REQUIRED")
    for parent in (I.Path("/opt"), I.Path("/etc"), I.Path("/var/lib")):
        I.owned_directory(parent)
        require(I.shutil.disk_usage(parent).free >= 256 * 1024**2, "TLS_DISK_HEADROOM_REQUIRED")
    require(state["phase"] == "ready" and not state.get("https_pending"), "STUDIO_NOT_READY")
    require(I.private_environment() == I.environment_text(state["port"], state.get("origin"), I.https_settings(state)), "ENVIRONMENT_CHANGED_OUTSIDE_INSTALLER")
    data = {}
    for name in COMMANDS:
        if name == "caddy" and not managed_tls: data[name] = ""; continue
        status, raw = run(name, state["port"])
        require(status == "ok", "PREFLIGHT_READ_INCOMPLETE")
        data[name] = raw
    fingerprint = empty_firewall(data)
    service, pid = service_summary("ok", data["service"])
    require(service["ActiveState"] == "active" and service["SubState"] == "running", "STUDIO_NOT_ACTIVE")
    records = own_listeners({k: data[k] for k in ("sockets4", "sockets6")}, pid, state["port"])
    if I.https_settings(state): require(all(r["family"] == 4 and r["address"] == "127.0.0.1" for r in records), "HTTPS_BACKEND_NOT_LOOPBACK")
    I.health(state["port"], timeout=5); I.api_health(state["port"])
    stopped = False
    if managed_tls:
        service, caddy_pid = service_summary("ok", data["caddy"])
        stopped = service["LoadState"] == "loaded" and service["ActiveState"] in ("inactive", "failed") and not data["web4"].strip() and not data["web6"].strip()
        if not (allow_stopped and stopped):
            require(service["ActiveState"] == "active", "MANAGED_CADDY_NOT_ACTIVE")
            for port in (80, 443):
                selected = {f"sockets{f}": select_port(data[f"web{f}"], port) for f in (4, 6)}
                own_listeners(selected, caddy_pid, port)
    else: require(not data["web4"].strip() and not data["web6"].strip(), "FOREIGN_80_443_LISTENER")
    public = set()
    for interface in json.loads(data["interfaces"]):
        for info in interface.get("addr_info", []):
            value = ipaddress.ip_address(info["local"])
            if value.is_global: public.add(value.compressed)
    require(set(addresses) <= public, "DIRECT_PUBLIC_ADDRESSES_REQUIRED_NO_NAT_ADOPTION")
    memory = re.search(r"^MemAvailable:\s+(\d+)", I.Path("/proc/meminfo").read_text(), re.M)
    require(memory and int(memory[1]) >= 512 * 1024, "MEMORY_HEADROOM_BELOW_512_MIB")
    outbound()
    # No counter/queue equality claim; compare stable kernel socket identities.
    for name in ("service", "caddy", "sockets4", "sockets6", "web4", "web6"):
        if name == "caddy" and not managed_tls: continue
        status, fresh = run(name, state["port"])
        require(status == "ok" and fresh == data[name], "PREFLIGHT_STATE_CHANGED")
    return {"arch": I.host_facts()["arch"], "firewall": fingerprint, "public": sorted(public), "port": state["port"], "tls_stopped": stopped}
