"""Read-only admission: proved empty firewall or audited standard UFW paths."""
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
from configuration import SERVICE, UNIT_DIR
from checks import require, HttpsError, acme_ready
from probe_studio_network import LIMIT
import firewall

COMMANDS = {
    "service": ("systemctl", "show", I.SERVICE, "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID", "--property=FragmentPath", "--property=DropInPaths"),
    "caddy": ("systemctl", "show", SERVICE, "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID", "--property=FragmentPath", "--property=DropInPaths"),
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
    if name == "ufw": return firewall.read("ufw")
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
    try:
        records = listener_records(data, expected_port=port)
        data["listener_ownership"] = listener_ownership(data, pid, readlink, expected_port=port)
    except Unsafe:
        raise HttpsError("LISTENER_METADATA_UNCONFIRMED") from None
    require(studio_owns(records, data, pid), "LISTENER_NOT_EXCLUSIVELY_MANAGED")
    return records


def own_unit(raw, expected):
    fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    require(fields.get("FragmentPath") == str(expected) and fields.get("DropInPaths") == "", "UNIT_SHADOW_OR_DROPIN_REQUIRES_REVIEW")


def check_interfaces(status, raw, addresses, report=None):
    """Parse fixed `ip -j address show scope global`; never return raw data.

    iproute2 opens an addr_info object before scope filtering, so filtered
    records can be exactly {}. Only these placeholders are ignored; a nonempty
    incomplete record is invalid. Absence of an address does not prove NAT.
    """
    def fail(result, reason):
        if report: report(result, reason)
        raise HttpsError(result)
    if status != "ok":
        reason = {"missing": "COMMAND_MISSING", "timeout": "COMMAND_TIMEOUT", "output_limit": "OUTPUT_LIMIT"}.get(status, "COMMAND_ERROR") if type(status) is str else "COMMAND_ERROR"
        fail("INTERFACE_READ_FAILED", reason)
    if type(raw) is not str or len(raw) > LIMIT:
        fail("INTERFACE_DATA_INVALID", "RAW_TYPE_OR_SIZE_INVALID")
    def reject_constant(value): raise ValueError()
    try: interfaces = json.loads(raw, parse_constant=reject_constant)
    except (ValueError, RecursionError): fail("INTERFACE_DATA_INVALID", "JSON_INVALID")
    if type(interfaces) is not list: fail("INTERFACE_DATA_INVALID", "ROOT_NOT_ARRAY")
    public = set(); filtered = False
    for interface in interfaces:
        if type(interface) is not dict: fail("INTERFACE_DATA_INVALID", "INTERFACE_NOT_OBJECT")
        if type(interface.get("addr_info")) is not list: fail("INTERFACE_DATA_INVALID", "ADDR_INFO_NOT_ARRAY")
        for info in interface["addr_info"]:
            if type(info) is not dict: fail("INTERFACE_DATA_INVALID", "ADDRESS_NOT_OBJECT")
            if not info:
                filtered = True
                continue
            if "local" not in info: fail("INTERFACE_DATA_INVALID", "LOCAL_MISSING")
            local = info["local"]
            if type(local) is not str or not local or len(local) > 45 or "%" in local:
                fail("INTERFACE_DATA_INVALID", "LOCAL_TYPE_OR_FORMAT_INVALID")
            try: value = ipaddress.ip_address(local)
            except ValueError: fail("INTERFACE_DATA_INVALID", "ADDRESS_INVALID")
            if "family" in info and info["family"] != ("inet" if value.version == 4 else "inet6"):
                fail("INTERFACE_DATA_INVALID", "FAMILY_MISMATCH")
            if "scope" in info and info["scope"] != "global": fail("INTERFACE_DATA_INVALID", "SCOPE_MISMATCH")
            if "prefixlen" in info and (type(info["prefixlen"]) is not int or not 0 <= info["prefixlen"] <= value.max_prefixlen):
                fail("INTERFACE_DATA_INVALID", "PREFIX_INVALID")
            if value.is_global and not value.is_multicast and not getattr(value, "ipv4_mapped", None): public.add(value.compressed)
    # Inputs have already passed public-literal configuration validation.
    try:
        if type(addresses) is not list or not 1 <= len(addresses) <= 2 or any(type(a) is not str for a in addresses): raise ValueError()
        expected = {ipaddress.ip_address(a).compressed for a in addresses}
    except ValueError: fail("INTERFACE_DATA_INVALID", "EXPECTED_ADDRESS_INVALID")
    if not expected <= public: fail("PUBLIC_IP_NOT_ON_INTERFACE", "EXPECTED_ADDRESS_ABSENT")
    if report: report("DIRECT_PUBLIC_IP_PRESENT", "FILTERED_EMPTY_ENTRIES_IGNORED" if filtered else "NONE")
    return public


def snapshot(state, addresses, managed_tls=False, run=read, outbound=acme_ready, allow_stopped=False, progress=None, interface_report=None):
    mark = progress or (lambda phase: None)
    mark("CHECK_PLATFORM")
    I.host_facts()
    mark("CHECK_IDENTITY")
    account = I.managed_account(state)
    require(I.shutil.which("runuser", path="/usr/sbin:/usr/bin:/sbin:/bin"), "RUNUSER_REQUIRED")
    mark("CHECK_STORAGE")
    for parent in (I.Path("/opt"), I.Path("/etc"), I.Path("/var/lib")):
        I.owned_directory(parent)
        require(I.shutil.disk_usage(parent).free >= 256 * 1024**2, "TLS_DISK_HEADROOM_REQUIRED")
    mark("CHECK_ENVIRONMENT")
    require(state["phase"] == "ready" and not state.get("https_pending"), "STUDIO_NOT_READY")
    require(I.private_environment() == I.environment_text(state["port"], state.get("origin"), I.https_settings(state)), "ENVIRONMENT_CHANGED_OUTSIDE_INSTALLER")
    data = {}
    for name in COMMANDS:
        if name == "caddy" and not managed_tls: data[name] = ""; continue
        mark("READ_" + name.upper())
        status, raw = run(name, state["port"])
        if name == "interfaces" and status != "ok": check_interfaces(status, raw, addresses, interface_report)
        require(status == "ok", "PREFLIGHT_READ_INCOMPLETE")
        data[name] = raw
    mark("CHECK_FIREWALL")
    firewall_facts = firewall.inspect(addresses) if ufw_summary("ok", data["ufw"])["active"] == "active" else {"firewall": empty_firewall(data), "firewall_plan": []}
    mark("CHECK_SERVICE")
    service, pid = service_summary("ok", data["service"])
    own_unit(data["service"], I.UNIT)
    require(service["ActiveState"] == "active" and service["SubState"] == "running", "STUDIO_NOT_ACTIVE")
    mark("CHECK_LISTENER")
    records = own_listeners({k: data[k] for k in ("sockets4", "sockets6")}, pid, state["port"])
    if I.https_settings(state): require(all(r["family"] == 4 and r["address"] == "127.0.0.1" for r in records), "HTTPS_BACKEND_NOT_LOOPBACK")
    mark("CHECK_HEALTH")
    I.health(state["port"], timeout=5)
    mark("CHECK_API")
    I.api_health(state["port"])
    mark("CHECK_TLS_LISTENER")
    stopped = False
    if managed_tls:
        service, caddy_pid = service_summary("ok", data["caddy"])
        own_unit(data["caddy"], UNIT_DIR / SERVICE)
        stopped = service["LoadState"] == "loaded" and service["ActiveState"] in ("inactive", "failed") and not data["web4"].strip() and not data["web6"].strip()
        if not (allow_stopped and stopped):
            require(service["ActiveState"] == "active", "MANAGED_CADDY_NOT_ACTIVE")
            for port in (80, 443):
                selected = {f"sockets{f}": select_port(data[f"web{f}"], port) for f in (4, 6)}
                own_listeners(selected, caddy_pid, port)
    else: require(not data["web4"].strip() and not data["web6"].strip(), "FOREIGN_80_443_LISTENER")
    mark("CHECK_INTERFACES")
    public = check_interfaces("ok", data["interfaces"], addresses, interface_report)
    mark("CHECK_MEMORY")
    memory = re.search(r"^MemAvailable:\s+(\d+)", I.Path("/proc/meminfo").read_text(), re.M)
    require(memory and int(memory[1]) >= 512 * 1024, "MEMORY_HEADROOM_BELOW_512_MIB")
    mark("CHECK_ACME")
    outbound()
    mark("CHECK_STABILITY")
    # No counter/queue equality claim; compare stable kernel socket identities.
    for name in ("service", "caddy", "sockets4", "sockets6", "web4", "web6"):
        if name == "caddy" and not managed_tls: continue
        status, fresh = run(name, state["port"])
        require(status == "ok" and fresh == data[name], "PREFLIGHT_STATE_CHANGED")
    return {"arch": I.host_facts()["arch"], **firewall_facts, "public": sorted(public), "port": state["port"], "tls_stopped": stopped}
