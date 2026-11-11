"""HTTPS adapter for the audited UFW engine. No flush/reload/delete or repair.

All raw rules stay in private memory. Only an exact append of TCP/80 or TCP/443
may be performed, under the existing official UFW lock, after a dry proof.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
from types import FunctionType

if "studio_firewall" not in sys.modules:
    spec = importlib.util.spec_from_file_location("studio_firewall", Path(__file__).resolve().parents[1] / "firewall/host.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
import studio_firewall as F
from checks import HttpsError, require

PORTS = (80, 443)
READS = ("ufw", "nft", "ip4", "ip6", "legacy4", "legacy6", "version4", "version6")


def read(name):
    if name == "ufw": return F.read_host(name)  # no CLI lock/capability-test writes
    commands = {key: F.HOST_COMMANDS[key] for key in READS}
    for key in ("ip4", "ip6", "legacy4", "legacy6"):
        commands[key] = (*commands[key], "-M", "/bin/false")
    reader = FunctionType(F.read_command.__code__, {**F.read_command.__globals__, "COMMANDS": commands})
    return reader(name)


@contextlib.contextmanager
def lock():
    fd = os.open("/run/ufw.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "r+b") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o022, "HTTPS_UFW_LOCK_UNSAFE")
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def take(reader=read, files=F.bounded_file):
    data = {}
    for name in READS:
        status, raw = reader(name)
        require(status == "ok", "HTTPS_FIREWALL_READ_INCOMPLETE")
        data[name] = raw
    data["protected"] = {name: files(name).hex() for name in F.PROTECTED}
    for family, name in ((4, "user.rules"), (6, "user6.rules")):
        data["user" + str(family)] = files("/etc/ufw/" + name).decode()
    return data


def fingerprint(data):
    canonical = {key: F.saved_tables(data[key]) for key in ("ip4", "ip6", "legacy4", "legacy6")}
    canonical["nft"] = [F.clean_nft(v) for v in json.loads(data["nft"])["nftables"] if "metainfo" not in v]
    for key in ("protected", "version4", "version6", "ufw"): canonical[key] = data[key]
    for family in (4, 6): canonical["user" + str(family)] = F.persistent_rules(data["user" + str(family)])
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def plan(data, ssh_family, implementation=F.ufw_implementation, operation=F.ufw_operation):
    implementation()
    _, ssh_missing = F.firewall_plan(data, 22, allow_existing=True)
    require(ssh_family not in ssh_missing, "SSH_22_PATH_NOT_CONFIRMED")
    result = {}
    for port in PORTS:
        backend, families = F.firewall_plan(data, port, allow_existing=True)
        if families:
            operation(data, apply=False, port=port, families=families)
            result[port] = families
    return backend, result


def inspect(addresses):
    try:
        with lock():
            data = take()
            _, missing = plan(data, ipaddress.ip_address(addresses[0]).version)
            return {"firewall": fingerprint(data), "firewall_plan": sorted(missing)}
    except HttpsError: raise
    except F.Unsafe as error: raise HttpsError("HTTPS_UFW_" + error.code) from None
    except Exception: raise HttpsError("HTTPS_UFW_AUDIT_UNCONFIRMED") from None


def enable(expected, ports, addresses, take_state=take, guard=lock, implementation=F.ufw_implementation, operation=F.ufw_operation):
    """Called only by confirmed HTTPS apply. No automatic firewall rollback.

    Failure/transport loss after the first write requires a fresh check: a
    persisted allow may remain. Never remove a rule just to hide a partial run.
    """
    started = False
    try:
        require(type(ports) is list and ports and ports == sorted(set(ports)) and all(type(p) is int and p in PORTS for p in ports), "HTTPS_FIREWALL_PLAN_INVALID")
        with guard():
            before = take_state()
            require(fingerprint(before) == expected, "HTTPS_FIREWALL_STATE_CHANGED")
            backend, missing = plan(before, ipaddress.ip_address(addresses[0]).version, implementation, operation)
            require(sorted(missing) == ports, "HTTPS_FIREWALL_STATE_CHANGED")
            # The two plans above are both dry-validated before any write.
            for port in ports:
                require(fingerprint(take_state()) == fingerprint(before), "HTTPS_FIREWALL_STATE_CHANGED")
                families = missing[port]
                started = True
                operation(before, apply=True, port=port, families=families)
                after = take_state()
                require(F.expected_delta(before, after, backend, port, families), "HTTPS_FIREWALL_UNEXPECTED_DELTA")
                for family in (4, 6):
                    if family in families:
                        require(F.persistent_delta(before["user" + str(family)], after["user" + str(family)], family, port), "HTTPS_FIREWALL_UNEXPECTED_DELTA")
                    else:
                        require(F.persistent_rules(before["user" + str(family)]) == F.persistent_rules(after["user" + str(family)]), "HTTPS_FIREWALL_UNEXPECTED_DELTA")
                _, still_missing = plan(after, ipaddress.ip_address(addresses[0]).version, implementation, operation)
                require(port not in still_missing, "HTTPS_FIREWALL_UNEXPECTED_DELTA")
                before = after
            require(not plan(before, ipaddress.ip_address(addresses[0]).version, implementation, operation)[1], "HTTPS_FIREWALL_UNEXPECTED_DELTA")
            return fingerprint(before)
    except BaseException as error:
        if started: raise HttpsError("HTTPS_FIREWALL_CHANGE_UNCONFIRMED_REVIEW_REQUIRED") from None
        if isinstance(error, HttpsError): raise
        if isinstance(error, F.Unsafe): raise HttpsError("HTTPS_UFW_" + error.code) from None
        raise HttpsError("HTTPS_UFW_AUDIT_UNCONFIRMED") from None
