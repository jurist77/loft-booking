"""Read-only listener identity and per-socket dual-stack proof. No global sysctl.

ss -e obtains v6only from INET_DIAG_SKV6ONLY on that socket. Missing data is
unknown, never the machine default. Inodes/cookies/fds stay private to the probe.
"""
import ipaddress
import os
import re

if "Unsafe" not in globals():
    from rules import Unsafe


def listener_records(data):
    """Parse only the fixed, port-filtered ss commands; reject partial records."""
    records = []
    for family in (4, 6):
        for line in data["sockets" + str(family)].splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[0] != "LISTEN": raise Unsafe("READS_INCOMPLETE")
            # Process names are quoted, user-controlled display text. They
            # cannot provide kernel attributes or fake PID/fd ownership tokens.
            metadata = re.sub(r'"(?:[^"\\]|\\.)*"', "", line)
            if '"' in metadata: raise Unsafe("READS_INCOMPLETE")
            try:
                address, port = parts[3].rsplit(":", 1)
                address = address.strip("[]")
                scoped = "%" in address
                address = address.split("%", 1)[0]
                if address == "*": address = "0.0.0.0" if family == 4 else "::"
                ip = ipaddress.ip_address(address)
                if ip.version != family or port != "3000": raise ValueError()
            except ValueError: raise Unsafe("READS_INCOMPLETE") from None
            inodes = re.findall(r"(?<!\S)ino:([0-9]+)(?=\s|$)", metadata)
            cookies = re.findall(r"(?<!\S)sk:([0-9a-fA-F]+)(?=\s|$)", metadata)
            options = re.findall(r"(?<!\S)v6only:([^\s]+)", metadata)
            if len(inodes) != 1 or len(cookies) != 1 or len(inodes[0]) > 20 or len(cookies[0]) > 16 or not 0 < int(inodes[0]) < 2**64 or not int(cookies[0], 16): raise Unsafe("READS_INCOMPLETE")
            if len(options) > 1 or (options and (family != 6 or options[0] not in ("0", "1"))): raise Unsafe("READS_INCOMPLETE")
            owners = re.findall(r"\bpid=([0-9]+),fd=([0-9]+)\b", metadata)
            pids = re.findall(r"\bpid=([0-9]+)\b", metadata)
            if len(owners) > 16 or any(len(pid) > 10 or len(fd) > 7 for pid, fd in owners): raise Unsafe("READS_INCOMPLETE")
            # Missing/partial process data cannot establish Studio ownership.
            complete_owners = bool(owners) and len(owners) == len(pids)
            records.append({"family": family, "address": ip.compressed, "scoped": scoped,
                            "wildcard": ip.is_unspecified, "inode": int(inodes[0]), "cookie": int(cookies[0], 16),
                            "v6only": int(options[0]) if options else None,
                            "owners": sorted(set((int(pid), int(fd)) for pid, fd in owners)), "complete_owners": complete_owners})
    if len(records) > 16: raise Unsafe("READS_INCOMPLETE")
    # Duplicate identities across rows/families are ambiguous, not two proofs.
    if len({(r["inode"], r["cookie"]) for r in records}) != len(records): raise Unsafe("READS_INCOMPLETE")
    return sorted(records, key=lambda r: (r["family"], r["address"], r["inode"], r["cookie"]))


def ownership_key(record, pid, fd): return f"{pid}:{fd}:{record['inode']}"


def listener_ownership(data, pid, readlink=os.readlink):
    """Inspect only Studio's numeric fd links, never another application's files."""
    result = {}
    for record in listener_records(data):
        for owner, fd in record["owners"]:
            if owner != pid or pid <= 0: continue
            try: verified = readlink(f"/proc/{pid}/fd/{fd}") == f"socket:[{record['inode']}]"
            except OSError: verified = False
            result[ownership_key(record, pid, fd)] = verified
    return result  # Booleans only; other fd target paths are discarded.


def studio_owns(records, data, pid):
    return bool(records) and pid > 0 and all(r["complete_owners"] and not r["scoped"] and
        all(owner == pid and data["listener_ownership"].get(ownership_key(r, owner, fd)) is True for owner, fd in r["owners"]) for r in records)


def bind_proof(records, family):
    """Call only after verifying EVERY listener's Studio ownership."""
    if any(r["family"] == family and r["wildcard"] and not r["scoped"] for r in records): return "native_ipv4" if family == 4 else "native_ipv6"
    # A separate IPv4/IPv6 loopback/reuseport socket could explain local health.
    # Support the provable single-listener case; never guess among sockets.
    if family == 4 and len(records) == 1:
        r = records[0]
        if r["family"] == 6 and r["wildcard"] and not r["scoped"] and r["v6only"] == 0: return "ipv4_dual_stack"
    return "unconfirmed"
