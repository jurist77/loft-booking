#!/usr/bin/env python3
"""Manual READ-ONLY HTTPS audit. No install/apply mode or remote state files."""
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "installer"))
from deploy import SSH, DeployError, server_ip
from probe_studio_network import (deadline, READ_STATES, LOAD_STATES, ACTIVE_STATES, SUB_STATES, HEALTH_ERRORS)
from studio_network import ProtocolError, SSH_ERRORS, health_valid
from probe_https_readiness import UNITS, TOOLS, PATHS, META, PROGRAMS
from probe_tls_residue import TLS_CHECKS, TLS_REASONS

REMOTE_COMMAND = "python3 -I -B -S -"
SCHEMA = {
    "status": ("OBSERVED",),
    "tls_residue": {"status": ("BLOCKED", "MATCHED_FAILED_PREPARE"), "reason": TLS_REASONS,
        "checks": {key:("NOT_CHECKED","MATCH") for key in TLS_CHECKS},
        "objects": {key:{"kind": ("unknown","directory","other"), "owner": ("unknown","root","tls","other"),
            "group": ("unknown","root","tls","other"), "mode": lambda v:type(v) is int and 0<=v<=0o7777} for key in ("base","config","data")},
        "account": ("unknown","missing","unsafe","expected"), "preservation_required": bool},
    "host": {"root": bool, "ubuntu24": bool, "arch": ("x64", "arm64", "unsupported"), "clock_sync": ("yes", "no", "unknown")},
    "studio": {"service": {"read": READ_STATES, "LoadState": LOAD_STATES, "ActiveState": ACTIVE_STATES, "SubState": SUB_STATES},
        "listener_owned": bool, "snapshot_stable": bool, "bind_proof": ("native_ipv4", "native_ipv6", "ipv4_dual_stack", "unconfirmed"),
        "local_health": {"http": lambda v: v is None or type(v) is int and 100 <= v <= 599, "ok": bool, "error": HEALTH_ERRORS},
        "isolated_user": bool, "permissions_compatible": bool, "managed_rootfs": bool, "private_network": ("yes", "no", "unknown"), "network_namespace": bool, "drop_ins": bool},
    "ports": {str(f): {"read": READ_STATES, "limited": bool, "listeners": [{"port": (80, 443), "bind": ("wildcard", "loopback", "specific"),
        "programs": [(*PROGRAMS, "other", "unknown")], "v6only": ("0", "1", "unknown")}]} for f in (4, 6)},
    "mechanisms": {"read": READ_STATES, "units": {name: ("active", "inactive", "failed", "activating", "deactivating", "reloading", "unknown", "not_observed") for name in UNITS},
        "tools": {name: bool for name in TOOLS}, "paths": {name: META for name in PATHS}, "custom_configuration": ("not_inspected",)},
    "firewall": {name: {"read": READ_STATES, "policy": ("allow", "deny", "reject", "inactive", "accept", "drop", "unknown"),
        "rules": int, "indirect": bool, "nat_or_other_hooks": bool,
        "port_rules": {str(port): {key: int for key in ("accept", "drop", "reject", "unknown")} for port in (80, 443, 3000)}}
        for name in ("ufw", "nft", "iptables", "ip6tables", "legacy4", "legacy6")},
}


def validate(value, schema=SCHEMA):
    if isinstance(schema, dict):
        if not isinstance(value, dict) or set(value) != set(schema): raise ProtocolError()
        for key in schema: validate(value[key], schema[key])
    elif isinstance(schema, list):
        if not isinstance(value, list) or len(value) > 4: raise ProtocolError()
        for item in value: validate(item, schema[0])
    elif isinstance(schema, tuple):
        if not any(type(value) is type(item) and value == item for item in schema): raise ProtocolError()
    elif schema is bool:
        if type(value) is not bool: raise ProtocolError()
    elif schema is int:
        if type(value) is not int or not 0 <= value <= 1000000: raise ProtocolError()
    elif not schema(value): raise ProtocolError()
    return value


def payload():
    # Embed only reviewed repository sources, no runtime input interpolation.
    base = (HERE / "probe_studio_network.py").read_text().split('\nif __name__ == "__main__":')[0]
    bindings = (HERE.parent / "firewall/bindings.py").read_text()
    probe = (HERE / "probe_https_readiness.py").read_text().split('\nif __name__ == "__main__":')[0]
    residue = (HERE / 'probe_tls_residue.py').read_text()
    reference = json.loads((HERE / 'https-residue-reference.json').read_text())
    return (base + "\nclass Unsafe(Exception): pass\n" + bindings + "\n" + residue +
            '\nTLS_RESIDUE_REFERENCE='+repr(reference)+'\n'+probe+
            '\ntry: print(json.dumps(collect(), sort_keys=True))\nexcept Exception: print(\'{"status":"PROBE_UNAVAILABLE"}\')\n').encode()


def external_checks(address):
    """One bounded TCP connection per port, one verified TLS handshake if open.

    No HTTP request to another application, no redirects or unverified TLS.
    IP-only verification cannot validate a hostname-only certificate.
    """
    result = {"tcp80": "error", "tcp443": "error", "tls443_for_ip": "not_checked", "certificate_lifetime": "unknown"}
    family = socket.AF_INET if ipaddress.ip_address(address).version == 4 else socket.AF_INET6
    for port in (80, 443):
        try:
            with deadline(4), socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(3); connection.connect((address, port))
            result["tcp" + str(port)] = "open"
        except TimeoutError: result["tcp" + str(port)] = "timeout"
        except ConnectionRefusedError: result["tcp" + str(port)] = "refused"
        except OSError: pass
    if result["tcp443"] == "open":
        try:
            with deadline(5), socket.socket(family, socket.SOCK_STREAM) as raw:
                raw.settimeout(3); raw.connect((address, 443))
                with ssl.create_default_context().wrap_socket(raw, server_hostname=address) as connection:
                    expiry = ssl.cert_time_to_seconds(connection.getpeercert()["notAfter"]) - time.time()
                    result["certificate_lifetime"] = "under_24h" if expiry < 86400 else "under_48h" if expiry < 172800 else "under_7d" if expiry < 604800 else "at_least_7d"
                    result["tls443_for_ip"] = "verified"
        except ssl.SSLCertVerificationError: result["tls443_for_ip"] = "not_verified_for_ip"
        except (OSError, TimeoutError, ValueError, KeyError): result["tls443_for_ip"] = "unavailable"
    return result


EXTERNAL_SCHEMA = {"tcp80": ("open", "refused", "timeout", "error"), "tcp443": ("open", "refused", "timeout", "error"),
    "tls443_for_ip": ("not_checked", "verified", "not_verified_for_ip", "unavailable"),
    "certificate_lifetime": ("unknown", "under_24h", "under_48h", "under_7d", "at_least_7d")}
VERDICTS = {
    "INCONCLUSIVE": "Данных недостаточно. Отсутствующий инструмент/неполный вывод не означает свободные порты или отсутствие TLS.",
    "STUDIO_PREFLIGHT_FAILED": "Совместимость или работоспособность Studio не подтверждена. Сначала отдельная проверка; ничего не устанавливать.",
    "EXISTING_443_LISTENER": "TCP/443 занят. Не останавливать listener, не менять VPN или чужой proxy. Требуется отдельная сетевая схема или аудит другого имеющегося VPS.",
    "PORT_80_CHALLENGE_REVIEW": "TCP/80 занят. Не останавливать listener ради HTTP-01. При свободном 443 изучить TLS-ALPN-01 или автоматизированный DNS-01.",
    "NETWORK_PATH_REVIEW_REQUIRED": "Есть дополнительные/неизвестные слои фильтрации или расхождение внешнего и локального наблюдения. Пути обработки пакетов эта сводка не доказывает.",
    "FREE_PORTS_OBSERVED_REVIEW_REQUIRED": "На снимке 80/443 свободны. DuckDNS + отдельный proxy — кандидат; DNS, firewall, стабильность VPN и согласование владельца всё ещё обязательны.",
}


def verdict(remote, external):
    if remote is None: return "INCONCLUSIVE"
    if any(p["read"] != "ok" or p["limited"] for p in remote["ports"].values()): return "INCONCLUSIVE"
    ports = {p["port"] for family in remote["ports"].values() for p in family["listeners"]}
    if 443 in ports: return "EXISTING_443_LISTENER"
    studio = remote["studio"]
    if not (remote["host"]["root"] and remote["host"]["ubuntu24"] and remote["host"]["arch"] != "unsupported" and
            studio["service"]["read"] == "ok" and studio["service"]["LoadState"] == "loaded" and studio["service"]["ActiveState"] == "active" and studio["service"]["SubState"] == "running" and
            studio["listener_owned"] and studio["local_health"]["ok"] and studio["isolated_user"] and studio["permissions_compatible"] and studio["managed_rootfs"] and
            studio["private_network"] == "no" and not studio["network_namespace"]): return "STUDIO_PREFLIGHT_FAILED"
    if 80 in ports: return "PORT_80_CHALLENGE_REVIEW"
    firewall = remote["firewall"]
    if any(p["read"] != "ok" or p["rules"] or p["indirect"] or p["nat_or_other_hooks"] or p["policy"] in ("unknown", "drop", "deny", "reject") for p in firewall.values()) or any(external[k] in ("open", "error") for k in ("tcp80", "tcp443")):
        return "NETWORK_PATH_REVIEW_REQUIRED"
    if remote["mechanisms"]["read"] != "ok" or remote["host"]["clock_sync"] != "yes" or studio["drop_ins"]: return "INCONCLUSIVE"
    return "FREE_PORTS_OBSERVED_REVIEW_REQUIRED"


def diagnose(address, password, ssh_factory=SSH, external=external_checks):
    remote = None; state = "connected"
    try:
        ssh = ssh_factory(address, password)
        with tempfile.TemporaryFile(mode="w+b") as source:
            source.write(payload()); source.seek(0)
            remote = validate(ssh.execute(REMOTE_COMMAND, source, timeout=150))
            health_valid(remote["studio"]["local_health"])
            if (remote["studio"]["listener_owned"] and not remote["studio"]["snapshot_stable"] or
                    remote["studio"]["bind_proof"] != "unconfirmed" and not remote["studio"]["listener_owned"]): raise ProtocolError()
            if any(p["v6only"] != "unknown" for p in remote["ports"]["4"]["listeners"]): raise ProtocolError()
            residue=remote['tls_residue']
            if residue['status']=='MATCHED_FAILED_PREPARE':
                if (residue['reason']!='MATCHED_PINNED_PREPARE' or residue['preservation_required'] or
                    residue['account']!='expected' or any(v!='MATCH' for v in residue['checks'].values())):raise ProtocolError()
                for key,owner,group in (('base','root','root'),('config','root','tls'),('data','tls','tls')):
                    if residue['objects'][key]!={'kind':'directory','owner':owner,'group':group,'mode':0o700}:raise ProtocolError()
                studio=remote['studio']
                if not (studio['snapshot_stable'] and studio['listener_owned'] and studio['local_health']['ok'] and
                        studio['permissions_compatible'] and studio['service']['ActiveState']=='active' and
                        all(p['read']=='ok' and not p['limited'] and not p['listeners'] for p in remote['ports'].values())):
                    residue.update(status='BLOCKED',reason='STUDIO_NOT_HEALTHY',preservation_required=True)
            elif residue['reason']=='MATCHED_PINNED_PREPARE' or not residue['preservation_required']:raise ProtocolError()
    except DeployError as error: state = str(error) if str(error) in SSH_ERRORS else "SSH_PROBE_FAILED"
    except (ProtocolError, TypeError, ValueError): remote = None; state = "REMOTE_PROTOCOL_FAILED"
    # Do not make external requests if SSH failed, input is not validated or
    # remote JSON was rejected. This workflow never guesses a repair.
    observed = validate(external(address), EXTERNAL_SCHEMA) if remote else None
    outcome = verdict(remote, observed)
    return {"status": "observed" if remote else "failed", "ssh": state, "verdict": outcome,
            "remote": remote, "external": observed, "changes": "none", "dns_hostname": "owner_input_required"}


def emit(report):
    text = json.dumps(report, sort_keys=True, ensure_ascii=True, indent=2)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write("## Studio HTTPS readiness — READ ONLY\n\n" + VERDICTS.get(report.get("verdict"), "Audit failed; no changes attempted.") +
                "\n\n```json\n" + text + "\n```\n\nNo installation authorization. No DNS/ACME issuance, direct database/booking access, service changes or firewall changes. Client names, IPs, credentials and configuration contents are omitted. Existing health performs its normal DB check. A green job means a report was produced.\n")
            output.write('\nTLS residue: BLOCKED means preserve everything. MATCHED_FAILED_PREPARE is a snapshot match to the pinned failed run, not cleanup/apply authorization. See docs/https-residue-audit.md; no quarantine or deletion is performed.\n')


def main():
    try:
        value = os.environ.get("STUDIO_SERVER_IP")
        if value is None:
            with open(os.environ["GITHUB_EVENT_PATH"], "rb") as event:
                raw = event.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024: raise ValueError()
            value = json.loads(raw).get("inputs", {}).get("server_ip", "")
        address = server_ip(value)
        password = os.environ.get("STUDIO_SSH_PASSWORD", "")
        if not password: raise DeployError("STUDIO_SSH_PASSWORD_MISSING")
        report = diagnose(address, password); emit(report)
        return 0 if report["status"] == "observed" else 1
    except Exception as error:
        code = str(error) if isinstance(error, DeployError) and str(error) in ("INVALID_SERVER_IP", "STUDIO_SSH_PASSWORD_MISSING") else "HTTPS_AUDIT_FAILED"
        emit({"status": "failed", "code": code, "changes": "none"}); return 1


if __name__ == "__main__": raise SystemExit(main())
