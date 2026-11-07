#!/usr/bin/env python3
"""Manual diagnostic coordinator; never installs, repairs or restarts anything."""
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "installer"))
from deploy import SSH, DeployError, server_ip
from probe_studio_network import (PORT, READ_STATES, LOAD_STATES, ACTIVE_STATES,
                                 SUB_STATES, HEALTH_ERRORS, read_health)


class ProtocolError(Exception): pass


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected): raise ProtocolError()


def choice(value, allowed):
    if value not in allowed: raise ProtocolError()


def boolean(value):
    if type(value) is not bool: raise ProtocolError()


def health_valid(value):
    keys(value, ("http", "ok", "error"))
    if value["http"] is not None and (type(value["http"]) is not int or not 100 <= value["http"] <= 599): raise ProtocolError()
    boolean(value["ok"]); choice(value["error"], HEALTH_ERRORS)
    if value["ok"] and (value["http"] != 200 or value["error"] != "none"): raise ProtocolError()


def counts_valid(value):
    keys(value, ("accept", "drop", "reject", "unknown"))
    if any(type(n) is not int or not 0 <= n <= 100000 for n in value.values()): raise ProtocolError()


def validate_remote(value):
    # Do not echo arbitrary remote JSON even after authenticated SSH. In this
    # owner-approved policy host-key verification is off; fixed schema is vital.
    keys(value, ("status", "service", "sockets", "local4", "local6", "firewall"))
    choice(value["status"], ("DIAGNOSED",))
    service = value["service"]
    keys(service, ("read", "LoadState", "ActiveState", "SubState"))
    for key, allowed in (("read", READ_STATES), ("LoadState", LOAD_STATES), ("ActiveState", ACTIVE_STATES), ("SubState", SUB_STATES)):
        choice(service[key], allowed)
    if not isinstance(value["sockets"], list) or len(value["sockets"]) != 2: raise ProtocolError()
    for expected_family, item in zip((4, 6), value["sockets"]):
        keys(item, ("read", "bindings", "limited")); choice(item["read"], READ_STATES); boolean(item["limited"])
        if not isinstance(item["bindings"], list) or len(item["bindings"]) > 16: raise ProtocolError()
        for binding in item["bindings"]:
            keys(binding, ("address", "family", "port", "scoped", "kind", "owner"))
            if type(binding["address"]) is not str or "%" in binding["address"]: raise ProtocolError()
            try: ip = ipaddress.ip_address(binding["address"])
            except ValueError: raise ProtocolError() from None
            if type(binding["family"]) is not int or binding["family"] != expected_family or ip.version != expected_family: raise ProtocolError()
            if type(binding["port"]) is not int or not 1 <= binding["port"] <= 65535: raise ProtocolError()
            boolean(binding["scoped"]); choice(binding["owner"], ("studio", "other", "unknown"))
            if binding["port"] != PORT and binding["owner"] != "studio": raise ProtocolError()
            kind = "wildcard" if ip.is_unspecified else "loopback" if ip.is_loopback else "specific"
            if binding["kind"] != kind: raise ProtocolError()
    health_valid(value["local4"]); health_valid(value["local6"])
    firewall = value["firewall"]; keys(firewall, ("ufw", "nft", "iptables4", "iptables6"))
    ufw = firewall["ufw"]; keys(ufw, ("read", "active", "default_incoming", "port3000", "allow_any"))
    choice(ufw["read"], READ_STATES); choice(ufw["active"], ("active", "inactive", "unknown"))
    choice(ufw["default_incoming"], ("allow", "deny", "reject", "unknown")); counts_valid(ufw["port3000"]); boolean(ufw["allow_any"])
    for name in ("iptables4", "iptables6"):
        item = firewall[name]; keys(item, ("read", "input_policy", "direct_port3000", "indirect"))
        choice(item["read"], READ_STATES); choice(item["input_policy"], ("accept", "drop", "unknown"))
        counts_valid(item["direct_port3000"]); boolean(item["indirect"])
    nft = firewall["nft"]; keys(nft, ("read", "input_policies", "direct_port3000", "indirect"))
    choice(nft["read"], READ_STATES); counts_valid(nft["direct_port3000"]); boolean(nft["indirect"])
    if not isinstance(nft["input_policies"], list) or len(nft["input_policies"]) > 9: raise ProtocolError()
    for policy in nft["input_policies"]:
        keys(policy, ("family", "policy")); choice(policy["family"], ("inet", "ip", "ip6")); choice(policy["policy"], ("accept", "drop", "unknown"))
    return value


CAUSES = {
    "EXTERNAL_HEALTHY": "С runner получен ожидаемый health 200. В этой точке отказ не обнаружен; это не проверка всего клиентского пути.",
    "SERVICE_STATUS_DISAGREES": "Внешний health доступен, но состояние Studio не подтверждено: возможен другой процесс или изменение состояния во время проверки.",
    "SSH_UNAVAILABLE": "Удалённые проверки не выполнены: SSH/инструменты недоступны. Внешний результат приведён отдельно.",
    "SERVICE_NOT_ACTIVE": "Studio service не active. Причину остановки этот read-only workflow не устанавливает и ничего не запускает.",
    "PORT_OWNED_BY_OTHER_PROCESS": "Порт 3000 принадлежит не MainPID Studio. Ничего не останавливать: возможен конфликт с другим приложением.",
    "STUDIO_USES_DIFFERENT_PORT": "Studio слушает другой порт, а не 3000. Проверка адреса IP:3000 не проверяет этот listener.",
    "NO_PORT_3000_LISTENER": "На 3000 не обнаружен TCP listener. Возможен иной порт или переходное состояние службы.",
    "SOCKET_STATE_UNKNOWN": "Данных ss недостаточно для вывода о прослушивании; отсутствие инструмента не означает отсутствие listener.",
    "LOOPBACK_BIND": "Listener 3000 доступен только через loopback. Прямое подключение к внешнему IP обычно не достигает такого bind.",
    "IP_FAMILY_BIND_MISMATCH": "Не подтверждён публичный bind нужного семейства IP. IPv6 wildcard сам по себе не доказывает доступность по IPv4.",
    "SPECIFIC_BIND_MISMATCH": "Listener привязан к конкретному адресу, не совпадающему с введённым IP; NAT/маршрутизация могут менять соответствие.",
    "LOCAL_HEALTH_FAILED": "Локальный health не подтверждён. Возможны недоступность приложения/SQLite, иной ответ или ограниченный bind; содержимое ответа не раскрывается.",
    "HOST_FIREWALL_POSSIBLE": "Локальный health работает, но внешний нет; сводка firewall допускает фильтрацию TCP/3000 на хосте. Это вероятная причина, не полная оценка ruleset.",
    "HOST_OR_UPSTREAM_UNDETERMINED": "Локальный health работает, но внешний нет. Возможны сложные правила хоста, firewall провайдера, NAT, маршрут или ограничения runner; точный слой не установлен.",
}


def probable_cause(remote, external, address):
    if remote is None: return "SSH_UNAVAILABLE"
    service = remote["service"]
    observed = [binding for item in remote["sockets"] for binding in item["bindings"] if binding["port"] == PORT]
    if external["ok"]:
        family = ipaddress.ip_address(address).version
        suitable = any(binding["family"] == family and (binding["kind"] == "wildcard" or binding["address"] == address) for binding in observed)
        if family == 4 and remote["local4"]["ok"]:
            suitable = suitable or any(binding["family"] == 6 and binding["kind"] == "wildcard" for binding in observed)
        complete = all(item["read"] == "ok" and not item["limited"] for item in remote["sockets"])
        own_listener = observed and complete and suitable and all(binding["owner"] == "studio" for binding in observed)
        return "EXTERNAL_HEALTHY" if service["read"] == "ok" and service["ActiveState"] == "active" and own_listener else "SERVICE_STATUS_DISAGREES"
    if service["read"] == "ok" and service["ActiveState"] in ("inactive", "failed"): return "SERVICE_NOT_ACTIVE"
    if any(item["limited"] or item["read"] != "ok" for item in remote["sockets"]): return "SOCKET_STATE_UNKNOWN"
    all_bindings = [binding for item in remote["sockets"] for binding in item["bindings"]]
    bindings = [binding for binding in all_bindings if binding["port"] == PORT]
    if not bindings:
        if any(binding["owner"] == "studio" for binding in all_bindings): return "STUDIO_USES_DIFFERENT_PORT"
        return "NO_PORT_3000_LISTENER" if all(item["read"] == "ok" and not item["limited"] for item in remote["sockets"]) else "SOCKET_STATE_UNKNOWN"
    if all(binding["owner"] == "other" for binding in bindings): return "PORT_OWNED_BY_OTHER_PROCESS"
    if all(binding["kind"] == "loopback" for binding in bindings): return "LOOPBACK_BIND"
    family = ipaddress.ip_address(address).version
    public = [binding for binding in bindings if binding["kind"] != "loopback"]
    matching = [binding for binding in public if binding["family"] == family]
    local = remote["local4"] if family == 4 else remote["local6"]
    if not matching and (family == 6 or not local["ok"]): return "IP_FAMILY_BIND_MISMATCH"
    if matching and all(binding["kind"] == "specific" and binding["address"] != address for binding in matching): return "SPECIFIC_BIND_MISMATCH"
    if not local["ok"]: return "LOCAL_HEALTH_FAILED"
    firewall = remote["firewall"]; ufw = firewall["ufw"]
    denied = ufw["read"] == "ok" and ufw["active"] == "active" and (ufw["port3000"]["drop"] or ufw["port3000"]["reject"] or (ufw["default_incoming"] in ("deny", "reject") and not ufw["allow_any"]))
    for name in ("nft", "iptables4" if family == 4 else "iptables6"):
        item = firewall[name]
        default_drop = (any(p["policy"] == "drop" and p["family"] in ("inet", "ip" if family == 4 else "ip6") for p in item["input_policies"])
                        if name == "nft" else item["input_policy"] == "drop")
        denied = denied or (item["read"] == "ok" and (item["direct_port3000"]["drop"] or item["direct_port3000"]["reject"] or (default_drop and not item["direct_port3000"]["accept"])))
    return "HOST_FIREWALL_POSSIBLE" if denied else "HOST_OR_UPSTREAM_UNDETERMINED"


SSH_ERRORS = ("SSH_AUTH_FAILED", "SSH_CONNECTION_FAILED", "SSH_TIMEOUT_OR_TRANSPORT_FAILED", "SSH_TOOLS_MISSING", "SSH_STREAM_UNSUPPORTED", "REMOTE_PROTOCOL_FAILED", "ROOT_REQUIRED", "PYTHON_3_12_REQUIRED")
REMOTE_COMMAND = "python3 -I -B -S -"  # No site customizations, bytecode writes or remote files.


def diagnose(address, password, ssh_factory=SSH, health=read_health):
    remote = None; ssh_state = "connected"
    try:
        # Reuse Studio root:22, password environment and owner-approved options.
        ssh = ssh_factory(address, password)
        with tempfile.TemporaryFile(mode="w+b") as source:
            source.write(Path(__file__).with_name("probe_studio_network.py").read_bytes()); source.seek(0)
            remote = validate_remote(ssh.execute(REMOTE_COMMAND, source, timeout=75))
    except DeployError as error:
        ssh_state = str(error) if str(error) in SSH_ERRORS else "SSH_PROBE_FAILED"
    except (ProtocolError, ValueError, TypeError): ssh_state = "REMOTE_PROTOCOL_FAILED"
    external = health(address, PORT); health_valid(external)
    cause = probable_cause(remote, external, address)
    partial = remote is None or any(item["limited"] for item in remote["sockets"]) or any(item["read"] != "ok" for item in [remote["service"], *remote["sockets"], *remote["firewall"].values()])
    host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    return {"status": "partial" if partial else "complete", "ssh": ssh_state, "checked_url": f"http://{host}:{PORT}/api/health",
            "remote": remote, "external": external, "probable_cause": cause}


def emit(report):
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as output:
            output.write("## Studio 19.25 — read-only network diagnostic\n\n")
            if report.get("probable_cause") in CAUSES:
                output.write(CAUSES[report["probable_cause"]] + "\n\n")
            output.write("```json\n" + json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n```\n\n")
            output.write("Workflow success means a report was produced, not that the site is healthy. No repair, restart or configuration change was attempted. Raw firewall output, HTTP bodies, service journals and credentials are omitted.\n")


def main():
    try:
        address = server_ip(os.environ.get("STUDIO_SERVER_IP", ""))
        password = os.environ.get("STUDIO_SSH_PASSWORD", "")
        if not password:
            emit({"status": "failed", "code": "STUDIO_SSH_PASSWORD_MISSING"}); return 1
        report = diagnose(address, password)
        emit(report)
        return 1 if report["ssh"] != "connected" else 0
    except Exception as error:
        code = "INVALID_SERVER_IP" if isinstance(error, DeployError) and str(error) == "INVALID_SERVER_IP" else "DIAGNOSTIC_FAILED"
        emit({"status": "failed", "code": code}); return 1


if __name__ == "__main__": raise SystemExit(main())
