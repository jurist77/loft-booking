#!/usr/bin/env python3
"""Read-only, bounded probe. Raw command output stays in memory and is never logged."""
import contextlib
import http.client
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess

PORT = 3000
LIMIT = 2 * 1024 * 1024
COMMANDS = {
    "service": ("systemctl", "show", "studio1925.service", "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID"),
    "sockets4": ("ss", "-H", "-4", "-lntp"),
    "sockets6": ("ss", "-H", "-6", "-lntp"),
    "ufw": ("ufw", "status", "verbose"),
    "nft": ("nft", "-j", "list", "ruleset"),
    "iptables": ("iptables-save", "-t", "filter"),
    "ip6tables": ("ip6tables-save", "-t", "filter"),
}
READ_STATES = ("ok", "missing", "error", "timeout", "output_limit")
LOAD_STATES = ("loaded", "not-found", "masked", "error", "unknown")
ACTIVE_STATES = ("active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "unknown")
SUB_STATES = ("running", "dead", "failed", "exited", "auto-restart", "start-pre", "start", "stop", "stop-sigterm", "unknown")
HEALTH_ERRORS = ("none", "timeout", "refused", "connection_error", "unexpected_response", "oversize")


@contextlib.contextmanager
def deadline(seconds):
    """Hard per-check deadline, including slow HTTP headers/body; this process only."""
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame): raise TimeoutError()
    signal.signal(signal.SIGALRM, expired)
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        signal.signal(signal.SIGALRM, previous)


def read_command(name):
    # No arbitrary argv, shell, sudo, configuration files or modification verbs.
    argv = COMMANDS[name]
    executable = shutil.which(argv[0], path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable: return "missing", ""
    child = None
    try:
        with deadline(5):
            child = subprocess.Popen([executable, *argv[1:]], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     start_new_session=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"})
            raw = child.stdout.read(LIMIT + 1)
            if len(raw) > LIMIT: return "output_limit", ""
            if child.wait(timeout=1) != 0: return "error", ""
            return "ok", raw.decode("utf-8", errors="replace")
    except (TimeoutError, subprocess.TimeoutExpired): return "timeout", ""
    except OSError: return "error", ""
    finally:
        if child:
            try:
                if child.poll() is None:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait(timeout=2)
            finally:
                if child.stdout: child.stdout.close()


def read_health(address, port=PORT):
    connection = http.client.HTTPConnection(address, port, timeout=3)
    result = {"http": None, "ok": False, "error": "connection_error"}
    try:
        with deadline(5):
            connection.request("GET", "/api/health", headers={"Connection": "close"})
            response = connection.getresponse()
            result["http"] = response.status
            body = response.read(513)
            if len(body) > 512: result["error"] = "oversize"
            else:
                try: value = json.loads(body)
                except (ValueError, UnicodeError): value = None
                result["ok"] = response.status == 200 and value == {"status": "ok"}
                result["error"] = "none" if result["ok"] else "unexpected_response"
    except TimeoutError: result["error"] = "timeout"
    except ConnectionRefusedError: result["error"] = "refused"
    except (OSError, http.client.HTTPException): pass
    finally: connection.close()
    return result  # Never return response body, headers, redirect, exception text.


def service_summary(state, raw):
    fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    result = {"read": state}
    for key, values in (("LoadState", LOAD_STATES), ("ActiveState", ACTIVE_STATES), ("SubState", SUB_STATES)):
        result[key] = fields.get(key) if fields.get(key) in values else "unknown"
    pid = fields.get("MainPID", "0")
    return result, int(pid) if pid.isascii() and pid.isdigit() and len(pid) <= 10 else 0


def socket_summary(state, raw, family, pid):
    bindings = []
    if state == "ok":
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0] != "LISTEN": continue
            try:
                address, port = parts[3].rsplit(":", 1)
                port = int(port)
                if not 1 <= port <= 65535: continue
                address = address.strip("[]")
                scoped = "%" in address
                address = address.split("%", 1)[0]
                if address == "*": address = "0.0.0.0" if family == 4 else "::"
                ip = ipaddress.ip_address(address)
                if ip.version != family: continue
            except (ValueError, IndexError): continue
            owners = set(re.findall(r"\bpid=(\d+)", line))
            owner = "studio" if pid and str(pid) in owners else "other" if pid and owners else "unknown"
            if port != PORT and owner != "studio": continue
            binding = {"address": ip.compressed, "family": family, "port": port, "scoped": scoped,
                       "kind": "wildcard" if ip.is_unspecified else "loopback" if ip.is_loopback else "specific", "owner": owner}
            if binding not in bindings: bindings.append(binding)
    return {"read": state, "bindings": bindings[:16], "limited": len(bindings) > 16}


def rule_counts(): return {"accept": 0, "drop": 0, "reject": 0, "unknown": 0}


def ufw_summary(state, raw):
    result = {"read": state, "active": "unknown", "default_incoming": "unknown", "port3000": rule_counts(), "allow_any": False}
    if state != "ok": return result
    if re.search(r"^Status: active\s*$", raw, re.M): result["active"] = "active"
    if re.search(r"^Status: inactive\s*$", raw, re.M): result["active"] = "inactive"
    policy = re.search(r"^Default:\s*(allow|deny|reject)\s*\(incoming\)", raw, re.M)
    if policy: result["default_incoming"] = policy[1]
    for line in raw.splitlines():
        # Strict target token; do not infer a decision from comments mentioning 3000.
        match = re.match(r"^3000(?:/tcp)?(?:\s+\(v6\))?\s+(ALLOW|DENY|REJECT)(?:\s+IN)?\s+(.+)$", line)
        if not match: continue
        action = {"ALLOW": "accept", "DENY": "drop", "REJECT": "reject"}[match[1]]
        result["port3000"][action] += 1
        if action == "accept" and re.fullmatch(r"Anywhere(?: \(v6\))?", match[2].split("#", 1)[0].strip()): result["allow_any"] = True
    return result


def iptables_summary(state, raw):
    result = {"read": state, "input_policy": "unknown", "direct_port3000": rule_counts(), "indirect": False}
    if state != "ok": return result
    policy = re.search(r"^:INPUT (ACCEPT|DROP)\s", raw, re.M)
    if policy: result["input_policy"] = policy[1].lower()
    for line in raw.splitlines():
        try: args = shlex.split(line)
        except ValueError: continue
        if args[:2] != ["-A", "INPUT"]: continue
        def value(flag):
            try: return args[args.index(flag) + 1]
            except (ValueError, IndexError): return ""
        verdict = (value("-j") or value("-g")).lower()
        if verdict and verdict not in ("accept", "drop", "reject", "return", "log"): result["indirect"] = True
        if value("-p") == "tcp" and value("--dport") == "3000":
            result["direct_port3000"][verdict if verdict in ("accept", "drop", "reject") else "unknown"] += 1
    return result


def nft_summary(state, raw):
    result = {"read": state, "input_policies": [], "direct_port3000": rule_counts(), "indirect": False}
    if state != "ok": return result
    try:
        entries = json.loads(raw)["nftables"]
        if not isinstance(entries, list): raise ValueError()
        chains = set()
        for entry in entries:
            chain = entry.get("chain", {})
            if chain.get("hook") == "input" and chain.get("family") in ("inet", "ip", "ip6"):
                chains.add((chain["family"], chain["table"], chain["name"]))
                policy = {"family": chain["family"], "policy": chain.get("policy") if chain.get("policy") in ("accept", "drop") else "unknown"}
                if policy not in result["input_policies"]: result["input_policies"].append(policy)
        for entry in entries:
            rule = entry.get("rule", {})
            if (rule.get("family"), rule.get("table"), rule.get("chain")) not in chains: continue
            expressions = rule.get("expr", [])
            if any("jump" in e or "goto" in e or "vmap" in e for e in expressions): result["indirect"] = True
            target = any(e.get("match", {}).get("left") == {"payload": {"protocol": "tcp", "field": "dport"}}
                         and e.get("match", {}).get("op") == "==" and e.get("match", {}).get("right") == PORT for e in expressions)
            if target:
                verdict = next((key for key in ("accept", "drop", "reject") if any(key in e for e in expressions)), "unknown")
                result["direct_port3000"][verdict] += 1
    except (ValueError, TypeError, KeyError, AttributeError): result["read"] = "error"
    return result


def collect(run=read_command, health=read_health):
    state, raw = run("service"); service, pid = service_summary(state, raw)
    sockets = [socket_summary(*run("sockets4"), 4, pid), socket_summary(*run("sockets6"), 6, pid)]
    return {"status": "DIAGNOSED", "service": service, "sockets": sockets,
            "local4": health("127.0.0.1"), "local6": health("::1"),
            "firewall": {"ufw": ufw_summary(*run("ufw")), "nft": nft_summary(*run("nft")),
                         "iptables4": iptables_summary(*run("iptables")), "iptables6": iptables_summary(*run("ip6tables"))}}


if __name__ == "__main__":
    try: print(json.dumps(collect(), sort_keys=True))
    except Exception: print('{"status":"PROBE_UNAVAILABLE"}')
