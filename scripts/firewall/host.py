"""Remote operation. Only write: one UFW allow; no repair/reload/rollback.

Loaded together with the read-only probe and rules.py over SSH stdin. Nothing
from this program or the SSH password is installed on the host.
"""
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import runpy
import sys

if "COMMANDS" not in globals():  # Normal imports in fixture tests; payload embeds these.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "diagnostics"))
    from probe_studio_network import COMMANDS, LIMIT, read_command, read_health, service_summary, ufw_summary, deadline
    from rules import Unsafe, saved_tables, empty_tables, ip_rule, ip_profile, nft_profile, clean_nft, expected_delta
    from bindings import listener_records, listener_ownership, studio_owns, bind_proof
    import json
    import re

CONFIRMATION = "ENABLE STUDIO TCP 3000"
ALLOW = ["/usr/sbin/ufw", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "3000"]
# Audited Ubuntu 24.04 ufw_0.36.2-6_all.deb, official archive. These are source
# integrity gates, not an instruction to downgrade packages or change backends.
UFW_HASHES = {
    "/usr/sbin/ufw": "e2ff4f8178807f04b411aad08315d875cb915ce8d9aa5895703bb7f0055e5d28",
    "/usr/lib/python3/dist-packages/ufw/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "/usr/lib/python3/dist-packages/ufw/applications.py": "c309cc855849b4505551c5211a5b3f7349d1f26a376f8ed0dd72b2bc4779f264",
    "/usr/lib/python3/dist-packages/ufw/backend.py": "24a372164947a8a3808b8797db49430d285f6ec1113f2c2895e403a058689232",
    "/usr/lib/python3/dist-packages/ufw/backend_iptables.py": "69cabdd144d3feef41910ac44fd79dde9fd518aa2c9eb8d9e6a7800c4661fc55",
    "/usr/lib/python3/dist-packages/ufw/common.py": "3eacf4b886260b0a9b1f9b74986fd6fcba3e0e90afed38c01db30736cce41728",
    "/usr/lib/python3/dist-packages/ufw/frontend.py": "c61d78d719778acf01314b222078db152fbfb45b2f9de66f3df51be45868d7eb",
    "/usr/lib/python3/dist-packages/ufw/parser.py": "db8d0769467fb4af3fd843980bf19dd82d55161e1986e8ae4723a5ae81f62d0b",
    "/usr/lib/python3/dist-packages/ufw/util.py": "7bb332974f8caf4322b6246c51fc72af6b6ff67ad18ce62b4735dc762e9dd6cc",
}
PROTECTED = ("/etc/default/ufw", "/etc/ufw/ufw.conf", "/etc/ufw/before.rules", "/etc/ufw/after.rules",
             "/etc/ufw/before6.rules", "/etc/ufw/after6.rules", "/etc/ufw/sysctl.conf")
HOST_COMMANDS = {
    **COMMANDS,
    "sockets4": ("ss", "-H", "-O", "-4", "-lntpe", "sport", "=", ":3000"),
    "sockets6": ("ss", "-H", "-O", "-6", "-lntpe", "sport", "=", ":3000"),
    "ip4": ("iptables-save",), "ip6": ("ip6tables-save",),
    "legacy4": ("iptables-legacy-save",), "legacy6": ("ip6tables-legacy-save",),
    "version4": ("iptables", "--version"), "version6": ("ip6tables", "--version"),
}


def bounded_file(name):
    path = Path(name)
    if path.is_symlink() or not path.is_file(): raise Unsafe("UNSUPPORTED_UFW_IMPLEMENTATION")
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022: raise Unsafe("UNSUPPORTED_UFW_IMPLEMENTATION")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT: raise Unsafe("READS_INCOMPLETE")
    return raw


def ufw_implementation():
    os_release = bounded_file("/usr/lib/os-release").decode()
    if not re.search(r'^ID=ubuntu$', os_release, re.M) or not re.search(r'^VERSION_ID="24\.04"$', os_release, re.M): raise Unsafe("UNSUPPORTED_HOST")
    for name, expected in UFW_HASHES.items():
        if hashlib.sha256(bounded_file(name)).hexdigest() != expected: raise Unsafe("UNSUPPORTED_UFW_IMPLEMENTATION")


def ufw_io(argv, allow_append=False):
    """Bounded subprocess boundary for audited UFW. No inherited env or shell."""
    executable, *args = argv
    allowed = False
    if executable in ("/usr/sbin/iptables", "/usr/sbin/ip6tables", "/sbin/iptables", "/sbin/ip6tables"):
        allowed = args in (["--version"], ["-V"])
        for prefix in ("ufw", "ufw6"):
            for suffix in ("input", "output", "forward", "limit", "limit-accept"):
                chain = prefix + "-user-" + suffix
                allowed = allowed or args in (["-L", chain, "-n"], ["-n", "-L", chain])
            if allow_append and args == ["-A", prefix + "-user-input", "-p", "tcp", "--dport", "3000", "-j", "ACCEPT"]: allowed = True
    if executable == "sysctl" and args in (["net.ipv4.ip_forward"], ["net.ipv6.conf.default.forwarding"], ["net.ipv6.conf.all.forwarding"]): allowed = True
    if not allowed: raise Unsafe("UNEXPECTED_UFW_COMMAND")
    from types import FunctionType
    reader = FunctionType(read_command.__code__, {**read_command.__globals__, "COMMANDS": {"operation": tuple(argv)}})
    state, raw = reader("operation")
    return (0, raw) if state == "ok" else (1, "")


def read_host(name):
    # Reuse the already bounded read-only subprocess implementation. Its command
    # lookup is supplied at payload assembly time, never from workflow inputs.
    if name == "ufw":
        # The CLI would wait for our already-held UFW lock in a second PID.
        # Its audited read-only backend method uses no CLI lock or caps probe.
        try:
            ufw_implementation()
            sys.path.insert(0, "/usr/lib/python3/dist-packages")
            import gettext
            gettext.install("ufw")
            import ufw.util
            import ufw.backend_iptables
            saved = (ufw.util.cmd, ufw.backend_iptables.cmd, ufw.util._print, sys.argv)
            try:
                # Backend security checks validate sys.argv[0]. SSH stdin uses
                # '-', which is not an installed file; use the audited CLI path.
                sys.argv = ["/usr/sbin/ufw"]
                ufw.util.cmd = ufw.backend_iptables.cmd = ufw_io
                ufw.util._print = lambda *args: None
                with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink), deadline(15):
                    return "ok", ufw.backend_iptables.UFWBackendIptables(False).get_status(True)
            finally: ufw.util.cmd, ufw.backend_iptables.cmd, ufw.util._print, sys.argv = saved
        except Unsafe: raise
        except Exception: return "error", ""
    from types import FunctionType
    # Reuse read limits/process cleanup with a private fixed command table;
    # leave the existing diagnostic module unchanged when imported in tests.
    reader = FunctionType(read_command.__code__, {**read_command.__globals__, "COMMANDS": HOST_COMMANDS})
    return reader(name)


def snapshot(read=read_host, files=bounded_file, health=read_health, readlink=os.readlink):
    result = {}
    for name in ("service", "sockets4", "sockets6", "ufw", "nft", "ip4", "ip6", "legacy4", "legacy6", "version4", "version6"):
        state, raw = read(name)
        if state != "ok": raise Unsafe("READS_INCOMPLETE")
        result[name] = raw
    result["protected"] = {name: files(name).hex() for name in PROTECTED}
    result["user4"] = files("/etc/ufw/user.rules").decode()
    result["user6"] = files("/etc/ufw/user6.rules").decode()
    service, pid = service_summary("ok", result["service"])
    records = listener_records(result)
    result["listener_ownership"] = listener_ownership(result, pid, readlink)
    result["local4"] = health("127.0.0.1")["ok"]
    result["local6"] = health("::1")["ok"]
    # Health must not bridge a process/socket replacement. Queues/counters are
    # volatile; compare PID/state and exact socket identities/options instead.
    fresh = {}
    for name in ("service", "sockets4", "sockets6"):
        state, raw = read(name)
        if state != "ok": raise Unsafe("READS_INCOMPLETE")
        fresh[name] = raw
    if service_summary("ok", fresh["service"]) != (service, pid) or listener_records(fresh) != records or listener_ownership(fresh, pid, readlink) != result["listener_ownership"]: raise Unsafe("LISTENER_STATE_CHANGED")
    return result  # Private memory only, never returned over SSH or logged.


def studio_ok(data, family):
    service, pid = service_summary("ok", data["service"])
    if not pid or service["LoadState"] != "loaded" or service["ActiveState"] != "active" or service["SubState"] != "running": raise Unsafe("STUDIO_NOT_ACTIVE")
    records = listener_records(data)
    if not studio_owns(records, data, pid): raise Unsafe("PORT_NOT_EXCLUSIVELY_STUDIO")
    proof = bind_proof(records, family)
    if proof == "unconfirmed": raise Unsafe("PUBLIC_BIND_NOT_CONFIRMED")
    if not data["local" + str(family)] or (proof == "ipv4_dual_stack" and not data["local6"]): raise Unsafe("LOCAL_HEALTH_FAILED")
    return proof


def backend_of(data):
    if all("(nf_tables)" in data[name] for name in ("version4", "version6")): return "nft"
    if all("(legacy)" in data[name] for name in ("version4", "version6")): return "legacy"
    raise Unsafe("MIXED_OR_UNKNOWN_BACKEND")


def persistent_rules(raw):
    # Preserve rule order and tuple metadata (including comments), not generated
    # headers or counter values. UFW regenerates these files for a normal add.
    return [line for line in raw.splitlines() if line.startswith(("### tuple ###", "-A ", ":", "*")) or line == "COMMIT"]


def canonical_rule(args):
    result = []; i = 0
    while i < len(args):
        if args[i:i + 2] in (["-m", "tcp"], ["-m", "udp"]): i += 2; continue
        result.append(args[i].replace("/minute", "/min")); i += 1
    return result


def state_fingerprint(data):
    # Counters, nft handles, generated headers and ss queue sizes are volatile.
    stable = {name: saved_tables(data[name]) for name in ("ip4", "ip6", "legacy4", "legacy6")}
    stable["nft"] = [clean_nft(v) for v in json.loads(data["nft"])["nftables"] if "metainfo" not in v]
    for name in ("protected", "version4", "version6", "service", "ufw", "local4", "local6"): stable[name] = data[name]
    stable["listeners"] = listener_records(data)
    stable["listener_ownership"] = data["listener_ownership"]
    for family in (4, 6):
        stable["user" + str(family)] = persistent_rules(data["user" + str(family)])
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def persistent_delta(before, after, family):
    old, new = persistent_rules(before), persistent_rules(after)
    user = ("ufw" if family == 4 else "ufw6") + "-user-input"
    extra_rule = f"-A {user} -p tcp --dport 3000 -j ACCEPT"
    # Tuple generated by audited UFW, independent of addresses in existing rules.
    zero = "0.0.0.0/0" if family == 4 else "::/0"
    extra_tuple = f"### tuple ### allow tcp 3000 {zero} any {zero} in"
    if new.count(extra_rule) != 1 or new.count(extra_tuple) != 1: return False
    new.remove(extra_rule); new.remove(extra_tuple)
    return old == new


def authorize(data, family, implementation=None):
    studio_ok(data, family)
    ufw = ufw_summary("ok", data["ufw"])
    if ufw["active"] != "active": raise Unsafe("UFW_NOT_ACTIVE")
    if ufw["default_incoming"] != "deny": raise Unsafe("POLICY_NOT_SUPPORTED")
    if ufw["port3000"]["accept"] or ufw["port3000"]["drop"] or ufw["port3000"]["reject"]: raise Unsafe("EXISTING_OR_CONFLICTING_3000_RULE")
    defaults = bytes.fromhex(data["protected"]["/etc/default/ufw"]).decode()
    if not re.search(r'^IPV6=yes$', defaults, re.M) or not re.search(r'^MANAGE_BUILTINS=no$', defaults, re.M): raise Unsafe("UNSUPPORTED_UFW_DEFAULTS")
    if not re.search(r'^ENABLED=yes$', bytes.fromhex(data["protected"]["/etc/ufw/ufw.conf"]).decode(), re.M): raise Unsafe("UNSUPPORTED_UFW_DEFAULTS")
    backend = backend_of(data)
    if backend == "nft":
        empty_tables(data["legacy4"]); empty_tables(data["legacy6"])
    elif saved_tables(data["legacy4"]) != saved_tables(data["ip4"]) or saved_tables(data["legacy6"]) != saved_tables(data["ip6"]): raise Unsafe("MIXED_OR_UNKNOWN_BACKEND")
    for version in (4, 6):
        ip_profile(data["ip" + str(version)], version)
        # Pending/different persisted rules could turn an add into replacement.
        active = saved_tables(data["ip" + str(version)])["filter"]
        saved = saved_tables(data["user" + str(version)])["filter"]
        user_prefix = ("ufw" if version == 4 else "ufw6") + "-user-"
        if not any(chain.startswith(user_prefix) for chain in saved["chains"]): raise Unsafe("PERSISTED_RULES_DIFFER")
        for chain in saved["chains"]:
            live = [canonical_rule(r) for r in active["rules"] if r[1] == chain]
            stored = [canonical_rule(r) for r in saved["rules"] if r[1] == chain]
            if live != stored or saved["chains"].get(chain) != "-": raise Unsafe("PERSISTED_RULES_DIFFER")
        # Restrict persisted tuples too: a broad/app/range rule can cause UFW's
        # matcher to replace a rule instead of appending. Never infer it safe.
        tuples = [line.split() for line in persistent_rules(data["user" + str(version)]) if line.startswith("### tuple ###")]
        if any(len(t) not in (10, 11) or (len(t) == 11 and not t[10].startswith("comment=")) or t[3] != "allow" or t[4] not in ("tcp", "udp") or not t[5].isdigit() or t[5] == "3000" or t[7] != "any" or t[9] not in ("in", "out") for t in tuples): raise Unsafe("PERSISTED_RULES_DIFFER")
    nft_profile(data["nft"], backend)
    if implementation is None:
        ufw_implementation()
        ufw_operation(data, apply=False)
    else: implementation()
    return backend


def result(status, reason, possible=False): return {"status": status, "reason": reason, "change_possible": possible}


def operate(mode, confirmation, family, take=snapshot, write=None, implementation=None, expected=None, accessible=False):
    if mode not in ("check", "apply") or (mode == "apply" and confirmation != CONFIRMATION): return result("FAILED_NO_CHANGE", "CONFIRMATION_REQUIRED")
    started = False
    observations = None
    def answer(status, reason, changed=False):
        value = result(status, reason, changed)
        if observations is not None: value["observations"] = observations
        return value
    try:
        before = take()
        service, pid = service_summary("ok", before["service"])
        records = listener_records(before)
        owned = studio_owns(records, before, pid)
        proof = bind_proof(records, family) if owned else "unconfirmed"
        ufw = ufw_summary("ok", before["ufw"])
        observations = {"studio_active": service["ActiveState"] == "active", "port_owned_by_studio": owned,
                        "public_bind": proof != "unconfirmed", "bind_proof": proof,
                        "local_health": before["local" + str(family)], "ufw": ufw["active"], "incoming": ufw["default_incoming"],
                        "allow3000": ufw["port3000"]["accept"], "deny3000": ufw["port3000"]["drop"] + ufw["port3000"]["reject"], "path_and_method_proven": False}
        studio_ok(before, family)
        fingerprint = state_fingerprint(before)
        if accessible: return answer("NO_CHANGE_REQUIRED" if mode == "apply" else "ALREADY_ACCESSIBLE", "EXTERNAL_HEALTH_CONFIRMED")
        backend = authorize(before, family, implementation)
        observations["path_and_method_proven"] = True
        if mode == "check": return {**answer("READY_TO_APPLY", "PATH_AND_APPEND_PROVEN"), "fingerprint": fingerprint}
        if fingerprint != expected: return answer("FAILED_NO_CHANGE", "STATE_CHANGED_SINCE_CHECK")
        started = True
        if write is None: ufw_operation(before, apply=True)
        else: write()
        after = take()
        if not expected_delta(before, after, backend) or any(not persistent_delta(before["user" + str(v)], after["user" + str(v)], v) for v in (4, 6)):
            return answer("MANUAL_REVIEW_REQUIRED", "UNEXPECTED_FIREWALL_DELTA", True)
        studio_ok(after, family)
        ufw_after = ufw_summary("ok", after["ufw"])
        if ufw_after["active"] != "active" or ufw_after["port3000"]["accept"] != 2 or ufw_after["port3000"]["drop"] or ufw_after["port3000"]["reject"]: raise Unsafe("UNEXPECTED_FIREWALL_DELTA")
        value = answer("APPLIED_PENDING_EXTERNAL", "ONLY_TCP_3000_ALLOW_ADDED", True)
        value["postflight"] = {"only_expected_firewall_delta": True, "persistent_allow": True, "ufw_allow": True, "studio_active": True, "local_health": True}
        return value
    except Unsafe as error:
        status = "MANUAL_REVIEW_REQUIRED" if started else "FAILED_NO_CHANGE" if mode == "apply" else "BLOCKED_FOR_SAFETY"
        if not started and mode == "check" and error.code in ("READS_INCOMPLETE", "UNSUPPORTED_UFW_IMPLEMENTATION", "PATH_NOT_PROVEN", "MIXED_OR_UNKNOWN_BACKEND"): status = "INCONCLUSIVE"
        return answer(status, error.code, started)
    except Exception:
        return answer("MANUAL_REVIEW_REQUIRED" if started else "FAILED_NO_CHANGE" if mode == "apply" else "INCONCLUSIVE", "OPERATION_NOT_CONFIRMED", started)


def ufw_operation(before, apply):
    """Same-process CLI uses the already held official POSIX UFW lock.

    No subprocess may re-acquire it in a different PID. Only lock plumbing is
    replaced in memory. Audited UFW parsing/persistence/append behavior is intact.
    A reload guard is an additional fail-closed barrier, never a fallback.
    """
    sys.path.insert(0, "/usr/lib/python3/dist-packages")
    import ufw.util
    import ufw.backend
    import ufw.backend_iptables
    replacements = []
    def replace(obj, name, value):
        replacements.append((obj, name, getattr(obj, name))); setattr(obj, name, value)
    replace(ufw.util, "create_lock", lambda **kwargs: None)
    replace(ufw.util, "release_lock", lambda lock: None)
    # msg() has an import-time stdout default; redirect_stdout alone does not
    # suppress it. All audited UFW messages use this single output boundary.
    replace(ufw.util, "_print", lambda *args: None)
    def refuse_reload(*args, **kwargs): raise Unsafe("UFW_RELOAD_WOULD_BE_REQUIRED")
    replace(ufw.backend_iptables.UFWBackendIptables, "_reload_user_rules", refuse_reload)
    # UFW's normal capability probe temporarily creates/flushed test chains.
    # Do not run it. Existing limit chains are mandatory in authorize(), and
    # the simple allow does not use recent/limit modules. Preserve their files.
    def existing_caps(backend): backend.caps = {"limit": {"4": True, "6": True}}
    replace(ufw.backend.UFWBackend, "initcaps", existing_caps)
    planning = [True]; planned = {}; appends = []
    def guarded_cmd(argv):
        executable, *args = argv
        if executable not in ("/usr/sbin/iptables", "/usr/sbin/ip6tables", "/sbin/iptables", "/sbin/ip6tables"): raise Unsafe("UNEXPECTED_UFW_COMMAND")
        for prefix in ("ufw", "ufw6"):
            chain = prefix + "-user-input"
            if args == ["-D", chain, "-j", "RETURN"]:
                # Audited UFW attempts to remove a legacy RETURN after append.
                # It is proven absent. Suppress even the attempted delete.
                return 1, ""
            if args == ["-A", chain, "-p", "tcp", "--dport", "3000", "-j", "ACCEPT"]:
                appends.append(chain)
                if appends.count(chain) != 1: raise Unsafe("UNEXPECTED_UFW_COMMAND")
                if planning[0]: return 0, ""
                code, output = ufw_io(argv, allow_append=True)
                if code != 0: raise Unsafe("UFW_ADD_FAILED")
                return code, output
            for suffix in ("input", "output", "forward", "limit", "limit-accept"):
                read_chain = prefix + "-user-" + suffix
                if args in (["-L", read_chain, "-n"], ["-n", "-L", read_chain]): return ufw_io(argv)
        if args in (["--version"], ["-V"]): return ufw_io(argv)
        raise Unsafe("UNEXPECTED_UFW_COMMAND")
    for module in (ufw.util, ufw.backend_iptables): replace(module, "cmd", guarded_cmd)
    for module in (ufw.util, ufw.backend_iptables): replace(module, "cmd_pipe", refuse_reload)
    # _need_reload only checks that chains exist, already proven under the same
    # UFW lock. Avoid its repeated capability probing and any reload fallback.
    replace(ufw.backend_iptables.UFWBackendIptables, "_need_reload", lambda *args: False)
    original_write = ufw.backend_iptables.UFWBackendIptables._write_rules
    def render(backend, v6=False):
        # Run the audited serializer, with all its file I/O redirected to
        # memory. This proves both persisted deltas BEFORE any config write.
        fragments = []; saved = (ufw.util.open_files, ufw.util.close_files, ufw.util.write_to_file)
        try:
            ufw.util.open_files = lambda name: {"tmp": -1}
            ufw.util.close_files = lambda *args: None
            ufw.util.write_to_file = lambda fd, value: fragments.append(value)
            original_write(backend, v6)
        finally: ufw.util.open_files, ufw.util.close_files, ufw.util.write_to_file = saved
        planned[6 if v6 else 4] = "".join(fragments)
    replace(ufw.backend_iptables.UFWBackendIptables, "_write_rules", render)
    old_argv = sys.argv
    def cli():
        sys.argv = ALLOW[:]
        try: runpy.run_path(ALLOW[0], run_name="__main__")
        except SystemExit as error:
            if error.code not in (0, None): raise Unsafe("UFW_ADD_FAILED") from None
    try:
        # No raw output, rule comments or errors may enter SSH stdout.
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink), deadline(20):
            cli()
            if set(planned) != {4, 6} or appends != ["ufw-user-input", "ufw6-user-input"] or any(not persistent_delta(before["user" + str(v)], planned[v], v) for v in (4, 6)): raise Unsafe("PERSISTED_RULES_DIFFER")
            if apply:
                planning[0] = False; appends.clear()
                # Recheck exact serialized content at each actual write.
                def checked_write(backend, v6=False):
                    version = 6 if v6 else 4
                    expected = planned[version]; render(backend, v6)
                    if planned[version] != expected: raise Unsafe("PERSISTED_RULES_DIFFER")
                    original_write(backend, v6)
                ufw.backend_iptables.UFWBackendIptables._write_rules = checked_write
                cli()
                if appends != ["ufw-user-input", "ufw6-user-input"]: raise Unsafe("UFW_ADD_FAILED")
    finally:
        sys.argv = old_argv
        for obj, name, old in reversed(replacements): setattr(obj, name, old)


def remote_main(options):
    # No files are created in check. Require the existing official UFW lock,
    # non-symlink, root-owned regular file; no Studio/global SSH config writes.
    entered = False
    try:
        if os.geteuid() != 0: raise Unsafe("ROOT_REQUIRED")
        if options["mode"] == "apply" and options["confirmation"] != CONFIRMATION: return result("FAILED_NO_CHANGE", "CONFIRMATION_REQUIRED")
        import stat
        fd = os.open("/run/ufw.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "r+b") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise Unsafe("UNSAFE_UFW_LOCK")
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            entered = True
            return operate(**options)
    except Exception:
        uncertain = entered and options["mode"] == "apply"
        return result("MANUAL_REVIEW_REQUIRED" if uncertain else "FAILED_NO_CHANGE" if options["mode"] == "apply" else "INCONCLUSIVE", "LOCK_OR_ROOT_UNAVAILABLE", uncertain)
