"""Root transaction. Studio paths/units plus separately proved TCP/80/443 allows.

The caller holds the install lock. Recovery uses the same lock and a durable
checkpoint. SQLite is not restored, copied or opened by this controller.
"""
import contextlib
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import struct
import sys
import tarfile
import threading
import time
import studio_installer as I
from configuration import (BASE, ETC, DATA, USER, SERVICE, RECOVERY_SERVICE, RECOVERY_TIMER,
                           MONITOR_TIMER, MONITOR_SERVICE, UNIT_DIR, caddy_config, service, auxiliary_units, inputs)
from checks import require, HttpsError, https_health
from inventory import snapshot, read, own_listeners
import firewall
from probe_studio_network import deadline
from phase_report import Progress, error_kind, INPUT_ERROR_CODES

RELEASE = None  # Injected from the checked-in immutable manifest by the bundler.
OWNER = BASE / "managed.json"
TRANSACTION = BASE / "transaction.json"


def private_json(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < 256000, "UNSAFE_TLS_STATE")
    return json.loads(path.read_text())


def owned():
    if not OWNER.exists():
        require(not any(p.exists() or p.is_symlink() for p in (BASE, ETC, DATA, UNIT_DIR / SERVICE, UNIT_DIR / RECOVERY_SERVICE, UNIT_DIR / RECOVERY_TIMER, UNIT_DIR / MONITOR_SERVICE, UNIT_DIR / MONITOR_TIMER)), "UNMANAGED_TLS_PATH_COLLISION")
        # An exact missing name makes list-unit-files exit 1 on systemd 255.
        # Enumerate successfully, then compare names; don't treat arbitrary
        # command errors as evidence that a service is absent.
        units = set()
        for argv in (["systemctl", "list-unit-files", "--plain", "--no-legend", "--no-pager"],
                     ["systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager"]):
            units.update(line.split()[0] for line in I.run(argv, "TLS_UNIT_INVENTORY_FAILED").splitlines() if line.strip())
        require(not units.intersection((SERVICE, *auxiliary_units())), "UNMANAGED_TLS_UNIT_COLLISION")
        try: pwd.getpwnam(USER)
        except KeyError: return None
        raise HttpsError("UNMANAGED_TLS_USER_COLLISION")
    I.owned_directory(BASE, mode=0o755)
    value = private_json(OWNER)
    require(set(value) == {"format", "managed_by", "uid", "gid", "archive_sha256", "hostname", "committed", "files"} and value.get("managed_by") == "studio-https" and value.get("format") == 1 and type(value["committed"]) is bool, "UNSAFE_TLS_STATE")
    I.https_settings({"https": {"format": 1, "hostname": value["hostname"]}})
    expected = RELEASE["archives"][I.host_facts()["arch"]]["sha256"]
    paths = {str(BASE / "control.py"), str(ETC / "caddy.json"), str(BASE / "releases" / expected / "caddy"), *(str(UNIT_DIR / n) for n in (SERVICE, *auxiliary_units()))}
    require(isinstance(value["files"], dict) and set(value["files"]) == paths, "UNSAFE_TLS_FILE_SET")
    account = pwd.getpwnam(USER)
    require(account.pw_uid == value.get("uid") and account.pw_gid == value.get("gid") and account.pw_uid > 0 and account.pw_gid > 0 and account.pw_shell == "/usr/sbin/nologin" and set(os.getgrouplist(USER, account.pw_gid)) == {account.pw_gid}, "TLS_IDENTITY_CHANGED")
    I.owned_directory(DATA, account.pw_uid, account.pw_gid)
    require(ETC.resolve() == ETC and ETC.stat().st_uid == 0 and not ETC.stat().st_mode & 0o022, "UNSAFE_TLS_DIRECTORY")
    for name, digest in value.get("files", {}).items():
        path = Path(name)
        allowed = (path == BASE / "control.py" or path == ETC / "caddy.json" or path == UNIT_DIR / SERVICE or path.name in auxiliary_units() and path.parent == UNIT_DIR or path.is_relative_to(BASE / "releases"))
        require(allowed and path.resolve() == path and path.is_file() and not path.is_symlink() and path.stat().st_uid == 0 and not path.stat().st_mode & 0o022 and I.digest(path) == digest, "MANAGED_TLS_FILE_CHANGED")
    require(value.get("archive_sha256") == expected, "CADDY_UPGRADE_REQUIRES_REVIEW")
    return value


def save_owner(value): I.atomic_write(OWNER, json.dumps(value, sort_keys=True))


class PortProbe:
    def __init__(self, nonce, addresses, ports=(80, 443)):
        self.servers = []; self.threads = []; self.nonce = hashlib.sha256((nonce + ":ports").encode()).hexdigest().encode()
        self.addresses = addresses; self.ports = ports

    def __enter__(self):
        expected = self.nonce
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                body = expected if self.path == "/.well-known/studio-probe/" + expected.decode() else b""
                self.send_response(200 if body else 404); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            # Permit the successor Caddy listener after our accepted HTTP
            # sockets enter TIME_WAIT. SO_REUSEPORT is NEVER enabled: an
            # active foreign listener still prevents this bind.
            allow_reuse_address = True
            request_queue_size = 8
            def __init__(self, *args, **kwargs):
                self.slots = threading.BoundedSemaphore(8)
                super().__init__(*args, **kwargs)
            def process_request(self, request, client_address):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(request); return
                try: super().process_request(request, client_address)
                except BaseException: self.slots.release(); raise
            def process_request_thread(self, request, client_address):
                try: super().process_request_thread(request, client_address)
                finally: self.slots.release()
            def get_request(self):
                conn, address = super().get_request(); conn.settimeout(3); return conn, address
            def handle_error(self, *args): pass
        try:
            families = {4, *(6 for a in self.addresses if ":" in a)}
            for family in sorted(families):
                for port in self.ports:
                    cls = type("V6Probe", (Server,), {"address_family": socket.AF_INET6}) if family == 6 else Server
                    server = cls(("::" if family == 6 else "0.0.0.0", port), Handler, bind_and_activate=False)
                    if family == 6: server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    try: server.server_bind(); server.server_activate()
                    except BaseException: server.server_close(); raise
                    self.servers.append(server)
                    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .1}, daemon=True)
                    thread.start(); self.threads.append(thread)
            return self
        except BaseException: self.__exit__(None, None, None); raise HttpsError("PORT_PROBE_BIND_FAILED") from None

    def __exit__(self, *args):
        for server in self.servers: server.shutdown(); server.server_close()
        for thread in self.threads: thread.join(timeout=4)


class Operations:
    def __init__(self, source, config=caddy_config, inspector=snapshot, verifier=https_health):
        self.source, self.config, self.inspector, self.verifier = source, config, inspector, verifier

    def checkpoint(self, state, owner):
        return {"format": 1, "stage": "prepared", "prior": state, "prior_env": I.private_environment(), "prior_unit": I.UNIT.read_text(),
                "previous_tls": owner, "hostname": None, "planned_env": None, "planned_unit": None}

    def prepare(self, state, archive, options, owner):
        arch = I.host_facts()["arch"]; expected = RELEASE["archives"][arch]["sha256"]
        require(hashlib.sha256(archive).hexdigest() == expected, "CADDY_CHECKSUM_MISMATCH")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            members = tar.getmembers()
            require({m.name for m in members} <= {"caddy", "LICENSE", "README.md"} and len({m.name for m in members}) == len(members) and all(m.isfile() and m.size <= 100 * 1024**2 and not m.mode & 0o6000 for m in members), "UNSAFE_CADDY_ARCHIVE")
            binary = tar.extractfile("caddy").read(100 * 1024**2 + 1)
            license_text = tar.extractfile("LICENSE").read(100000)
        require(binary[:4] == b"\x7fELF" and struct.unpack("<H", binary[18:20])[0] == (62 if arch == "x64" else 183), "CADDY_ARCH_MISMATCH")
        if owner:
            require(not owner.get("committed"), "ALREADY_HTTPS_USE_CHECK")
            account = pwd.getpwnam(USER)
        else:
            I.run(["useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", USER], "TLS_USER_CREATE_FAILED")
            account = pwd.getpwnam(USER)
            I.owned_directory(BASE, mode=0o755, create=True)
            # entry uses umask 077: mkdir(mode=...) alone would create 0700
            # root directories and prevent the separate TLS uid from entering.
            BASE.chmod(0o755)
            ETC.mkdir(mode=0o750); os.chown(ETC, 0, account.pw_gid)
            ETC.chmod(0o750)
            I.owned_directory(DATA, account.pw_uid, account.pw_gid, create=True)
        release_dir = BASE / "releases" / expected
        if not release_dir.parent.exists():
            release_dir.parent.mkdir(mode=0o755); release_dir.parent.chmod(0o755)
        if not release_dir.exists():
            release_dir.mkdir(mode=0o755); release_dir.chmod(0o755)
        binary_path = release_dir / "caddy"
        if binary_path.exists(): require(not binary_path.is_symlink() and binary_path.read_bytes() == binary, "CADDY_FILE_CHANGED")
        else:
            with binary_path.open("xb") as stream: stream.write(binary); stream.flush(); os.fsync(stream.fileno())
            os.chmod(binary_path, 0o755)
        I.atomic_write(release_dir / "LICENSE", license_text.decode(), 0o644)
        I.atomic_write(BASE / "control.py", self.source, 0o644)
        config_path = ETC / "caddy.json"
        I.atomic_write(config_path, json.dumps(self.config(options["hostname"], state["port"]), sort_keys=True), 0o640)
        os.chown(config_path, 0, account.pw_gid)
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "XDG_DATA_HOME": str(DATA), "XDG_CONFIG_HOME": str(DATA / "config")}
        result = I.subprocess.run(["runuser", "-u", USER, "--", str(binary_path), "validate", "--config", str(config_path)], stdout=I.subprocess.DEVNULL, stderr=I.subprocess.DEVNULL, env=environment, timeout=30)
        require(result.returncode == 0, "CADDY_CONFIG_INVALID")
        files = [binary_path, BASE / "control.py", config_path]
        for name, contents in {SERVICE: service(binary_path), **auxiliary_units()}.items():
            target = UNIT_DIR / name
            require(owner or not target.exists() and not target.is_symlink(), "UNMANAGED_TLS_UNIT_COLLISION")
            I.atomic_write(target, contents, 0o644); files.append(target)
        current = {"format": 1, "managed_by": "studio-https", "uid": account.pw_uid, "gid": account.pw_gid,
                   "archive_sha256": expected, "hostname": options["hostname"], "committed": False,
                   "files": {str(path): I.digest(path) for path in files}}
        save_owner(current)
        I.run(["systemctl", "daemon-reload"], "TLS_MANAGER_RELOAD_FAILED")
        I.run(["systemctl", "enable", "--now", RECOVERY_TIMER], "TLS_RECOVERY_TIMER_FAILED")
        return current

    def start_tls(self):
        I.run(["systemctl", "start", SERVICE], "TLS_START_FAILED", timeout=45)

    def certificate(self, host, port):
        end = time.monotonic() + 240
        last_error = None
        while time.monotonic() < end:
            try: return self.verifier(host, "127.0.0.1")
            except HttpsError as error:
                if str(error) in ("HTTPS_APPLICATION_UNAVAILABLE", "HTTPS_VERIFICATION_RATE_LIMITED", "HTTPS_HEALTH_OR_API_FAILED", "HTTPS_API_CONTRACT_FAILED"): raise
                last_error = error
                time.sleep(2)
        raise HttpsError("TRUSTED_CERTIFICATE_NOT_READY") from last_error

    def cutover(self, checkpoint, current):
        prior = checkpoint["prior"]
        settings = {"format": 1, "hostname": checkpoint["hostname"]}
        release = I.BASE / "releases" / prior["current"]
        checkpoint["planned_env"] = I.environment_text(prior["port"], https=settings)
        checkpoint["planned_unit"] = I.service_text(release, prior["port"], settings)
        checkpoint["stage"] = "cutover"
        I.atomic_write(TRANSACTION, json.dumps(checkpoint, sort_keys=True))
        barrier = {**prior, "https_pending": True}; I.store_state(barrier)
        I.atomic_write(I.CONFIG / "server.env", checkpoint["planned_env"])
        I.atomic_write(I.UNIT, checkpoint["planned_unit"], 0o644)
        I.run(["systemctl", "daemon-reload"], "TLS_MANAGER_RELOAD_FAILED")
        I.run(["systemctl", "restart", I.SERVICE], "TLS_STUDIO_RESTART_FAILED", timeout=45)
        I.health(prior["port"]); I.api_health(prior["port"])
        state = {**prior, "https": settings, "origin": "https://" + settings["hostname"], "https_pending": True, "unit_sha256": I.digest(I.UNIT)}
        I.store_state(state)
        return state

    def commit(self, checkpoint, current, state):
        require(I.private_environment() == checkpoint["planned_env"] and I.UNIT.read_text() == checkpoint["planned_unit"], "CUTOVER_FILES_CHANGED")
        checkpoint["stage"] = "public-verified"; I.atomic_write(TRANSACTION, json.dumps(checkpoint, sort_keys=True))
        state.pop("https_pending", None); I.store_state(state)
        current["committed"] = True; save_owner(current)
        I.run(["systemctl", "enable", SERVICE, MONITOR_TIMER], "TLS_ENABLE_FAILED")
        I.run(["systemctl", "start", MONITOR_TIMER], "TLS_MONITOR_START_FAILED")
        TRANSACTION.unlink(); self.sync()

    def sync(self):
        fd = os.open(BASE, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def rollback(self, checkpoint):
        # Refuse to overwrite manual changes or a newer app release. Data is
        # never rewound, even if customers booked during the transition.
        require(checkpoint.get("format") == 1 and checkpoint.get("stage") in ("prepared", "cutover", "public-verified"), "UNSAFE_TLS_CHECKPOINT")
        state = I.load_state(allow_https_pending=True)
        require(state["current"] == checkpoint["prior"]["current"], "RECOVERY_RELEASE_CHANGED")
        require(I.private_environment() in (checkpoint["prior_env"], checkpoint["planned_env"]) and I.UNIT.read_text() in (checkpoint["prior_unit"], checkpoint["planned_unit"]), "RECOVERY_FILES_CHANGED")
        if checkpoint["stage"] == "public-verified":
            require(I.private_environment() == checkpoint["planned_env"] and I.UNIT.read_text() == checkpoint["planned_unit"] and I.https_settings(state) == {"format": 1, "hostname": checkpoint["hostname"]}, "RECOVERY_VERIFIED_STATE_CHANGED")
            I.run(["systemctl", "start", SERVICE], timeout=45)
            I.run(["systemctl", "start", I.SERVICE], timeout=45)
            I.health(state["port"])
            self.verifier(checkpoint["hostname"], "127.0.0.1")
            state.pop("https_pending", None); I.store_state(state)
            current = owned(); current["committed"] = True; save_owner(current)
            I.run(["systemctl", "enable", SERVICE, MONITOR_TIMER]); I.run(["systemctl", "start", MONITOR_TIMER])
        else:
            if checkpoint["stage"] == "cutover":
                I.atomic_write(I.CONFIG / "server.env", checkpoint["prior_env"])
                I.atomic_write(I.UNIT, checkpoint["prior_unit"], 0o644)
                I.run(["systemctl", "daemon-reload"])
                I.run(["systemctl", "restart", I.SERVICE], timeout=45); I.health(state["port"])
                I.store_state(checkpoint["prior"])
            I.run(["systemctl", "stop", SERVICE], check=False, timeout=45)
            I.run(["systemctl", "disable", SERVICE], check=False)
        TRANSACTION.unlink(missing_ok=True); self.sync()


def event(kind, **fields):
    print(json.dumps({"event": kind, **fields}, sort_keys=True), flush=True)


def acknowledge(phase, nonce):
    with deadline(120): value = json.loads(sys.stdin.buffer.readline(4097))
    require(isinstance(value, dict) and set(value) == {"phase", "nonce", "ok"} and value["phase"] == phase and value["nonce"] == nonce and value["ok"] is True, "EXTERNAL_PROOF_NOT_CONFIRMED")


def apply(options, archive, source, ops=None, emit=event, ack=acknowledge, probe=PortProbe):
    ops = ops or Operations(source)
    with I.install_lock():
        require(not TRANSACTION.exists(), "PENDING_TLS_RECOVERY_REQUIRED")
        state = I.load_state(); require(state and state.get("current"), "STUDIO_INSTALL_REQUIRED")
        owner = owned()
        require(bool(owner and owner["committed"]) == bool(I.https_settings(state)), "HTTPS_STATE_DISAGREES")
        require(not I.https_settings(state) or I.https_settings(state)["hostname"] == options["hostname"], "HTTPS_HOSTNAME_CHANGE_REQUIRES_REVIEW")
        require(not owner or owner["hostname"] == options["hostname"], "HTTPS_HOSTNAME_CHANGE_REQUIRES_REVIEW")
        facts = ops.inspector(state, options["addresses"], bool(owner and owner["committed"]), allow_stopped=True)
        added = facts.get("firewall_plan", [])
        if added:
            # DNS/ownership/local API and both dry plans already passed. No TLS
            # preparation or Studio restart occurs before the verified append.
            expected = firewall.enable(facts["firewall"], added, options["addresses"])
            facts = ops.inspector(state, options["addresses"], bool(owner and owner["committed"]), allow_stopped=True)
            require(facts["firewall"] == expected and not facts.get("firewall_plan"), "HTTPS_FIREWALL_CHANGE_UNCONFIRMED_REVIEW_REQUIRED")
            emit("firewall-result", ports=added)
        if owner and owner["committed"]:
            require(I.https_settings(state) == {"format": 1, "hostname": options["hostname"]}, "HTTPS_STATE_DISAGREES")
            if facts["tls_stopped"]:
                I.run(["systemctl", "reset-failed", SERVICE], check=False)
                ops.start_tls()
            value = ops.certificate(options["hostname"], state["port"])
            emit("verify-existing", fingerprint=value["fingerprint"], port=state["port"])
            ack("verify-existing", options["nonce"])
            changed = facts["tls_stopped"] or any(I.run(["systemctl", "is-enabled", unit], check=False) != 0 for unit in (SERVICE, MONITOR_TIMER, RECOVERY_TIMER))
            I.run(["systemctl", "enable", SERVICE, MONITOR_TIMER, RECOVERY_TIMER], "TLS_ENABLE_FAILED")
            I.run(["systemctl", "start", MONITOR_TIMER, RECOVERY_TIMER], "TLS_MONITOR_START_FAILED")
            emit("result", status="SUCCESS", operation="https-service-recovered" if changed else "already-https", changes="studio-tls-and-ufw" if added else "studio-tls-only" if changed else "none", firewall_added=added)
            return
        # Every active admission check runs BEFORE changing installed Studio.
        with probe(options["nonce"], options["addresses"]):
            emit("ports-probe")
            ack("ports-probe", options["nonce"])
        require(ops.inspector(state, options["addresses"], False)["firewall"] == facts["firewall"], "NETWORK_STATE_CHANGED")
        checkpoint = ops.checkpoint(state, owner); checkpoint["hostname"] = options["hostname"]
        current = ops.prepare(state, archive, options, owner)
        I.atomic_write(TRANSACTION, json.dumps(checkpoint, sort_keys=True))
        committed = False
        try:
            ops.start_tls(); certificate = ops.certificate(options["hostname"], state["port"])
            emit("certificate-ready", fingerprint=certificate["fingerprint"], port=state["port"])
            ack("certificate-ready", options["nonce"])
            require(ops.inspector(state, options["addresses"], True)["firewall"] == facts["firewall"], "NETWORK_STATE_CHANGED")
            new_state = ops.cutover(checkpoint, current)
            ops.inspector(new_state | {"https_pending": False}, options["addresses"], True)
            emit("cutover-ready", fingerprint=certificate["fingerprint"], port=state["port"])
            ack("cutover-ready", options["nonce"])
            ops.commit(checkpoint, current, new_state)
            committed = True
            emit("result", status="SUCCESS", operation="https-enabled", changes="studio-tls-and-ufw" if added else "studio-tls-only", firewall_added=added)
        except BaseException as original:
            if committed: raise HttpsError("HTTPS_COMMITTED_RESULT_UNCONFIRMED_CHECK_AGAIN") from None
            try: ops.rollback(checkpoint)
            except BaseException: raise HttpsError("MANUAL_REVIEW_REQUIRED_CHECKPOINT_RETAINED") from None
            raise HttpsError("HTTPS_COMMITTED_RECOVERED_CHECK_AGAIN" if checkpoint["stage"] == "public-verified" else "HTTPS_FAILED_PRIOR_CONFIGURATION_RESTORED") from original


def entry(options=None, archive=b"", source=""):
    def interrupted(_number, _frame): raise HttpsError("HTTPS_INTERRUPTED")
    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT): signal.signal(sig, interrupted)
    os.umask(0o077)
    progress = Progress(event)
    checking = isinstance(options, dict) and options.get("mode") == "check"
    try:
        if checking: progress.mark("CHECK_ROOT")
        require(os.geteuid() == 0, "ROOT_REQUIRED")
        if options is None:
            action = sys.argv[1] if len(sys.argv) == 2 else "invalid"
            require(action in ("recover", "monitor"), "INVALID_ACTION")
            if action == "recover":
                if not TRANSACTION.exists(): return 0
                try:
                    with I.install_lock(): Operations(source).rollback(private_json(TRANSACTION))
                except I.InstallError as e:
                    if e.code == "INSTALL_ALREADY_RUNNING": return 0
                    raise
            else:
                current = owned(); require(current and current["committed"], "TLS_MONITOR_NOT_CONFIGURED")
                https_health(current["hostname"], "127.0.0.1")
            return 0
        if checking: progress.mark("CHECK_INPUT")
        require(isinstance(options, dict) and set(options) == {"server_ip", "additional_ip", "hostname", "mode", "confirmation", "nonce"}, "INVALID_INPUT")
        require(re.fullmatch(r"[0-9a-f]{64}", options["nonce"] or ""), "INVALID_NONCE")
        normalized = inputs({k: v for k, v in options.items() if k != "nonce"}); normalized["nonce"] = options["nonce"]
        if normalized["mode"] == "check":
            progress.mark("CHECK_PENDING")
            require(not TRANSACTION.exists(), "PENDING_TLS_RECOVERY_REQUIRED")
            progress.mark("CHECK_STATE")
            state = I.load_state(); require(state and state.get("current"), "STUDIO_INSTALL_REQUIRED")
            progress.mark("CHECK_TLS_OWNER")
            owner = owned()
            progress.mark("CHECK_TRANSPORT")
            require(bool(owner and owner["committed"]) == bool(I.https_settings(state)), "HTTPS_STATE_DISAGREES")
            require(not owner or owner["hostname"] == normalized["hostname"], "HTTPS_HOSTNAME_CHANGE_REQUIRES_REVIEW")
            facts = snapshot(state, normalized["addresses"], bool(owner and owner["committed"]), allow_stopped=True, progress=progress.mark, interface_report=progress.interfaces)
            progress.mark("CHECK_LOCAL_TLS")
            certificate = https_health(normalized["hostname"], "127.0.0.1") if owner and owner["committed"] and not facts["tls_stopped"] else None
            status = "CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED" if not owner or not owner["committed"] else "CHECK_MANAGED_TLS_STOPPED" if facts["tls_stopped"] else "CHECK_EXISTING_HTTPS"
            if owner and owner["committed"] and facts.get("firewall_plan"): status = "CHECK_FIREWALL_PLAN_REQUIRED"
            progress.mark("CHECK_COMPLETE")
            event("result", status=status, arch=facts["arch"], changes="none", certificate=certificate, port=state["port"], firewall_plan=facts.get("firewall_plan", []))
        else: apply(normalized, archive, source)
        return 0
    except BaseException as error:
        code = error.code if isinstance(error, I.InstallError) else str(error) if isinstance(error, HttpsError) or isinstance(error, ValueError) and str(error) in INPUT_ERROR_CODES else "HTTPS_OPERATION_FAILED"
        if not re.fullmatch(r"[A-Z0-9_]+", code): code = "HTTPS_OPERATION_FAILED"
        if options is None:
            print("STUDIO_TLS_ATTENTION_" + code, flush=True)
        else:
            fields = {"phase": progress.phase, "error_kind": "EXPECTED" if isinstance(error, (HttpsError, I.InstallError)) else error_kind(error)} if checking and progress.phase else {}
            event("result", status="FAILED", code=code, **fields)
        return 1
