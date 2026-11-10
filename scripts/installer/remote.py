#!/usr/bin/env python3
"""Root-only installer. Never changes VPN, network, package manager or proxy.

Only Studio paths and units below are mutable. Exceptions/results are safe codes.
"""
import argparse
import contextlib
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from types import SimpleNamespace
try:
    from transport_settings import https_settings, https_origin
except ModuleNotFoundError:  # Importlib-based CI fixtures load this file directly.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from transport_settings import https_settings, https_origin

BASE = Path("/opt/studio1925")
CONFIG = Path("/etc/studio1925")
DATA = Path("/var/lib/studio1925")
BACKUPS = Path("/var/backups/studio1925")
CACHE = Path("/var/cache/studio1925")
UNIT = Path("/etc/systemd/system/studio1925.service")
LOCK = Path("/run/lock/studio1925-install.lock")
USER = "studio1925"
SERVICE = "studio1925.service"
NODE_VERSION = "v24.12.0"


class InstallError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise InstallError(code)


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args, code="COMMAND_FAILED", timeout=60, check=True):
    try:
        result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, check=False)
    except (OSError, subprocess.SubprocessError):
        raise InstallError(code) from None
    if check and result.returncode:
        raise InstallError(code)
    return result.stdout.strip() if check else result.returncode


def host_facts():
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(sys.version_info >= (3, 12), "PYTHON_3_12_REQUIRED")
    values = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
    except OSError:
        raise InstallError("OS_UNAVAILABLE") from None
    require(values.get("ID") == "ubuntu" and values.get("VERSION_ID") == "24.04", "UBUNTU_24_04_REQUIRED")
    arch = {"x86_64": "x64", "aarch64": "arm64"}.get(platform.machine())
    require(arch, "ARCH_UNSUPPORTED")
    require(Path("/run/systemd/system").is_dir(), "SYSTEMD_REQUIRED")
    for command in ("systemctl", "systemd-run", "useradd", "findmnt"):
        require(shutil.which(command, path="/usr/sbin:/usr/bin:/sbin:/bin"), "BASE_TOOL_MISSING")
    require(run(["systemctl", "is-system-running"], check=False) in (0, 1), "SYSTEMD_UNAVAILABLE")
    for path in (BASE, DATA, BACKUPS, CACHE):
        target = path if path.exists() else path.parent
        filesystem = run(["findmnt", "--noheadings", "--output", "FSTYPE", "--target", target], "STORAGE_TYPE_UNAVAILABLE")
        require(filesystem in ("ext4", "xfs", "btrfs", "zfs"), "LOCAL_PERSISTENT_STORAGE_REQUIRED")
    return {"status": "CONNECTED", "arch": arch, "os": "ubuntu", "os_version": "24.04"}


@contextlib.contextmanager
def install_lock():
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077,
                "UNSAFE_LOCK")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("INSTALL_ALREADY_RUNNING") from None
        yield
    finally:
        os.close(fd)  # Keep the inode: unlinking a lock could allow two lock owners.


def atomic_write(path, contents, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".studio-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def owned_directory(path, uid=0, gid=0, mode=0o700, create=False):
    require(path.parent.resolve() == path.parent, "PATH_SYMLINK_REFUSED")
    if create and not path.exists():
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022,
            "UNSAFE_DIRECTORY")
    require(path.resolve() == path, "PATH_SYMLINK_REFUSED")
    if uid != 0:
        require(stat.S_IMODE(info.st_mode) == mode, "PRIVATE_DIRECTORY_REQUIRED")


def load_state(allow_pending=False, allow_https_pending=False):
    path = CONFIG / "state.json"
    if not path.exists():
        # Never adopt another application's account/files/unit.
        require(not any(p.exists() or p.is_symlink() for p in (BASE, CONFIG, DATA, BACKUPS, CACHE, UNIT)), "UNMANAGED_PATH_COLLISION")
        try:
            pwd.getpwnam(USER)
        except KeyError:
            return None
        raise InstallError("UNMANAGED_USER_COLLISION")
    owned_directory(CONFIG)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, "UNSAFE_STATE")
    state = json.loads(path.read_text())
    require(state.get("format") == 1 and state.get("managed_by") == "studio-installer", "UNMANAGED_STATE")
    require(not state.get("https_pending") or allow_https_pending, "HTTPS_TRANSACTION_PENDING")
    try: https_settings(state)
    except ValueError: raise InstallError("UNSAFE_HTTPS_STATE") from None
    phases = ("ready", "failed-first", "snapshotting", "backup-pending", "updating") if allow_pending else ("ready", "failed-first")
    require(state.get("phase") in phases, "INTERRUPTED_INSTALL_REQUIRES_REVIEW")
    if state.get("current"):
        require(isinstance(state.get("port"), int) and (state["port"] == 3000 or 3100 <= state["port"] <= 3199), "UNSAFE_STATE")
        require(re.fullmatch(r"[0-9a-f]{40}-[0-9a-f]{16}-[0-9a-f]{8}", state["current"]), "UNSAFE_STATE")
        require(UNIT.is_file() and not UNIT.is_symlink(), "UNIT_CHANGED_OUTSIDE_INSTALLER")
        if not (allow_pending and state["phase"] == "updating") and not (allow_https_pending and state.get("https_pending")):
            require(digest(UNIT) == state.get("unit_sha256"), "UNIT_CHANGED_OUTSIDE_INSTALLER")
    return state


def store_state(state):
    atomic_write(CONFIG / "state.json", json.dumps(state, sort_keys=True))


def managed_account(state):
    account = pwd.getpwnam(USER)
    require(account.pw_uid != 0 and account.pw_shell == "/usr/sbin/nologin", "UNSAFE_APPLICATION_USER")
    require(account.pw_uid == state.get("uid") and account.pw_gid == state.get("gid"), "APPLICATION_IDENTITY_CHANGED")
    require(set(os.getgrouplist(USER, account.pw_gid)) == {account.pw_gid}, "EXTRA_APPLICATION_GROUPS_REFUSED")
    return account


def private_environment():
    path = CONFIG / "server.env"
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            "UNSAFE_ENVIRONMENT")
    return path.read_text()


def inspect_archive(archive_path, expected_sha, version, arch):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha) and digest(archive_path) == expected_sha, "ARTIFACT_CHECKSUM_MISMATCH")
    require(re.fullmatch(r"[0-9a-f]{40}", version), "INVALID_VERSION")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) < 200000, "ARTIFACT_TOO_MANY_FILES")
        names = set()
        total = 0
        for member in members:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts and member.name not in names, "UNSAFE_ARCHIVE_PATH")
            require(member.name == "manifest.json" or name.parts[0] == "root", "UNEXPECTED_ARCHIVE_FILE")
            require(member.isdir() or member.isfile(), "ARCHIVE_LINK_OR_DEVICE_REFUSED")
            require(not member.mode & 0o6000, "UNSAFE_ARCHIVE_MODE")
            names.add(member.name)
            total += member.size
        require(total < 4 * 1024**3, "ARTIFACT_TOO_LARGE")
        manifest_member = archive.getmember("manifest.json")
        require(manifest_member.size < 100000, "INVALID_MANIFEST")
        manifest = json.load(archive.extractfile(manifest_member))
        require(manifest.get("format") == 1 and manifest.get("mode") == "server", "INVALID_MANIFEST")
        require(manifest.get("version") == version, "VERSION_MISMATCH")
        require(manifest.get("os") == "ubuntu" and manifest.get("os_version") == "24.04", "ARTIFACT_OS_MISMATCH")
        require(manifest.get("arch") == arch, "ARTIFACT_ARCH_MISMATCH")
        require(manifest.get("node") == NODE_VERSION and manifest.get("node_abi") == "137", "ARTIFACT_NODE_MISMATCH")
        require(manifest.get("unpacked_bytes") == total - manifest_member.size, "INVALID_MANIFEST_SIZE")
        return manifest


def ipv6_available():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::", 0))
        return True
    except OSError:
        # Python may support IPv6 while it is disabled on this particular VPS.
        return False


def choose_port(preferred=None, loopback=False):
    v6_enabled = not loopback and ipv6_available()
    for port in ((preferred,) if preferred is not None else (3000, *range(3100, 3200))):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1" if loopback else "0.0.0.0", port))
                if v6_enabled:
                    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as v6:
                        v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        v6.bind(("::", port))
                return port
            except OSError:
                continue
    raise InstallError("NO_FREE_LOOPBACK_PORT")


def service_text(release, port, https=None):
    if https: https_origin(https)  # Validate before rendering any unit.
    bind = "127.0.0.1" if https else "::" if ipv6_available() else "0.0.0.0"
    return f"""# Managed by Studio installer; host VPN/network/proxy are out of scope.
[Unit]
Description=Studio 19.25 SERVER
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=studio1925
Group=studio1925
RootDirectory={release}/root
WorkingDirectory=/app
MountAPIVFS=true
BindPaths={DATA}:/data {CACHE}:/app/.next-server/cache {DATA}/photos:/app/public/images
EnvironmentFile={CONFIG}/server.env
Environment=STUDIO_TELEGRAM_WORKER=1
BindReadOnlyPaths=-/etc/resolv.conf:/etc/resolv.conf
ExecStart=/usr/bin/node /app/node_modules/next/dist/bin/next start --hostname {bind} --port {port}
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateDevices=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectProc=invisible
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryAccounting=true
CPUAccounting=true
IOAccounting=true
CPUWeight=50
IOWeight=50
OOMScoreAdjust=500

[Install]
WantedBy=multi-user.target
"""


def environment_text(port, origin=None, https=None):
    public = https_origin(https) if https else origin or f"http://127.0.0.1:{port}"
    return ("APP_MODE=server\nDEPLOY_TARGET=node\nNODE_ENV=production\nNEXT_TELEMETRY_DISABLED=1\n"
            "SQLITE_PATH=/data/studio.sqlite\nSQLITE_BUSY_TIMEOUT_MS=1000\n"
            f"API_PUBLIC_ORIGIN={public}\nAPI_TRUST_PROXY={'true' if https else 'false'}\nAPI_ALLOW_INSECURE_TEST_HTTP={'false' if https else 'true'}\n")


def helper(release, arguments, code, data_dir=None):
    name = "studio1925-task-" + uuid.uuid4().hex
    command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=" + name,
               "--property=Type=exec", "--property=User=studio1925", "--property=Group=studio1925",
               "--property=RootDirectory=" + str(release / "root"), "--property=WorkingDirectory=/app",
               "--property=BindPaths=" + str(data_dir or DATA) + ":/data " + str(BACKUPS) + ":/backups",
               "--property=RuntimeMaxSec=120", "--property=UMask=0077", "--property=NoNewPrivileges=true",
               "--property=CapabilityBoundingSet=", "--property=PrivateDevices=true", "--property=PrivateTmp=true",
               "--property=ProtectSystem=strict", "--property=ProtectHome=true", "--property=ProtectProc=invisible",
               "--property=CPUWeight=25", "--property=IOWeight=25", "--property=Nice=10", "--property=OOMScoreAdjust=500",
               "--setenv=APP_MODE=server", "--setenv=SQLITE_PATH=/data/studio.sqlite",
               "/usr/bin/node", "--conditions=react-server", *arguments]
    try:
        return run(command, code, timeout=150)
    finally:
        run(["systemctl", "stop", name + ".service"], check=False, timeout=20)


def schema(release, data_dir=None):
    value = helper(release, ["scripts/installer/schema.mjs"], "SCHEMA_CHECK_FAILED", data_dir=data_dir)
    require(re.fullmatch(r"[0-9a-f]{64}", value), "SCHEMA_CHECK_FAILED")
    return value


def health(port, timeout=35):
    deadline = time.monotonic() + timeout
    successes = 0
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("GET", "/api/health", headers={"Connection": "close"})
            response = connection.getresponse()
            ok = response.status == 200 and json.loads(response.read(1024)) == {"status": "ok"}
            ok = ok and run(["systemctl", "is-active", SERVICE], check=False) == 0
            successes = successes + 1 if ok else 0
            if successes == 3:
                return
        except (OSError, ValueError, http.client.HTTPException):
            successes = 0
        finally:
            connection.close()
        time.sleep(1)
    raise InstallError("APP_HEALTH_FAILED")


def api_health(port):
    import datetime
    date = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)).strftime("%Y-%m-%d")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/api/availability?date=" + date, headers={"X-Studio-Client-IP": "127.0.0.1"})
        response = connection.getresponse()
        value = json.loads(response.read(65536))
        require(response.status == 200 and value.get("date") == date and value.get("resourceId") == "studio-19-25"
                and value.get("timezone") == "Europe/Moscow" and isinstance(value.get("busy"), list), "PRODUCTION_API_UNAVAILABLE")
    finally:
        connection.close()


def maintenance():
    from maintenance import Maintenance
    return Maintenance(SimpleNamespace(**globals()))


def install(archive_path, checksum, version, origin_host=None, receipt=None, restore_bundle=None, confirmed=False):
    facts = host_facts()
    manifest = inspect_archive(archive_path, checksum, version, facts["arch"])
    state = load_state(allow_pending=True)
    held_state = state
    if state and state.get("phase") in ("snapshotting", "backup-pending"):
        state = state["pending"]["prior"]
    if state:
        account = managed_account(state)
        for path in (BASE, BASE / "releases"):
            owned_directory(path)
        for path in (DATA, BACKUPS, CACHE):
            owned_directory(path, account.pw_uid, account.pw_gid)
        if state.get("current") and not (restore_bundle and confirmed):
            expected = environment_text(state["port"], state.get("origin"), https_settings(state))
            legacy = environment_text(state["port"]).replace("API_ALLOW_INSECURE_TEST_HTTP=true\n", "")
            require(private_environment() in ((expected,) if https_settings(state) else (expected, legacy)), "ENVIRONMENT_CHANGED_OUTSIDE_INSTALLER")
    if restore_bundle:
        from backup import validate_bundle
        source_https = https_settings(validate_bundle(restore_bundle))
        require(not source_https or https_settings(state), "HTTPS_TARGET_REQUIRED_FOR_RESTORE")
    if state and state.get("current") and state.get("version") == version and not restore_bundle:
        try:
            health(state["port"], timeout=5)
        except InstallError as error:
            if error.code != "APP_HEALTH_FAILED":
                raise
            # An unhealthy/stopped instance is redeployed through the backup path.
        else:
            api_health(state["port"])
            helper(BASE / "releases" / state["current"], ["scripts/installer/acceptance.mjs"], "TECHNICAL_ACCEPTANCE_FAILED")
            run(["systemctl", "enable", SERVICE], "SERVICE_ENABLE_FAILED")
            return {"status": "SUCCESS", "version": version, "operation": "already-current", "migrations": "unchanged",
                    "service": "active-enabled", "health": 200, "port": state["port"], "url": state.get("origin", f"http://127.0.0.1:{state['port']}"), "technical_acceptance": "passed", "https": https_settings(state)}
    if state and state.get("current"):
        if restore_bundle and confirmed and receipt and receipt.get("unavailable") is True:
            # Explicit restore always preserves the whole original data directory.
            # A corrupt DB/unavailable offsite write must not be replaced silently.
            pass
        else:
            state = maintenance().check_receipt(held_state, receipt, "restore" if restore_bundle else "update")
    require(not restore_bundle or confirmed, "RESTORE_CONFIRMATION_REQUIRED")
    # Conservative admission thresholds, not an application peak-memory guarantee.
    memory = re.search(r"^MemAvailable:\s+(\d+)", Path("/proc/meminfo").read_text(), re.M)
    require(memory and int(memory[1]) >= 512 * 1024, "MEMORY_HEADROOM_BELOW_512_MIB")
    for path in (BASE.parent, DATA.parent, BACKUPS.parent):
        needed = manifest["unpacked_bytes"] * 2 + archive_path.stat().st_size + 512 * 1024**2
        if (DATA / "studio.sqlite").exists():
            needed += sum(p.stat().st_size for p in DATA.iterdir() if p.is_file()) * 3
        require(shutil.disk_usage(path).free >= needed, "DISK_HEADROOM_INSUFFICIENT")
    old_state = dict(state) if state else None
    old_release = BASE / "releases" / state["current"] if state and state.get("current") else None
    old_unit = UNIT.read_text() if old_release else None
    old_env = private_environment() if old_release else None
    old_schema = None
    restored_from = None
    recovery = None
    modified = False
    try:
        if not state:
            run(["useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", USER], "USER_CREATE_FAILED")
            CONFIG.mkdir(mode=0o700)
            account = pwd.getpwnam(USER)
            state = {"format": 1, "managed_by": "studio-installer", "phase": "failed-first", "current": None,
                     "uid": account.pw_uid, "gid": account.pw_gid, "instance": uuid.uuid4().hex}
            store_state(state)
        account = managed_account(state)
        for path in (BASE, BASE / "releases"):
            owned_directory(path, mode=0o755, create=True)
        for path in (DATA, BACKUPS, CACHE):
            owned_directory(path, account.pw_uid, account.pw_gid, create=True)
        release_id = version + "-" + checksum[:16] + "-" + uuid.uuid4().hex[:8]
        release = BASE / "releases" / release_id
        release.mkdir(mode=0o755)
        with tarfile.open(archive_path, "r:gz") as archive:
            archive.extractall(release, filter="data")
        # Code/root filesystem never writable by the application.
        for entry in release.rglob("*"):
            os.chmod(entry, 0o755 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o644)
        require(run([release / "root/usr/bin/node", "--version"]) == NODE_VERSION, "RUNTIME_UNAVAILABLE")
        require(helper(release, ["--version"], "SANDBOX_RUNTIME_UNAVAILABLE") == NODE_VERSION, "SANDBOX_RUNTIME_UNAVAILABLE")
        for name, expected in manifest["migrations"].items():
            require(re.fullmatch(r"\d{4}_[a-z0-9_]+\.sql", name) and digest(release / "root/app/migrations/sqlite" / name) == expected, "MIGRATION_CHECKSUM_MISMATCH")
        # Test actual native SQLite in the packaged root before touching the service.
        helper(release, ["-e", "const D=require('better-sqlite3');const d=new D(':memory:');d.prepare('SELECT 1').get();d.close()"], "NATIVE_SQLITE_UNAVAILABLE")
        maintenance().persistent(release, account)
        if old_release and not restore_bundle:
            helper(old_release, ["scripts/database.mjs", "backup", "--to", "/backups/online-" + uuid.uuid4().hex + ".sqlite"], "BACKUP_FAILED")
            old_schema = schema(old_release)
        elif old_release:
            try:
                old_schema = schema(old_release)
            except InstallError:
                old_schema = None
        state["phase"] = "updating"
        store_state(state)
        modified = True
        if old_release:
            run(["systemctl", "disable", SERVICE], "SERVICE_DISABLE_FAILED")
            run(["systemctl", "stop", SERVICE], "SERVICE_STOP_FAILED", timeout=45)
            if not restore_bundle:
                require(schema(old_release) == old_schema, "SCHEMA_CHANGED_DURING_UPDATE")
                helper(old_release, ["scripts/database.mjs", "backup", "--to", "/backups/checkpoint-" + uuid.uuid4().hex + ".sqlite"], "BACKUP_FAILED")
        elif not restore_bundle:
            helper(release, ["scripts/database.mjs", "init"], "DATABASE_INIT_FAILED")
        if restore_bundle:
            stage, restored_from = maintenance().stage_restore(restore_bundle, release, account)
            recovery = maintenance().swap_restore(stage)
        else:
            helper(release, ["scripts/database.mjs", "migrate"], "MIGRATION_FAILED")
        helper(release, ["scripts/database.mjs", "check"], "DATABASE_CHECK_FAILED")
        transport = https_settings(state)
        port = choose_port(state.get("port") if old_release else None, loopback=bool(transport))
        if transport:
            origin = https_origin(transport)
        elif origin_host:
            import ipaddress
            address = ipaddress.ip_address(origin_host)
            origin = f"http://{'[' + address.compressed + ']' if address.version == 6 else address.compressed}:{port}"
        else:
            origin = state.get("origin") or f"http://127.0.0.1:{port}"
        atomic_write(CONFIG / "server.env", environment_text(port, origin, transport))
        atomic_write(UNIT, service_text(release, port, transport), 0o644)
        run(["systemctl", "daemon-reload"], "SYSTEMD_RELOAD_FAILED")
        run(["systemctl", "reset-failed", SERVICE], check=False)
        run(["systemctl", "start", SERVICE], "APP_START_FAILED", timeout=45)
        health(port)
        api_health(port)
        helper(release, ["scripts/installer/acceptance.mjs"], "TECHNICAL_ACCEPTANCE_FAILED")
        run(["systemctl", "enable", SERVICE], "SERVICE_ENABLE_FAILED")
        state.update(phase="ready", current=release_id, previous=old_state.get("current") if old_state else None,
                     version=version, archive_sha256=checksum, port=port, origin=origin,
                     restored_from=restored_from["nonce"] if restored_from else None, unit_sha256=digest(UNIT))
        state.pop("pending", None)
        store_state(state)
        return {"status": "SUCCESS", "version": version, "operation": "restore" if restored_from else ("update" if old_release else "install"),
                "migrations": "verified", "service": "active-enabled", "health": 200, "port": port, "url": origin, "technical_acceptance": "passed", "https": transport}
    except BaseException as error:
        # SIGTERM/HUP are converted to InstallError; never delete or restore customer data.
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        rollback = "not-needed"
        if modified:
            run(["systemctl", "stop", SERVICE], check=False, timeout=45)
            run(["systemctl", "disable", SERVICE], check=False)
            rollback = "manual-required" if old_release else "first-install-stopped"
            try:
                if recovery:
                    maintenance().undo_restore(recovery)
                # No automatic DB restore. A committed new migration blocks code rollback.
                if old_release and old_schema and schema(old_release) == old_schema:
                    helper(old_release, ["scripts/database.mjs", "migrate"], "OLD_SCHEMA_INCOMPATIBLE")
                    helper(old_release, ["scripts/database.mjs", "check"], "OLD_DATABASE_CHECK_FAILED")
                    atomic_write(UNIT, old_unit, 0o644)
                    atomic_write(CONFIG / "server.env", old_env)
                    run(["systemctl", "daemon-reload"])
                    run(["systemctl", "reset-failed", SERVICE], check=False)
                    run(["systemctl", "start", SERVICE], timeout=45)
                    health(old_state["port"])
                    run(["systemctl", "enable", SERVICE])
                    store_state(old_state)
                    rollback = "restored-and-health-verified"
                elif not old_release:
                    state["phase"] = "failed-first"
                    store_state(state)
            except Exception:
                run(["systemctl", "stop", SERVICE], check=False, timeout=45)
                run(["systemctl", "disable", SERVICE], check=False)
                rollback = "manual-required"
        code = error.code if isinstance(error, InstallError) else "INSTALL_FAILED"
        raise InstallError(code + ";rollback=" + rollback) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--sha256")
    parser.add_argument("--version")
    parser.add_argument("--action", choices=("info", "snapshot", "abort"))
    parser.add_argument("--purpose", choices=("daily", "update", "restore"), default="daily")
    parser.add_argument("--hold", action="store_true")
    parser.add_argument("--nonce")
    parser.add_argument("--origin-host")
    parser.add_argument("--receipt")
    parser.add_argument("--restore-bundle", type=Path)
    parser.add_argument("--confirm-restore", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    os.nice(10)
    def interrupted(_number, _frame):
        raise InstallError("INTERRUPTED")
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        if args.probe:
            result = host_facts()
        elif args.action:
            with install_lock():
                host_facts()
                m = maintenance()
                if args.action == "info":
                    result = m.info()
                elif args.action == "abort":
                    result = m.abort(args.nonce)
                else:
                    m.snapshot(args.purpose, args.hold)
                    return 0
        else:
            require(args.archive and args.sha256 and args.version, "INVALID_INSTALL_ARGUMENTS")
            with install_lock():
                result = install(args.archive, args.sha256, args.version, args.origin_host,
                                 json.loads(args.receipt) if args.receipt else None, args.restore_bundle, args.confirm_restore)
        print(json.dumps(result))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, InstallError) else "INSTALL_FAILED"
        if type(error).__module__ == "backup" and type(error).__name__ == "BackupError" and re.fullmatch(r"[A-Z0-9_]+", str(error)):
            code = str(error)
        print(json.dumps({"status": "FAILED", "code": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
