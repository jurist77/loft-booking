#!/usr/bin/env python3
"""Runner-side password SSH transport. Never print raw SSH output or secrets."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SAFE_CODES = {
    "ROOT_REQUIRED", "UBUNTU_24_04_REQUIRED", "ARCH_UNSUPPORTED", "SYSTEMD_REQUIRED", "BASE_TOOL_MISSING",
    "SYSTEMD_UNAVAILABLE", "ARTIFACT_CHECKSUM_MISMATCH", "ARTIFACT_ARCH_MISMATCH", "ARTIFACT_OS_MISMATCH",
    "ARTIFACT_NODE_MISMATCH", "VERSION_MISMATCH", "NATIVE_SQLITE_UNAVAILABLE", "RUNTIME_UNAVAILABLE",
    "MEMORY_HEADROOM_BELOW_512_MIB", "DISK_HEADROOM_INSUFFICIENT", "INSTALL_ALREADY_RUNNING",
    "UNMANAGED_PATH_COLLISION", "UNMANAGED_USER_COLLISION", "UNMANAGED_STATE", "UNSAFE_STATE",
    "UNIT_CHANGED_OUTSIDE_INSTALLER", "INTERRUPTED_INSTALL_REQUIRES_REVIEW", "RELEASE_ALREADY_EXISTS_REQUIRES_REVIEW",
    "PATH_SYMLINK_REFUSED", "UNSAFE_DIRECTORY", "PRIVATE_DIRECTORY_REQUIRED", "UNSAFE_APPLICATION_USER",
    "DATABASE_INIT_FAILED", "MIGRATION_FAILED", "DATABASE_CHECK_FAILED", "BACKUP_FAILED", "SCHEMA_CHECK_FAILED",
    "SCHEMA_CHANGED_DURING_UPDATE", "APP_START_FAILED", "APP_HEALTH_FAILED", "NO_FREE_LOOPBACK_PORT",
    "SERVICE_ENABLE_FAILED", "SERVICE_STOP_FAILED", "SERVICE_DISABLE_FAILED", "SYSTEMD_RELOAD_FAILED",
    "MIGRATION_CHECKSUM_MISMATCH", "INVALID_MANIFEST", "INVALID_MANIFEST_SIZE", "UNSAFE_ARCHIVE_PATH",
    "ARCHIVE_LINK_OR_DEVICE_REFUSED", "INSTALL_FAILED", "INTERRUPTED", "UNSAFE_LOCK",
}
ROLLBACKS = {"not-needed", "manual-required", "first-install-stopped", "restored-and-health-verified"}

# Fixed bootstrap, no interpolated IP/password or shell command in its body.
# Files are private ephemeral upload files; the SSH password never crosses stdin.
BOOTSTRAP = r'''
import json, os, pathlib, shutil, signal, subprocess, sys, tempfile
child = None
def interrupted(signum, frame):
    raise InterruptedError()
for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(sig, interrupted)
def exact(stream, destination, size):
    while size:
        chunk = stream.read(min(size, 1024*1024))
        if not chunk: raise ValueError()
        destination.write(chunk)
        size -= len(chunk)
    destination.flush()
    os.fsync(destination.fileno())
try:
    if os.geteuid() != 0: raise ValueError()
    os.umask(0o077)
    source = sys.stdin.buffer
    header = json.loads(source.readline(4096))
    code_size, archive_size = header['code_size'], header['archive_size']
    if not 0 < code_size < 100000 or not 0 < archive_size < 2*1024**3: raise ValueError()
    if shutil.disk_usage('/var/tmp').free < archive_size + 256*1024**2: raise ValueError()
    with tempfile.TemporaryDirectory(prefix='studio1925-upload-', dir='/var/tmp') as folder:
        code = pathlib.Path(folder)/'installer.py'
        archive = pathlib.Path(folder)/'server.tar.gz'
        with code.open('wb') as output: exact(source, output, code_size)
        with archive.open('wb') as output: exact(source, output, archive_size)
        if source.read(1): raise ValueError()
        child = subprocess.Popen(['/usr/bin/python3', str(code), '--archive', str(archive),
                                  '--sha256', header['sha256'], '--version', header['version']],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                                 env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        try:
            output, _ = child.communicate(timeout=1200)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try: child.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL); child.wait()
        sys.stdout.buffer.write(output)
        sys.exit(child.returncode)
except (Exception, KeyboardInterrupt):
    print('{"status":"FAILED","code":"UPLOAD_OR_INSTALL_INTERRUPTED"}')
    sys.exit(1)
'''


class DeployError(Exception):
    pass


def server_ip(value):
    try:
        if "%" in value:
            raise ValueError()
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            raise ValueError()
        return address.compressed
    except ValueError:
        raise DeployError("INVALID_SERVER_IP") from None


class SSH:
    def __init__(self, address, password, user="root", port=22):
        self.address, self.password, self.user, self.port = address, password, user, port

    def arguments(self, command):
        return ["sshpass", "-e", "ssh", "-F", "/dev/null", "-T", "-p", str(self.port),
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no", "-o", "LogLevel=ERROR",
                "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
                "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                self.user + "@" + self.address, command]

    def execute(self, command, stream=None, timeout=45):
        child = None
        try:
            child = subprocess.Popen(self.arguments(command), stdin=stream, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, start_new_session=True,
                                     env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "SSHPASS": self.password})
            output, _ = child.communicate(timeout=timeout)
            if child.returncode == 5:
                raise DeployError("SSH_AUTH_FAILED")
            if child.returncode == 255:
                raise DeployError("SSH_CONNECTION_FAILED")
            if len(output) > 10000:
                raise DeployError("REMOTE_PROTOCOL_FAILED")
            try:
                value = json.loads(output)
                if not isinstance(value, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise DeployError("REMOTE_PROTOCOL_FAILED") from None
            if child.returncode or value.get("status") == "FAILED":
                code, _, rollback = str(value.get("code", "")).partition(";rollback=")
                safe = code if code in SAFE_CODES else "REMOTE_INSTALL_FAILED"
                if rollback in ROLLBACKS:
                    safe += ";rollback=" + rollback
                raise DeployError(safe)
            return value
        except FileNotFoundError:
            raise DeployError("SSH_TOOLS_MISSING") from None
        except (OSError, subprocess.SubprocessError):
            raise DeployError("SSH_TIMEOUT_OR_TRANSPORT_FAILED") from None
        finally:
            if child and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()


def safe_result(value, version):
    if (value.get("status") != "SUCCESS" or value.get("version") != version or
            value.get("health") != 200 or value.get("operation") not in ("install", "update", "already-current") or
            value.get("migrations") not in ("verified", "unchanged") or
            value.get("service") not in ("active", "active-enabled") or
            not re.fullmatch(r"127\.0\.0\.1:(?:3000|31\d\d)", str(value.get("listener", "")))):
        raise DeployError("REMOTE_PROTOCOL_FAILED")
    return {key: value[key] for key in ("status", "version", "operation", "migrations", "service", "health", "listener")}


def deploy(address, artifacts, version, password):
    require_version = re.fullmatch(r"[0-9a-f]{40}", version)
    if not require_version:
        raise DeployError("INVALID_VERSION")
    ssh = SSH(server_ip(address), password)
    with (HERE / "remote.py").open("rb") as source:
        probe = ssh.execute("python3 - --probe", source)
    if probe.get("status") != "CONNECTED" or probe.get("arch") not in ("x64", "arm64"):
        raise DeployError("REMOTE_PROTOCOL_FAILED")
    print("SSH_CONNECTED; Ubuntu 24.04; architecture=" + probe["arch"], flush=True)
    archive = artifacts / ("studio-server-" + probe["arch"]) / "server.tar.gz"
    checksum_path = Path(str(archive) + ".sha256")
    if not archive.is_file() or not checksum_path.is_file():
        raise DeployError("ARTIFACT_MISSING")
    checksum = checksum_path.read_text().strip()
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
            raise DeployError("ARTIFACT_CHECKSUM_MISMATCH")
    # tempfile here contains only code/archive, never password. It bounds memory usage.
    import tempfile
    import shutil
    import shlex
    with tempfile.TemporaryFile() as payload:
        code = (HERE / "remote.py").read_bytes()
        header = {"code_size": len(code), "archive_size": archive.stat().st_size, "sha256": checksum, "version": version}
        payload.write(json.dumps(header).encode() + b"\n")
        payload.write(code)
        with archive.open("rb") as stream:
            shutil.copyfileobj(stream, payload)
        payload.seek(0)
        value = ssh.execute("python3 -c " + shlex.quote(BOOTSTRAP), payload, timeout=1800)
    return safe_result(value, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        password = os.environ.get("STUDIO_SSH_PASSWORD", "")
        if not password:
            raise DeployError("STUDIO_SSH_PASSWORD_MISSING")
        result = deploy(os.environ.get("STUDIO_SERVER_IP", ""), args.artifacts, args.version, password)
        message = json.dumps(result)
        print(message)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as stream:
                stream.write("## Studio 19.25 — SUCCESS\n\nSSH: connected\n\n```json\n" + message + "\n```\n\n")
                stream.write("Listener is private. No public HTTPS was configured. Use a verified SSH local tunnel to this listener; replace `<server_ip>` with your workflow input.\n\n")
                port = result["listener"].split(":")[1]
                stream.write(f"`ssh -N -T -L 127.0.0.1:{port}:127.0.0.1:{port} root@<server_ip>`\n\nOpen `http://127.0.0.1:{port}` on the same device.\n")
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, DeployError) else "DEPLOY_FAILED"
        print("FAILED: " + code)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as stream:
                stream.write("## Studio 19.25 — FAILED\n\nSafe error code: `" + code + "`. No public HTTPS configured.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
