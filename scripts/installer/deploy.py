#!/usr/bin/env python3
"""Runner-side password SSH transport. Never print raw SSH output or secrets."""
import argparse
import contextlib
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from transport_settings import https_settings, https_origin

HERE = Path(__file__).resolve().parent
SAFE_CODES = {
    "ROOT_REQUIRED", "UBUNTU_24_04_REQUIRED", "ARCH_UNSUPPORTED", "SYSTEMD_REQUIRED", "BASE_TOOL_MISSING", "PYTHON_3_12_REQUIRED",
    "SYSTEMD_UNAVAILABLE", "ARTIFACT_CHECKSUM_MISMATCH", "ARTIFACT_ARCH_MISMATCH", "ARTIFACT_OS_MISMATCH",
    "STORAGE_TYPE_UNAVAILABLE", "LOCAL_PERSISTENT_STORAGE_REQUIRED",
    "ARTIFACT_NODE_MISMATCH", "VERSION_MISMATCH", "NATIVE_SQLITE_UNAVAILABLE", "RUNTIME_UNAVAILABLE", "SANDBOX_RUNTIME_UNAVAILABLE",
    "MEMORY_HEADROOM_BELOW_512_MIB", "DISK_HEADROOM_INSUFFICIENT", "INSTALL_ALREADY_RUNNING",
    "UNMANAGED_PATH_COLLISION", "UNMANAGED_USER_COLLISION", "UNMANAGED_STATE", "UNSAFE_STATE",
    "UNIT_CHANGED_OUTSIDE_INSTALLER", "INTERRUPTED_INSTALL_REQUIRES_REVIEW", "RELEASE_ALREADY_EXISTS_REQUIRES_REVIEW",
    "PATH_SYMLINK_REFUSED", "UNSAFE_DIRECTORY", "PRIVATE_DIRECTORY_REQUIRED", "UNSAFE_APPLICATION_USER",
    "APPLICATION_IDENTITY_CHANGED", "EXTRA_APPLICATION_GROUPS_REFUSED", "ENVIRONMENT_CHANGED_OUTSIDE_INSTALLER", "UNSAFE_ENVIRONMENT",
    "DATABASE_INIT_FAILED", "MIGRATION_FAILED", "DATABASE_CHECK_FAILED", "BACKUP_FAILED", "SCHEMA_CHECK_FAILED",
    "SCHEMA_CHANGED_DURING_UPDATE", "APP_START_FAILED", "APP_HEALTH_FAILED", "NO_FREE_LOOPBACK_PORT",
    "SERVICE_ENABLE_FAILED", "SERVICE_STOP_FAILED", "SERVICE_DISABLE_FAILED", "SYSTEMD_RELOAD_FAILED",
    "MIGRATION_CHECKSUM_MISMATCH", "INVALID_MANIFEST", "INVALID_MANIFEST_SIZE", "UNSAFE_ARCHIVE_PATH",
    "ARCHIVE_LINK_OR_DEVICE_REFUSED", "INSTALL_FAILED", "INTERRUPTED", "UNSAFE_LOCK",
    "VERIFIED_OFFSITE_BACKUP_REQUIRED", "RESTORE_CONFIRMATION_REQUIRED", "RESTORE_VERSION_SCHEMA_INCOMPATIBLE",
    "RESTORE_DATABASE_INVALID", "RESTORE_SCHEMA_MISMATCH", "MAINTENANCE_NONCE_MISMATCH", "MAINTENANCE_SCHEMA_CHANGED",
    "INSTALLED_APPLICATION_REQUIRED", "SNAPSHOT_SQLITE_FAILED", "SNAPSHOT_TOO_LARGE", "TECHNICAL_ACCEPTANCE_FAILED",
    "PRODUCTION_API_UNAVAILABLE",
    "MAINTENANCE_SOURCE_ACTIVE",
    "HTTPS_TRANSACTION_PENDING", "UNSAFE_HTTPS_STATE", "HTTPS_TARGET_REQUIRED_FOR_RESTORE",
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
        extra = []
        bundle_size = header.get('bundle_size', 0)
        if bundle_size:
            if not 0 < bundle_size < 2*1024**3 or header.get('confirmed') is not True: raise ValueError()
            bundle = pathlib.Path(folder)/'restore.tar.gz'
            with bundle.open('wb') as output: exact(source, output, bundle_size)
            import hashlib
            with bundle.open('rb') as incoming:
                if hashlib.file_digest(incoming,'sha256').hexdigest() != header.get('bundle_sha256'): raise ValueError()
            extra += ['--restore-bundle', str(bundle), '--confirm-restore']
        if header.get('origin_host'): extra += ['--origin-host',header['origin_host']]
        if header.get('receipt'): extra += ['--receipt',json.dumps(header['receipt'])]
        if source.read(1): raise ValueError()
        child = subprocess.Popen(['/usr/bin/python3', str(code), '--archive', str(archive),
                                  '--sha256', header['sha256'], '--version', header['version'], *extra],
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
        effective = getattr(address, "ipv4_mapped", None) or address
        if effective.is_unspecified or effective.is_multicast or effective.is_loopback or effective.is_link_local:
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

    def execute(self, command, stream=None, timeout=45, output_file=None, output_limit=10000):
        # Installer callers retain their original 10k limit. A bounded larger
        # read-only inventory may explicitly opt in; never an unlimited reply.
        if type(output_limit) is not int or not 1 <= output_limit <= 65536:
            raise DeployError("REMOTE_PROTOCOL_FAILED")
        child = None
        try:
            child = subprocess.Popen(self.arguments(command), stdin=stream, stdout=output_file if output_file else subprocess.PIPE,
                                     stderr=subprocess.PIPE, start_new_session=True,
                                     env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "SSHPASS": self.password})
            output, diagnostic = child.communicate(timeout=timeout)
            # With one password prompt sshpass may propagate ssh's 255 instead
            # of 5. Inspect fixed C-locale markers only; never print stderr.
            auth_denied = any(marker in (diagnostic or b"") for marker in
                              (b"Permission denied (", b"Permission denied, please try again.", b"Authentication failed."))
            if child.returncode == 5 or (child.returncode == 255 and auth_denied):
                raise DeployError("SSH_AUTH_FAILED")
            if child.returncode == 255:
                raise DeployError("SSH_CONNECTION_FAILED")
            if output_file:
                if child.returncode:
                    raise DeployError("REMOTE_SNAPSHOT_FAILED")
                return {"status": "DOWNLOADED"}
            if len(output) > output_limit:
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
        except io.UnsupportedOperation:
            # A local incompatible stdin/stdout is not an SSH outage/timeout.
            raise DeployError("SSH_STREAM_UNSUPPORTED") from None
        except (OSError, subprocess.SubprocessError):
            raise DeployError("SSH_TIMEOUT_OR_TRANSPORT_FAILED") from None
        finally:
            if child:
                try:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGTERM)
                        try:
                            child.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait()
                finally:
                    # communicate() closes pipes on success, but not on timeout.
                    # Close only Popen-owned pipes, never the caller's files.
                    for pipe in (child.stdout, child.stderr):
                        if pipe is not None:
                            pipe.close()


def safe_result(value, version, address, expected_https=None):
    port = value.get("port")
    if type(port) is not int or not (port == 3000 or 3100 <= port <= 3199):
        raise DeployError("REMOTE_PROTOCOL_FAILED")
    parsed = ipaddress.ip_address(address)
    expected = f"http://{'[' + parsed.compressed + ']' if parsed.version == 6 else parsed.compressed}:{port}"
    if expected_https:
        expected = https_origin(expected_https)
        if value.get("https") != expected_https: raise DeployError("REMOTE_PROTOCOL_FAILED")
    if (value.get("status") != "SUCCESS" or value.get("version") != version or value.get("url") != expected or
            value.get("health") != 200 or value.get("technical_acceptance") != "passed" or
            value.get("operation") not in ("install", "update", "restore", "already-current") or
            value.get("migrations") not in ("verified", "unchanged") or value.get("service") != "active-enabled"):
        raise DeployError("REMOTE_PROTOCOL_FAILED")
    result = {key: value[key] for key in ("status", "version", "url", "port", "operation", "migrations", "service", "health", "technical_acceptance")}
    if expected_https: result["https"] = expected_https
    return result


def remote_source():
    # Bundle reviewed support modules into one self-contained Python source. No
    # credential or user data is interpolated into code; payloads remain files.
    modules = {name: (HERE / (name + ".py")).read_text() for name in ("transport_settings", "backup", "maintenance")}
    prefix = "import sys,types\nfor _name,_code in " + repr(modules) + ".items():\n _module=types.ModuleType(_name);sys.modules[_name]=_module;exec(compile(_code,_name,'exec'),_module.__dict__)\n"
    return prefix.encode() + (HERE / "remote.py").read_bytes()


@contextlib.contextmanager
def upload_payload(archive, version, checksum, origin_host=None, receipt=None, restore_bundle=None, confirmed=False):
    import tempfile
    import shutil
    with tempfile.TemporaryFile() as payload:
        code = remote_source()
        header = {"code_size": len(code), "archive_size": archive.stat().st_size, "sha256": checksum, "version": version}
        header.update(origin_host=origin_host, receipt=receipt, confirmed=confirmed)
        if restore_bundle:
            with restore_bundle.open("rb") as incoming:
                header.update(bundle_size=restore_bundle.stat().st_size, bundle_sha256=hashlib.file_digest(incoming, "sha256").hexdigest())
        payload.write(json.dumps(header).encode() + b"\n")
        payload.write(code)
        with archive.open("rb") as stream:
            shutil.copyfileobj(stream, payload)
        if restore_bundle:
            with restore_bundle.open("rb") as stream:
                shutil.copyfileobj(stream, payload)
        payload.seek(0)
        yield payload


def deploy(address, artifacts, version, password):
    # Compatibility CLI uses the same mandatory offsite barrier as workflows.
    from backup import GitHubStore, validate_passphrase
    from manage import connection, run_install
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise DeployError("INVALID_VERSION")
    phrase = os.environ.get("STUDIO_BACKUP_PASSPHRASE", "")
    validate_passphrase(phrase)
    store = GitHubStore(os.environ.get("STUDIO_BACKUP_REPOSITORY", ""), os.environ.get("STUDIO_BACKUP_TOKEN", ""))
    store.verify_private()
    with connection(server_ip(address), password) as peer:
        return run_install(peer, store, phrase, artifacts, version)


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
        from manage import summary
        summary(result)
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
