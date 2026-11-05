#!/usr/bin/env python3
"""Ephemeral loopback-only SSH server on a disposable GitHub runner, not a VPS."""
import contextlib
import importlib.util
import io
import json
import os
import pwd
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
PHASE = "guard"
spec = importlib.util.spec_from_file_location("transport", REPO / "scripts/installer/deploy.py")
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, check=True, timeout=30, **kwargs)


def main():
    global PHASE
    if not (os.geteuid() == 0 and os.environ.get("STUDIO_INSTALLER_CI") == "1" and os.environ.get("GITHUB_ACTIONS") == "true"
            and str(REPO).startswith("/home/runner/work/")):
        raise SystemExit("CI_ONLY: refusing to run outside a disposable GitHub runner")
    user = "studio-ssh-ci"
    try:
        pwd.getpwnam(user)
    except KeyError:
        pass
    else:
        raise SystemExit("CI_FIXTURE_COLLISION: refusing pre-existing SSH account")
    password = secrets.token_urlsafe(32)
    daemon = None
    with tempfile.TemporaryDirectory(prefix="studio-ssh-ci-") as directory:
        root = Path(directory)
        try:
            PHASE = "create-test-account"
            command(["useradd", "--system", "--no-create-home", "--shell", "/bin/sh", user])
            # Password goes only through stdin, never argv/file/stdout.
            command(["chpasswd"], input=(user + ":" + password + "\n").encode())
            key = root / "host-key"
            command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            ipv6 = False
            try:
                with socket.socket(socket.AF_INET6) as probe:
                    probe.bind(("::1", port))
                    ipv6 = True
            except OSError:
                pass
            config = root / "sshd_config"
            config.write_text(f"Port {port}\nListenAddress 127.0.0.1\n" + ("ListenAddress ::1\n" if ipv6 else "") + f"HostKey {key}\nPidFile {root}/pid\n"
                              f"PasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nAllowUsers {user}\nLogLevel QUIET\n")
            Path("/run/sshd").mkdir(exist_ok=True)
            PHASE = "validate-test-sshd"
            command(["/usr/sbin/sshd", "-t", "-f", str(config)])
            PHASE = "start-test-sshd"
            daemon = subprocess.Popen(["/usr/sbin/sshd", "-D", "-f", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.1)
            client = transport.SSH("127.0.0.1", password, user=user, port=port)
            PHASE = "valid-password"
            result = client.execute("printf '%s' '{\"status\":\"CONNECTED\"}'")
            assert result == {"status": "CONNECTED"}
            if ipv6:
                PHASE = "ipv6-valid-password"
                result = transport.SSH("::1", password, user=user, port=port).execute("printf '%s' '{\"status\":\"CONNECTED\"}'")
                assert result == {"status": "CONNECTED"}
            PHASE = "wrong-password"
            try:
                transport.SSH("127.0.0.1", "wrong-" + password, user=user, port=port).execute("true")
                raise AssertionError("Wrong password accepted")
            except transport.DeployError as error:
                assert str(error) == "SSH_AUTH_FAILED", "expected SSH_AUTH_FAILED, got " + str(error)
            # A hostile SSH stdout/error cannot put the password into public logs.
            output = io.StringIO()
            PHASE = "malformed-output"
            with contextlib.redirect_stdout(output):
                try:
                    client.execute("printf '%s' 'synthetic-non-json-output'")
                    raise AssertionError("Non-JSON accepted")
                except transport.DeployError as error:
                    assert password not in str(error)
            assert password not in output.getvalue()
            daemon.terminate()
            daemon.wait(timeout=10)
            PHASE = "refused-connection"
            try:
                client.execute("true")
                raise AssertionError("Stopped SSH server accepted connection")
            except transport.DeployError as error:
                assert str(error) == "SSH_CONNECTION_FAILED"
            print("::notice title=SSH CI::REAL_CI_SSH_OK: password authentication, wrong password, refused connection, secret-free diagnostics; IPv6=" + ("passed" if ipv6 else "unavailable"))
        finally:
            if daemon and daemon.poll() is None:
                daemon.terminate()
                daemon.wait(timeout=10)
            command(["userdel", user])


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, transport.DeployError) else type(error).__name__
        print("::error title=SSH CI::" + PHASE + ": " + code)
        raise
