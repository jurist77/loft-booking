#!/usr/bin/env python3
"""Destructive ONLY to Studio CI fixtures on disposable GitHub Ubuntu runners.

No real VPS and no real VPN. Tests the real production installer, systemd, native
runtime, HTTP and SQLite without replacing these with mocks.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installer", REPO / "scripts/installer/remote.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
SITE_PATHS = (installer.BASE, installer.CONFIG, installer.DATA, installer.CACHE, installer.BACKUPS)


def command(args, check=True):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=180)
    if check and result.returncode:
        raise AssertionError("CI_COMMAND_FAILED: " + str(args[0]))
    return result


def apply(archive, version, expected_success=True):
    checksum = installer.digest(archive)
    result = command(["python3", REPO / "scripts/installer/remote.py", "--archive", archive,
                      "--sha256", checksum, "--version", version], check=False)
    assert result.returncode == (0 if expected_success else 1), "Unexpected installer outcome: " + result.stdout[:200]
    value = json.loads(result.stdout)
    print("CI_INSTALL: " + json.dumps(value), flush=True)
    return value


def state():
    return json.loads((installer.CONFIG / "state.json").read_text())


def http(path, payload=None):
    port = state()["port"]
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    if payload:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"http://127.0.0.1:{port}" + path,
                                     data=json.dumps(payload).encode() if payload else None, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status, json.load(response)


def create_booking():
    import datetime
    import uuid
    date = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)).strftime("%Y-%m-%d")
    payload = {"requestId": str(uuid.uuid4()), "resourceId": "studio-19-25", "date": date, "start": "12:00", "end": "13:00",
               "firstName": "Тестовый", "lastName": "Персонаж", "phone": "+79991234567"}
    assert http("/api/bookings", payload)[0] == 201
    return date


def assert_booking(date):
    assert http("/api/availability?date=" + date)[1]["busy"] == [{"start": "12:00", "end": "13:00"}]


def variant(original, directory, version, fault=None):
    root = directory / "variant"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    with tarfile.open(original, "r:gz") as archive:
        archive.extractall(root, filter="data")
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["version"] = version
    if fault in ("bad-start", "changed-schema-bad-start"):
        (root / "root/app/.next-server/BUILD_ID").unlink()
    if fault in ("bad-migration", "changed-schema-bad-start"):
        migration = root / "root/app/migrations/sqlite/0003_ci_test.sql"
        migration.write_text("NOT VALID SQL;" if fault == "bad-migration" else "CREATE TABLE _ci_installer(value INTEGER) STRICT;")
        manifest["migrations"][migration.name] = installer.digest(migration)
    manifest["unpacked_bytes"] = sum(p.stat().st_size for p in (root / "root").rglob("*") if p.is_file())
    manifest_path.write_text(json.dumps(manifest))
    destination = directory / "variant.tar.gz"
    with tarfile.open(destination, "w:gz") as archive:
        archive.add(manifest_path, arcname="manifest.json")
        archive.add(root / "root", arcname="root")
    shutil.rmtree(root)
    return destination


def fingerprints():
    result = {}
    for directory in ("/etc/systemd/system", "/etc/ufw", "/etc/iproute2"):
        base = Path(directory)
        if not base.exists():
            continue
        for entry in sorted(base.rglob("*")):
            if "studio1925" in str(entry):
                continue
            if entry.is_symlink():
                result[str(entry)] = os.readlink(entry)
            elif entry.is_file():
                result[str(entry)] = installer.digest(entry)
    result["dns"] = installer.digest(Path("/etc/resolv.conf"))
    result["routes"] = command(["ip", "-j", "route", "show", "table", "all"]).stdout
    result["firewall"] = command(["iptables-save"]).stdout
    result["canary"] = installer.digest(Path("/opt/studio-ci-vpn/private.conf"))
    result["canary_pid"] = command(["systemctl", "show", "studio-ci-vpn.service", "-p", "MainPID", "--value"]).stdout
    return result


def check_isolation():
    release = installer.BASE / "releases" / state()["current"]
    installer.helper(release, ["-e", "const f=require('fs');if(f.existsSync('/opt/studio-ci-vpn/private.conf')||f.existsSync('/etc/shadow'))process.exit(1)"], "CI_ISOLATION_FAILED")
    pid = command(["systemctl", "show", installer.SERVICE, "-p", "MainPID", "--value"]).stdout.strip()
    rows = [line for line in command(["ss", "-H", "-lntp"]).stdout.splitlines() if f"pid={pid}," in line]
    assert rows and all("127.0.0.1:" in row for row in rows), "Public application listener"
    assert command(["systemctl", "is-enabled", installer.SERVICE]).stdout.strip() == "enabled"


def cleanup():
    command(["systemctl", "stop", installer.SERVICE], check=False)
    command(["systemctl", "disable", installer.SERVICE], check=False)
    installer.UNIT.unlink(missing_ok=True)
    command(["systemctl", "daemon-reload"])
    for path in SITE_PATHS:
        if path.exists():
            shutil.rmtree(path)  # CI fixtures only, never a production operation.
    command(["userdel", "studio1925"], check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("STUDIO_INSTALLER_CI") == "1" and os.environ.get("GITHUB_ACTIONS") == "true"
    assert str(REPO).startswith("/home/runner/work/"), "Only disposable GitHub runners"
    assert not any(p.exists() for p in (*SITE_PATHS, installer.UNIT)), "Refusing pre-existing Studio installation"
    original_checksum = installer.digest(args.archive)
    canary_unit = Path("/etc/systemd/system/studio-ci-vpn.service")
    canary_directory = Path("/opt/studio-ci-vpn")
    assert not canary_directory.exists() and not canary_unit.exists()
    canary_directory.mkdir(mode=0o755)
    (canary_directory / "private.conf").write_text("synthetic readable canary, no real VPN or credentials")
    os.chmod(canary_directory / "private.conf", 0o644)
    canary_unit.write_text("[Service]\nExecStart=/usr/bin/sleep infinity\n")
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "start", "studio-ci-vpn.service"])
    before = fingerprints()
    try:
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 3000))
            busy.listen()
            first = apply(args.archive, args.version)
            assert first["operation"] == "install" and first["listener"] != "127.0.0.1:3000"
        assert_booking_date = create_booking()
        check_isolation()
        assert apply(args.archive, args.version)["operation"] == "already-current"
        assert_booking(assert_booking_date)
        with tempfile.TemporaryDirectory(prefix="studio-ci-artifacts-") as temporary:
            directory = Path(temporary)
            upgraded = variant(args.archive, directory, "b" * 40)
            assert apply(upgraded, "b" * 40)["operation"] == "update"
            assert state()["previous"] is not None
            assert_booking(assert_booking_date)
            check_isolation()
            failed = variant(args.archive, directory, "c" * 40, "bad-migration")
            result = apply(failed, "c" * 40, False)
            assert result["code"] == "MIGRATION_FAILED;rollback=restored-and-health-verified"
            assert_booking(assert_booking_date)
            failed = variant(args.archive, directory, "d" * 40, "bad-start")
            result = apply(failed, "d" * 40, False)
            assert result["code"].endswith("rollback=restored-and-health-verified")
            assert_booking(assert_booking_date)
            failed = variant(args.archive, directory, "e" * 40, "changed-schema-bad-start")
            result = apply(failed, "e" * 40, False)
            assert result["code"].endswith("rollback=manual-required")
            assert command(["systemctl", "is-active", installer.SERVICE], check=False).returncode != 0
            assert command(["systemctl", "is-enabled", installer.SERVICE], check=False).returncode != 0
            assert (installer.DATA / "studio.sqlite").is_file()
            assert list(installer.BACKUPS.glob("checkpoint-*.sqlite"))
            assert fingerprints() == before, "Existing services/network/canary changed"
            cleanup()
            # Fresh failed initial install: no partly configured running service.
            failed = variant(args.archive, directory, "f" * 40, "bad-start")
            assert apply(failed, "f" * 40, False)["code"].endswith("rollback=first-install-stopped")
            assert command(["systemctl", "is-active", installer.SERVICE], check=False).returncode != 0
            assert (installer.DATA / "studio.sqlite").exists()
            assert apply(args.archive, args.version)["status"] == "SUCCESS"
            assert fingerprints() == before
        assert installer.digest(args.archive) == original_checksum, "Verified package was modified by tests"
        print("REAL_CI_SYSTEMD_OK: install/repeat/update/occupied-port/migration/start/rollback/schema-change/data/isolation/network")
    finally:
        cleanup()
        command(["systemctl", "stop", "studio-ci-vpn.service"], check=False)
        canary_unit.unlink(missing_ok=True)
        command(["systemctl", "daemon-reload"])
        shutil.rmtree(canary_directory)


if __name__ == "__main__":
    main()
