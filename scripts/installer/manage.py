#!/usr/bin/env python3
"""GitHub runner coordinator. No real external operations are run by unit tests."""
import argparse
import contextlib
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import tempfile
import time
from backup import BackupError, GitHubStore, crypt, validate_bundle, publish, retrieve, complete_update, file_hash, managed
from deploy import SSH, DeployError, remote_source, upload_payload, BOOTSTRAP, server_ip


class Peer:
    def __init__(self, ssh, address):
        self.ssh, self.address = ssh, address

    def call(self, args, output=None):
        command = "python3 - " + " ".join(shlex.quote(str(x)) for x in args)
        return self.ssh.execute(command, io.BytesIO(remote_source()), timeout=300, output_file=output)

    def info(self):
        value = self.call(["--action", "info"])
        if value.get("status") != "INFO" or type(value.get("installed")) is not bool or value.get("arch") not in ("x64", "arm64"):
            raise DeployError("REMOTE_PROTOCOL_FAILED")
        if value["installed"] and (not re.fullmatch(r"[a-f0-9]{40}", str(value.get("version", ""))) or not isinstance(value.get("port"), int)):
            raise DeployError("REMOTE_PROTOCOL_FAILED")
        return value

    def snapshot(self, path, purpose, hold):
        args = ["--action", "snapshot", "--purpose", purpose]
        if hold:
            args.append("--hold")
        with path.open("wb") as output:
            self.call(args, output)
        return validate_bundle(path)

    def abort(self, nonce):
        return self.call(["--action", "abort", "--nonce", nonce])

    def install(self, archive, version, receipt=None, bundle=None):
        checksum = Path(str(archive) + ".sha256").read_text().strip()
        if file_hash(archive) != checksum:
            raise DeployError("ARTIFACT_CHECKSUM_MISMATCH")
        with upload_payload(archive, version, checksum, self.address, receipt, bundle, confirmed=bool(bundle)) as stream:
            result = self.ssh.execute("python3 -c " + shlex.quote(BOOTSTRAP), stream, timeout=1800)
        port = result.get("port")
        if type(port) is not int or not (port == 3000 or 3100 <= port <= 3199):
            raise DeployError("REMOTE_PROTOCOL_FAILED")
        expected = public_url(self.address, port)
        if (result.get("status") != "SUCCESS" or result.get("version") != version or result.get("url") != expected or
                result.get("health") != 200 or result.get("technical_acceptance") != "passed" or
                result.get("operation") not in ("install", "update", "restore", "already-current") or
                result.get("migrations") not in ("unchanged", "verified") or result.get("service") != "active-enabled"):
            raise DeployError("REMOTE_PROTOCOL_FAILED")
        return {key: result[key] for key in ("status", "version", "url", "port", "operation", "migrations", "service", "health", "technical_acceptance")}


def public_url(address, port):
    parsed = ipaddress.ip_address(address)
    return f"http://{'[' + parsed.compressed + ']' if parsed.version == 6 else parsed.compressed}:{port}"


def public_access(address, port):
    # Separate from internal correctness; never changes firewall/routes/proxy.
    connection = http.client.HTTPConnection(address, port, timeout=5)
    try:
        connection.request("GET", "/api/health")
        result = connection.getresponse()
        return "reachable" if result.status == 200 and json.loads(result.read(1024)) == {"status": "ok"} else "unreachable"
    except (OSError, ValueError, http.client.HTTPException):
        return "unreachable"
    finally:
        connection.close()


def make_backup(peer, store, phrase, purpose, hold=False):
    with tempfile.TemporaryDirectory(prefix="studio-backup-") as directory:
        directory = Path(directory)
        plain = directory / "snapshot.tar.gz"
        manifest = None
        try:
            manifest = peer.snapshot(plain, purpose, hold)
            cipher = directory / "snapshot.tar.gz.gpg"
            crypt(plain, cipher, phrase)
            receipt = publish(store, cipher, manifest, "daily" if purpose == "daily" else "preupdate", retries=1 if purpose == "daily" else 2)
            receipt["bundle_sha256"] = file_hash(plain)
            return receipt
        except BaseException:
            if hold:
                try:
                    nonce = manifest["nonce"] if manifest else peer.info().get("nonce")
                    if nonce:
                        peer.abort(nonce)
                except Exception:
                    # State remains pinned/stopped if the server cannot safely resume.
                    pass
            raise


def run_install(peer, store, phrase, artifacts, version, bundle=None):
    info = peer.info()
    if info.get("phase") == "ready" and info.get("healthy") and info.get("instance"):
        # Recover a lost acknowledgement only after the host reports committed,
        # healthy state. An interrupted/failed upgrade remains pinned.
        for release in store.releases():
            meta = managed(release)
            if meta and meta["instance"] == info["instance"] and meta.get("pending"):
                complete_update(store, {"tag": release["tag_name"], "cipher_sha256": meta["cipher_sha256"]})
    receipt = None
    if info["installed"] and (info["version"] != version or bundle or not info.get("healthy", True)):
        try:
            receipt = make_backup(peer, store, phrase, "restore" if bundle else "update", hold=True)
        except (BackupError, DeployError):
            if not bundle:
                raise
            # This path is reachable only after explicit restore confirmation.
            # The host swaps directories and keeps the original including WAL.
            receipt = {"unavailable": True}
    archive = artifacts / ("studio-server-" + info["arch"]) / "server.tar.gz"
    try:
        result = peer.install(archive, version, receipt, bundle)
    except BaseException:
        # Preflight/transfer failure may leave only the snapshot hold. The host
        # resumes only if nonce AND schema still match; committed migration or
        # unknown state refuses this request and keeps its protected checkpoint.
        if receipt and receipt.get("nonce"):
            try:
                peer.abort(receipt["nonce"])
            except Exception:
                pass
        raise
    if receipt and receipt.get("verified"):
        complete_update(store, receipt)
    if receipt and receipt.get("unavailable"):
        result["pre_restore_preservation"] = "local_original_directory_retained; offsite checkpoint unavailable"
    result["public_access"] = public_access(peer.address, result["port"])
    result["warning"] = "HTTP_TEST_ONLY_SYNTHETIC_CONTACTS"
    return result


@contextlib.contextmanager
def connection(address, password, strict):
    if not password:
        raise DeployError("STUDIO_SSH_PASSWORD_MISSING")
    with tempfile.TemporaryDirectory(prefix="studio-known-hosts-") as directory:
        path = None
        if strict:
            value = os.environ.get("STUDIO_SSH_KNOWN_HOSTS", "")
            if not value:
                raise DeployError("STUDIO_SSH_KNOWN_HOSTS_MISSING")
            path = Path(directory) / "known_hosts"
            path.write_text(value)
            os.chmod(path, 0o600)
        yield Peer(SSH(address, password, known_hosts=path), address)


def summary(value):
    message = json.dumps(value, ensure_ascii=True, sort_keys=True)
    print(message)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as output:
            output.write("## Studio 19.25 lifecycle\n\n```json\n" + message + "\n```\n\n")
            output.write("Public HTTP is technical testing only: use fictional contacts. Internal health and external reachability are separate results. Firewall, VPN, reverse proxy and DNS are not changed.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("install", "daily", "list", "inspect", "restore"))
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--version", default=os.environ.get("GITHUB_SHA", ""))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        store = GitHubStore(os.environ.get("STUDIO_BACKUP_REPOSITORY", ""), os.environ.get("STUDIO_BACKUP_TOKEN", ""))
        phrase = os.environ.get("STUDIO_BACKUP_PASSPHRASE", "")
        if args.operation == "list":
            store.verify_private()
            entries = [{"tag": r["tag_name"], "version": m["version"], "kind": m["kind"], "pending": m.get("pending", False)}
                       for r in store.releases() if (m := managed(r))]
            summary({"status": "LIST_ONLY", "backups": entries})
            return 0
        if len(phrase) < 32:
            raise BackupError("BACKUP_PASSPHRASE_REQUIRES_32_CHARACTERS")
        if args.operation in ("inspect", "restore") and os.environ.get("STUDIO_RESTORE_CONFIRMATION") != "RESTORE STUDIO 19.25":
            raise BackupError("RESTORE_CONFIRMATION_REQUIRED")
        if args.operation == "inspect":
            with tempfile.TemporaryDirectory(prefix="studio-inspect-") as directory:
                manifest = retrieve(store, os.environ.get("STUDIO_BACKUP_TAG", ""), Path(directory) / "bundle.tar.gz", phrase)
            summary({"status": "RESTORE_VALIDATED", "backup_version": manifest["version"], "selected_version": args.version})
            return 0
        address = server_ip(os.environ.get("STUDIO_SERVER_IP", ""))
        with connection(address, os.environ.get("STUDIO_SSH_PASSWORD", ""), strict=args.operation != "install") as peer:
            if args.operation == "daily":
                for attempt in range(2):
                    try:
                        receipt = make_backup(peer, store, phrase, "daily")
                        summary({"status": "BACKUP_SUCCESS", "tag": receipt["tag"]})
                        return 0
                    except (BackupError, DeployError):
                        if attempt:
                            raise
                        time.sleep(3)
            elif args.operation == "restore":
                with tempfile.TemporaryDirectory(prefix="studio-restore-") as directory:
                    bundle = Path(directory) / "bundle.tar.gz"
                    retrieve(store, os.environ.get("STUDIO_BACKUP_TAG", ""), bundle, phrase)
                    summary(run_install(peer, store, phrase, args.artifacts, args.version, bundle))
            else:
                store.verify_private()
                summary(run_install(peer, store, phrase, args.artifacts, args.version))
        return 0
    except Exception as error:
        # Only our safe codes are emitted; raw network/library messages are private.
        code = str(error) if isinstance(error, (BackupError, DeployError)) and re.fullmatch(r"[A-Za-z0-9_;=-]+", str(error)) else "LIFECYCLE_FAILED"
        summary({"status": "FAILED", "code": code})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
