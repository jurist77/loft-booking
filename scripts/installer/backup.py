#!/usr/bin/env python3
"""Encrypted Release storage. External operations are injected/mocked in tests."""
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import time
import uuid

MAX_ASSET = 1900 * 1024**2  # GitHub limit is strictly <2 GiB; keep a margin.
TAG = re.compile(r"studio1925-(daily|preupdate)-([a-f0-9]{32})-(\d{8}T\d{6}Z)-([a-f0-9]{32})")


class BackupError(Exception):
    pass


def file_hash(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_bundle(path, destination=None):
    """Validate all paths/types/hashes before any extraction or live mutation."""
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 50000:
            raise BackupError("BUNDLE_LIMIT")
        names = set()
        total = 0
        for member in members:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or str(name) != member.name or member.name in names or
                    not (member.isfile() or member.isdir()) or member.mode & 0o6000 or
                    not (member.name in ("manifest.json", "studio.sqlite", "photos", "settings") or name.parts[0] in ("photos", "settings"))):
                raise BackupError("UNSAFE_BACKUP_BUNDLE")
            names.add(member.name)
            total += member.size
        if total > MAX_ASSET or not {"manifest.json", "studio.sqlite", "photos", "settings"} <= names:
            raise BackupError("BUNDLE_LIMIT")
        meta = archive.getmember("manifest.json")
        if (not meta.isfile() or not archive.getmember("studio.sqlite").isfile() or
                not archive.getmember("photos").isdir() or not archive.getmember("settings").isdir() or meta.size > 4 * 1024**2):
            raise BackupError("BUNDLE_METADATA_INVALID")
        manifest = json.load(archive.extractfile(meta))
        if (manifest.get("format") != 2 or manifest.get("studio") != "studio1925" or
                not re.fullmatch(r"[a-f0-9]{40}", str(manifest.get("version", ""))) or
                not re.fullmatch(r"[a-f0-9]{64}", str(manifest.get("schema", ""))) or
                not re.fullmatch(r"[a-f0-9]{32}", str(manifest.get("instance", ""))) or
                not re.fullmatch(r"[a-f0-9]{32}", str(manifest.get("nonce", "")))):
            raise BackupError("BUNDLE_METADATA_INVALID")
        files = {m.name: m for m in members if m.isfile() and m.name != "manifest.json"}
        if set(files) != set(manifest.get("files", {})):
            raise BackupError("BUNDLE_FILE_SET_MISMATCH")
        for name, member in files.items():
            entry = manifest["files"][name]
            if member.size != entry.get("size") or hashlib.file_digest(archive.extractfile(member), "sha256").hexdigest() != entry.get("sha256"):
                raise BackupError("BUNDLE_CHECKSUM_MISMATCH")
        if destination is not None:
            archive.extractall(destination, filter="data")
        return manifest


def crypt(source, destination, passphrase, decrypt=False):
    if not 32 <= len(passphrase) <= 1024 or len(passphrase.encode()) > 4096 or "\n" in passphrase or "\x00" in passphrase:
        raise BackupError("BACKUP_PASSPHRASE_REQUIRES_32_CHARACTERS")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, passphrase.encode() + b"\n")
        os.close(write_fd)
        write_fd = None
        with tempfile.TemporaryDirectory(prefix="studio-gpg-") as home:
            args = ["gpg", "--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback", "--no-symkey-cache",
                    "--passphrase-fd", str(read_fd), "--output", str(destination)]
            args += ["--decrypt", str(source)] if decrypt else ["--cipher-algo", "AES256", "--s2k-digest-algo", "SHA512", "--s2k-count", "65011712", "--symmetric", str(source)]
            try:
                result = subprocess.run(args, pass_fds=(read_fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GNUPGHOME": home, "LC_ALL": "C"}, timeout=300)
            finally:
                # Kill only the agent belonging to our unique ephemeral home.
                subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=15, check=False,
                               env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"})
            if result.returncode:
                destination.unlink(missing_ok=True)
                raise BackupError("DECRYPTION_FAILED" if decrypt else "ENCRYPTION_FAILED")
            os.chmod(destination, 0o600)
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


class GitHubStore:
    """Uses a dedicated fine-grained token, never main repository GITHUB_TOKEN."""
    def __init__(self, repo, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or "") or not token:
            raise BackupError("BACKUP_REPOSITORY_OR_TOKEN_MISSING")
        self.repo, self.token = repo, token
        if repo.lower() == os.environ.get("GITHUB_REPOSITORY", "").lower():
            raise BackupError("SEPARATE_BACKUP_REPOSITORY_REQUIRED")

    def command(self, args, output=None, payload=None, json_output=True):
        try:
            result = subprocess.run(["gh", *args], input=json.dumps(payload).encode() if payload is not None else None,
                                    stdout=output if output else subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GH_TOKEN": self.token, "LC_ALL": "C"}, timeout=600)
            if result.returncode:
                raise BackupError("BACKUP_GITHUB_OPERATION_FAILED")
            return None if output or not json_output else json.loads(result.stdout or b"null")
        except (OSError, subprocess.SubprocessError, ValueError):
            raise BackupError("BACKUP_GITHUB_OPERATION_FAILED") from None

    def api(self, path, method="GET", payload=None):
        args = ["api", "repos/" + self.repo + path, "--method", method]
        if payload is not None:
            args += ["--input", "-"]
        return self.command(args, payload=payload)

    def verify_private(self):
        meta = self.api("")
        if meta.get("private") is not True or meta.get("archived") or not meta.get("permissions", {}).get("push"):
            raise BackupError("PRIVATE_WRITABLE_BACKUP_REPOSITORY_REQUIRED")
        # An initialized repo/default branch is required for release tags.
        branch = self.api("/branches/" + meta["default_branch"])
        return branch["commit"]["sha"]

    def releases(self):
        result = []
        for page in range(1, 101):
            entries = self.api(f"/releases?per_page=100&page={page}")
            result.extend(entries)
            if len(entries) < 100:
                return result
        raise BackupError("BACKUP_RELEASE_LIST_LIMIT")

    def create(self, tag, metadata, target):
        return self.api("/releases", "POST", {"tag_name": tag, "target_commitish": target, "draft": True,
                                              "name": tag, "body": json.dumps(metadata, sort_keys=True)})

    def upload(self, release, cipher):
        self.command(["release", "upload", release["tag_name"], str(cipher), "--repo", self.repo], json_output=False)

    def asset(self, release):
        assets = self.api(f"/releases/{release['id']}/assets")
        matches = [a for a in assets if a["name"] == "snapshot.tar.gz.gpg" and a.get("state") == "uploaded"]
        if len(matches) != 1 or not 0 < matches[0]["size"] < MAX_ASSET:
            raise BackupError("BACKUP_ASSET_INVALID")
        return matches[0]

    def download(self, release, path):
        asset = self.asset(release)
        with path.open("wb") as output:
            self.command(["api", f"repos/{self.repo}/releases/assets/{asset['id']}", "--header", "Accept: application/octet-stream"], output=output)
        if path.stat().st_size != asset["size"]:
            raise BackupError("BACKUP_DOWNLOAD_INCOMPLETE")

    def edit(self, release, metadata, draft=False):
        return self.api(f"/releases/{release['id']}", "PATCH", {"body": json.dumps(metadata, sort_keys=True), "draft": draft})

    def delete(self, release):
        if not TAG.fullmatch(release["tag_name"]):
            raise BackupError("BACKUP_DELETE_OUTSIDE_NAMESPACE")
        self.api(f"/releases/{release['id']}", "DELETE")
        # Only our unique managed tag, never branches/other tags.
        if not release.get("draft"):
            self.api("/git/refs/tags/" + release["tag_name"], "DELETE")


def managed(release, drafts=False):
    try:
        meta = json.loads(release.get("body", ""))
        match = TAG.fullmatch(release["tag_name"])
        if (not match or meta.get("format") != 2 or meta.get("studio") != "studio1925" or
                meta.get("kind") != match[1] or meta.get("instance") != match[2] or
                not re.fullmatch(r"[a-f0-9]{64}", meta.get("cipher_sha256", "")) or
                (not drafts and (release.get("draft") or not meta.get("verified")))):
            return None
        return meta
    except (ValueError, KeyError, TypeError):
        return None


def rotate(store, instance):
    entries = [(r, managed(r)) for r in store.releases()]
    for kind, keep in (("daily", 7), ("preupdate", 3)):
        # One studio, one global retention policy, even after moving to a new VPS.
        eligible = [(r, m) for r, m in entries if m and m["kind"] == kind and not m.get("pending")]
        eligible.sort(key=lambda pair: (TAG.fullmatch(pair[0]["tag_name"])[3], TAG.fullmatch(pair[0]["tag_name"])[4]), reverse=True)
        # Keep newest distinct Moscow dates, including after moving to a new VPS.
        if kind == "daily":
            dates = []
            remove = []
            for r, m in eligible:
                instant = dt.datetime.strptime(TAG.fullmatch(r["tag_name"])[3], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
                day = (instant + dt.timedelta(hours=3)).strftime("%Y%m%d")
                if day in dates or len(dates) >= keep:
                    remove.append(r)
                else:
                    dates.append(day)
        else:
            remove = [r for r, _ in eligible[keep:]]
        for release in remove:
            store.delete(release)


def publish(store, cipher, manifest, kind, retries=2):
    if kind not in ("daily", "preupdate") or not 0 < cipher.stat().st_size < MAX_ASSET:
        raise BackupError("BACKUP_ASSET_LIMIT")
    target = store.verify_private()
    stamp = dt.datetime.fromisoformat(manifest["created_utc"].replace("Z", "+00:00")).astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = f"studio1925-{kind}-{manifest['instance']}-{stamp}-{manifest['nonce']}"
    if not TAG.fullmatch(tag):
        raise BackupError("BACKUP_TAG_INVALID")
    cipher_hash = file_hash(cipher)
    metadata = {"format": 2, "studio": "studio1925", "kind": kind, "instance": manifest["instance"],
                "version": manifest["version"], "cipher_sha256": cipher_hash, "verified": False, "pending": kind == "preupdate"}
    for attempt in range(retries):
        try:
            existing = [r for r in store.releases() if r["tag_name"] == tag]
            if kind == "preupdate":
                pending = [r for r in store.releases() if (m := managed(r)) and m["instance"] == manifest["instance"] and m.get("pending") and r["tag_name"] != tag]
                if pending:
                    raise BackupError("PREVIOUS_UPDATE_BACKUP_PINNED")
            release = existing[0] if existing else store.create(tag, metadata, target)
            prior = managed(release, drafts=True)
            if not prior or prior["cipher_sha256"] != cipher_hash:
                raise BackupError("BACKUP_ID_CONFLICT")
            try:
                store.asset(release)
            except BackupError:
                store.upload(release, cipher)
            with tempfile.TemporaryDirectory(prefix="studio-readback-") as folder:
                copy = Path(folder) / "copy.gpg"
                store.download(release, copy)
                if file_hash(copy) != cipher_hash:
                    raise BackupError("BACKUP_UPLOAD_VERIFICATION_FAILED")
            metadata["verified"] = True
            store.edit(release, metadata, draft=False)
            rotate(store, manifest["instance"])
            return {"tag": tag, "cipher_sha256": cipher_hash, "nonce": manifest["nonce"], "verified": True}
        except BackupError:
            if attempt + 1 == retries:
                # An unverified draft is never a retained backup. Keep published
                # verified copies even if later retention/acknowledgement fails.
                try:
                    for failed in store.releases():
                        if failed["tag_name"] == tag and failed.get("draft") and not (managed(failed, drafts=True) or {}).get("verified"):
                            store.delete(failed)
                except BackupError:
                    pass
                raise
            time.sleep(2)


def complete_update(store, receipt):
    matches = [r for r in store.releases() if r["tag_name"] == receipt["tag"]]
    if len(matches) != 1 or not (meta := managed(matches[0])) or meta["cipher_sha256"] != receipt["cipher_sha256"]:
        raise BackupError("UPDATE_BACKUP_RECEIPT_INVALID")
    meta["pending"] = False
    store.edit(matches[0], meta)
    rotate(store, meta["instance"])


def retrieve(store, tag, destination, passphrase):
    if not TAG.fullmatch(tag):
        raise BackupError("BACKUP_TAG_INVALID")
    store.verify_private()
    entries = [r for r in store.releases() if r["tag_name"] == tag and managed(r)]
    if len(entries) != 1:
        raise BackupError("VERIFIED_BACKUP_NOT_FOUND")
    with tempfile.TemporaryDirectory(prefix="studio-retrieve-") as folder:
        cipher = Path(folder) / "snapshot.gpg"
        store.download(entries[0], cipher)
        if file_hash(cipher) != managed(entries[0])["cipher_sha256"]:
            raise BackupError("BACKUP_DOWNLOAD_CHECKSUM_FAILED")
        crypt(cipher, destination, passphrase, decrypt=True)
    manifest = validate_bundle(destination)
    if (manifest["instance"] != managed(entries[0])["instance"] or manifest["version"] != managed(entries[0])["version"] or
            manifest["nonce"] != TAG.fullmatch(tag)[4]):
        raise BackupError("BACKUP_METADATA_CONFLICT")
    return manifest
