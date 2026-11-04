"""Host operations for consistent snapshots and explicit restoration.

No network, encryption keys or backup token on the host. The adapter is the
existing installer; tests supply an isolated filesystem/service adapter.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import uuid
from backup import validate_bundle, file_hash


class Maintenance:
    def __init__(self, ops):
        self.o = ops

    def persistent(self, release, account):
        o = self.o
        for name in ("photos", "settings"):
            path = o.DATA / name
            new = not path.exists()
            o.owned_directory(path, account.pw_uid, account.pw_gid, create=True)
            if new and name == "photos":
                source = release / "root/app/public/images"
                if source.exists():
                    self.copy_private(source, path, account)
            if new and name == "settings":
                target = path / "studio.json"
                target.write_text("{}\n")
                os.chmod(target, 0o600)
                os.chown(target, account.pw_uid, account.pw_gid)

    def copy_private(self, source, target, account):
        for path in source.rglob("*"):
            info = path.lstat()
            self.o.require(not path.is_symlink() and (path.is_dir() or (path.is_file() and info.st_nlink == 1)), "UNSAFE_PERSISTENT_FILE")
            destination = target / path.relative_to(source)
            if path.is_dir():
                destination.mkdir(mode=0o700, exist_ok=True)
            else:
                shutil.copyfile(path, destination)
                os.chmod(destination, 0o600)
            os.chown(destination, account.pw_uid, account.pw_gid)

    def info(self):
        o = self.o
        o.host_facts()
        state = o.load_state(allow_pending=True)
        if not state or not state.get("current"):
            return {"status": "INFO", "installed": False, "arch": o.host_facts()["arch"]}
        healthy = False
        if state["phase"] == "ready":
            try:
                o.health(state["port"], timeout=5)
                healthy = True
            except Exception:
                pass
        return {"status": "INFO", "installed": True, "healthy": healthy, "version": state["version"], "instance": state.get("instance"),
                "port": state["port"], "phase": state["phase"], "nonce": state.get("pending", {}).get("nonce"),
                "arch": o.host_facts()["arch"]}

    def abort(self, nonce):
        o = self.o
        state = o.load_state(allow_pending=True)
        o.require(state and state.get("pending", {}).get("nonce") == nonce, "MAINTENANCE_NONCE_MISMATCH")
        prior = state["pending"]["prior"]
        release = o.BASE / "releases" / prior["current"]
        o.require(o.schema(release) == state["pending"]["schema"], "MAINTENANCE_SCHEMA_CHANGED")
        if state["pending"]["was_active"]:
            o.run(["systemctl", "start", o.SERVICE], "SERVICE_RESUME_FAILED", timeout=45)
            o.health(prior["port"])
        o.store_state(prior)
        return {"status": "RESUMED"}

    def snapshot(self, purpose, hold=False, output=None):
        o = self.o
        o.require(purpose in ("daily", "update", "restore"), "INVALID_SNAPSHOT_PURPOSE")
        state = o.load_state()
        o.require(state and state.get("current"), "INSTALLED_APPLICATION_REQUIRED")
        account = o.managed_account(state)
        release = o.BASE / "releases" / state["current"]
        self.persistent(release, account)
        prior = dict(state)
        prior.setdefault("instance", uuid.uuid4().hex)
        nonce = uuid.uuid4().hex
        active = o.run(["systemctl", "is-active", o.SERVICE], check=False) == 0
        fingerprint = o.schema(release)
        state.update(instance=prior["instance"], phase="snapshotting",
                     pending={"nonce": nonce, "purpose": purpose, "prior": prior, "schema": fingerprint, "was_active": active})
        o.store_state(state)
        completed = False
        try:
            if active:
                o.run(["systemctl", "stop", o.SERVICE], "SERVICE_STOP_FAILED", timeout=45)
            with tempfile.TemporaryDirectory(prefix="snapshot-", dir=o.BACKUPS) as folder:
                folder = Path(folder)
                os.chown(folder, account.pw_uid, account.pw_gid)
                o.helper(release, ["scripts/database.mjs", "backup", "--to", "/backups/" + folder.name + "/studio.sqlite"], "SNAPSHOT_SQLITE_FAILED")
                for name in ("photos", "settings"):
                    (folder / name).mkdir(mode=0o700)
                    self.copy_private(o.DATA / name, folder / name, account)
                files = {str(p.relative_to(folder)): {"sha256": file_hash(p), "size": p.stat().st_size}
                         for p in folder.rglob("*") if p.is_file()}
                o.require(sum(f["size"] for f in files.values()) < 1500 * 1024**2, "SNAPSHOT_TOO_LARGE")
                manifest = {"format": 2, "studio": "studio1925", "version": prior["version"], "schema": fingerprint,
                            "instance": prior["instance"], "nonce": nonce, "purpose": purpose,
                            "created_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "migrations": json.loads((release / "manifest.json").read_text())["migrations"], "files": files}
                (folder / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
                archive_path = folder / "snapshot.tar.gz"
                with tarfile.open(archive_path, "w:gz", compresslevel=1) as archive:
                    for name in ("manifest.json", "studio.sqlite", "photos", "settings"):
                        archive.add(folder / name, arcname=name, recursive=True)
                validate_bundle(archive_path)
                state["pending"]["bundle_sha256"] = file_hash(archive_path)
                state["phase"] = "backup-pending"
                o.store_state(state)
                stream = output if output is not None else sys.stdout.buffer
                with archive_path.open("rb") as source:
                    shutil.copyfileobj(source, stream)
                stream.flush()
                completed = True
        finally:
            if not hold or not completed:
                if active:
                    o.run(["systemctl", "start", o.SERVICE], "SERVICE_RESUME_FAILED", timeout=45)
                    o.health(prior["port"])
                o.store_state(prior)

    def check_receipt(self, state, receipt, purpose):
        o = self.o
        pending = state.get("pending", {})
        o.require(state.get("phase") == "backup-pending" and receipt and receipt.get("verified") is True and
                  receipt.get("nonce") == pending.get("nonce") and receipt.get("bundle_sha256") == pending.get("bundle_sha256") and
                  pending.get("purpose") == purpose and
                  isinstance(receipt.get("tag"), str) and receipt["tag"].startswith("studio1925-preupdate-") and
                  len(receipt.get("cipher_sha256", "")) == 64, "VERIFIED_OFFSITE_BACKUP_REQUIRED")
        prior = pending["prior"]
        o.require(o.schema(o.BASE / "releases" / prior["current"]) == pending["schema"], "MAINTENANCE_SCHEMA_CHANGED")
        return prior

    def stage_restore(self, bundle, release, account):
        o = self.o
        manifest = validate_bundle(bundle)
        code_manifest = json.loads((release / "manifest.json").read_text())
        o.require(manifest["migrations"] == code_manifest["migrations"], "RESTORE_VERSION_SCHEMA_INCOMPATIBLE")
        o.require(not os.path.ismount(o.DATA), "RESTORE_DATA_MOUNTPOINT_UNSUPPORTED")
        stage = Path(tempfile.mkdtemp(prefix="studio1925-restore-", dir=o.DATA.parent))
        try:
            validate_bundle(bundle, stage)
            (stage / "manifest.json").unlink()
            for path in [stage, *stage.rglob("*")]:
                os.chown(path, account.pw_uid, account.pw_gid)
                os.chmod(path, 0o700 if path.is_dir() else 0o600)
            o.helper(release, ["scripts/database.mjs", "check"], "RESTORE_DATABASE_INVALID", data_dir=stage)
            o.require(o.schema(release, data_dir=stage) == manifest["schema"], "RESTORE_SCHEMA_MISMATCH")
            # Make the staged contents durable before publishing the directory.
            for path in sorted(stage.rglob("*"), key=lambda p: len(p.parts), reverse=True) + [stage]:
                fd = os.open(path, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return stage, manifest
        except BaseException:
            shutil.rmtree(stage)
            raise

    def swap_restore(self, stage):
        o = self.o
        recovery = o.DATA.parent / ("studio1925-recovery-" + uuid.uuid4().hex)
        o.DATA.rename(recovery)
        try:
            stage.rename(o.DATA)
        except BaseException:
            recovery.rename(o.DATA)
            raise
        self.sync_parent()
        return recovery

    def undo_restore(self, recovery):
        o = self.o
        failed = o.DATA.parent / ("studio1925-failed-restore-" + uuid.uuid4().hex)
        o.DATA.rename(failed)
        recovery.rename(o.DATA)
        self.sync_parent()

    def sync_parent(self):
        fd = os.open(self.o.DATA.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
