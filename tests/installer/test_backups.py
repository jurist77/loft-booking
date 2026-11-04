import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/installer"
sys.path.insert(0, str(SCRIPTS))
import backup
import manage
sys.path.pop(0)

PHRASE = "synthetic-test-passphrase-64-characters-not-production-secret-1234"
INSTANCE = "a" * 32


class FakeStore:
    """Mock ONLY GitHub; actual tar/GPG/download checksum paths are exercised."""
    def __init__(self):
        self.items = []
        self.assets = {}
        self.deleted = []
        self.fail_upload = False
        self.fail_download = False

    def verify_private(self):
        return "a" * 40

    def releases(self):
        return copy.deepcopy(self.items)

    def create(self, tag, metadata, target):
        value = {"id": len(self.items) + 1, "tag_name": tag, "body": json.dumps(metadata), "draft": True}
        self.items.append(value)
        return copy.deepcopy(value)

    def asset(self, release):
        if release["tag_name"] not in self.assets:
            raise backup.BackupError("NO_ASSET")
        return {"size": len(self.assets[release["tag_name"]])}

    def upload(self, release, cipher):
        if self.fail_upload:
            raise backup.BackupError("UPLOAD_FAILED")
        self.assets[release["tag_name"]] = cipher.read_bytes()

    def download(self, release, path):
        if self.fail_download:
            raise backup.BackupError("DOWNLOAD_FAILED")
        path.write_bytes(self.assets[release["tag_name"]])

    def edit(self, release, metadata, draft=False):
        for row in self.items:
            if row["tag_name"] == release["tag_name"]:
                row.update(body=json.dumps(metadata), draft=draft)

    def delete(self, release):
        self.deleted.append(release["tag_name"])
        self.items = [r for r in self.items if r["tag_name"] != release["tag_name"]]
        self.assets.pop(release["tag_name"], None)


def bundle(directory, day=1, nonce=None):
    source = directory / "data"
    source.mkdir(exist_ok=True)
    for name in ("photos", "settings"):
        (source / name).mkdir(exist_ok=True)
    (source / "photos/fixture.jpg").write_bytes(b"synthetic-photo-fixture")
    (source / "settings/studio.json").write_text('{"name":"studio 19.25"}')
    db = sqlite3.connect(source / "studio.sqlite")
    db.execute("CREATE TABLE IF NOT EXISTS fixture(value TEXT)")
    db.commit()
    # Real SQLite backup API (test fixture), never copy a live main file.
    snapshot = directory / "snapshot.sqlite"
    target = sqlite3.connect(snapshot)
    db.backup(target)
    target.close(); db.close()
    os.replace(snapshot, source / "studio.sqlite")
    files = {str(p.relative_to(source)): {"size": p.stat().st_size, "sha256": backup.file_hash(p)} for p in source.rglob("*") if p.is_file()}
    manifest = {"format": 2, "studio": "studio1925", "version": "b" * 40, "schema": "c" * 64,
                "instance": INSTANCE, "nonce": nonce or f"{day:032x}", "purpose": "daily", "migrations": {},
                "created_utc": f"2026-11-{day:02d}T00:15:00Z", "files": files}
    (source / "manifest.json").write_text(json.dumps(manifest))
    path = directory / "bundle.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name in ("manifest.json", "studio.sqlite", "photos", "settings"):
            archive.add(source / name, arcname=name)
    return path, manifest


class BackupTests(unittest.TestCase):
    def test_real_encryption_restore_photos_settings_and_sqlite(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            path, manifest = bundle(folder)
            cipher = folder / "snapshot.tar.gz.gpg"
            backup.crypt(path, cipher, PHRASE)
            self.assertNotIn(b"studio 19.25", cipher.read_bytes())
            store = FakeStore()
            receipt = backup.publish(store, cipher, manifest, "daily")
            self.assertTrue(receipt["verified"])
            restored = folder / "restored.tar.gz"
            self.assertEqual(backup.retrieve(store, receipt["tag"], restored, PHRASE), manifest)
            destination = folder / "restore"
            destination.mkdir()
            backup.validate_bundle(restored, destination)
            self.assertEqual((destination / "photos/fixture.jpg").read_bytes(), b"synthetic-photo-fixture")
            db = sqlite3.connect(destination / "studio.sqlite")
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            db.close()

    def test_wrong_key_and_tampering_do_not_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            source, _ = bundle(folder)
            cipher = folder / "cipher.gpg"
            backup.crypt(source, cipher, PHRASE)
            output = folder / "plain.tar.gz"
            with self.assertRaises(backup.BackupError):
                backup.crypt(cipher, output, "another-wrong-secret-longer-than-32-characters", True)
            self.assertFalse(output.exists())
            data = bytearray(cipher.read_bytes()); data[-10] ^= 32; cipher.write_bytes(data)
            with self.assertRaises(backup.BackupError):
                backup.crypt(cipher, output, PHRASE, True)
            self.assertFalse(output.exists())

    def test_keep_seven_daily_and_bounded_preupdate_preserve_pending(self):
        store = FakeStore()
        with tempfile.TemporaryDirectory() as folder, patch.object(backup.time, "sleep"):
            folder = Path(folder)
            cipher = folder / "snapshot.tar.gz.gpg"
            cipher.write_bytes(b"mock ciphertext; crypto independently tested")
            for day in range(1, 11):
                _, manifest = bundle(folder, day)
                backup.publish(store, cipher, manifest, "daily")
            self.assertEqual(len(store.items), 7)
            self.assertEqual(len(store.deleted), 3)
            for day in range(11, 16):
                _, manifest = bundle(folder, day)
                receipt = backup.publish(store, cipher, manifest, "preupdate")
                if day < 15:
                    backup.complete_update(store, receipt)
            pending = [r for r in store.items if backup.managed(r)["pending"]]
            self.assertEqual(len(pending), 1)
            self.assertNotIn(pending[0]["tag_name"], store.deleted)
            self.assertEqual(len([r for r in store.items if backup.managed(r)["kind"] == "preupdate"]), 4)

    def test_failed_new_backup_never_deletes_previous_success(self):
        store = FakeStore()
        with tempfile.TemporaryDirectory() as folder, patch.object(backup.time, "sleep"):
            folder = Path(folder)
            cipher = folder / "snapshot.tar.gz.gpg"; cipher.write_bytes(b"mock cipher")
            _, manifest = bundle(folder)
            receipt = backup.publish(store, cipher, manifest, "daily")
            store.fail_upload = True
            _, manifest = bundle(folder, 2)
            with self.assertRaises(backup.BackupError):
                backup.publish(store, cipher, manifest, "daily")
            self.assertIn(receipt["tag"], [r["tag_name"] for r in store.items])
            self.assertFalse(store.deleted)

    def test_readback_failure_is_not_success_or_update_permission(self):
        store = FakeStore(); store.fail_download = True
        with tempfile.TemporaryDirectory() as folder, patch.object(backup.time, "sleep"):
            folder = Path(folder)
            path, manifest = bundle(folder)
            cipher = folder / "snapshot.tar.gz.gpg"; cipher.write_bytes(b"cipher")
            with self.assertRaises(backup.BackupError):
                backup.publish(store, cipher, manifest, "preupdate")
            self.assertFalse(any(backup.managed(r) for r in store.items))

    def test_unmanaged_release_untouched_and_second_pending_blocks(self):
        store = FakeStore()
        store.items.append({"id": 0, "tag_name": "other-project", "body": "{}", "draft": False})
        with tempfile.TemporaryDirectory() as folder, patch.object(backup.time, "sleep"):
            folder = Path(folder)
            cipher = folder / "snapshot.tar.gz.gpg"; cipher.write_bytes(b"cipher")
            _, manifest = bundle(folder)
            backup.publish(store, cipher, manifest, "preupdate")
            _, manifest = bundle(folder, 2)
            with self.assertRaisesRegex(backup.BackupError, "PREVIOUS_UPDATE_BACKUP_PINNED"):
                backup.publish(store, cipher, manifest, "preupdate")
            self.assertIn("other-project", [r["tag_name"] for r in store.items])

    def test_archive_escape_corrupt_metadata_and_size_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            path, _ = bundle(folder)
            self.assertEqual(backup.validate_bundle(path)["format"], 2)
            with tarfile.open(path, "w:gz") as archive:
                entry = tarfile.TarInfo("../outside"); entry.size = 1
                archive.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaises(backup.BackupError): backup.validate_bundle(path)
            store = FakeStore()
            with patch.object(backup, "MAX_ASSET", 1):
                with self.assertRaisesRegex(backup.BackupError, "BACKUP_ASSET_LIMIT"):
                    backup.publish(store, path, {}, "daily")

    def test_install_never_runs_when_required_backup_fails(self):
        from unittest.mock import Mock
        peer = Mock()
        peer.info.return_value = {"installed": True, "version": "a" * 40, "arch": "x64"}
        peer.snapshot.side_effect = backup.BackupError("SNAPSHOT_FAILED")
        with self.assertRaises(backup.BackupError):
            manage.run_install(peer, FakeStore(), PHRASE, Path("/not-used"), "b" * 40)
        peer.install.assert_not_called()

    def test_key_not_in_gpg_arguments_or_child_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            source, _ = bundle(folder)
            actual = backup.subprocess.run
            def spy(args, **kwargs):
                self.assertNotIn(PHRASE, " ".join(str(x) for x in args))
                self.assertNotIn(PHRASE, json.dumps(kwargs.get("env", {})))
                return actual(args, **kwargs)
            with patch.object(backup.subprocess, "run", side_effect=spy):
                backup.crypt(source, folder / "cipher.gpg", PHRASE)


if __name__ == "__main__": unittest.main()
