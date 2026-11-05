"""Failure boundaries use real files/SQLite/GPG and mock ALL external operations."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/installer"
sys.path.insert(0, str(SCRIPTS))
import backup
import manage
from maintenance import Maintenance
from remote import InstallError
sys.path.pop(0)
from test_backups import FakeStore, PHRASE, bundle
from test_maintenance import FakeHost


class LocalPeer:
    """Simulate lost transport around the actual host maintenance protocol."""
    address = "192.0.2.1"  # RFC 5737 fixture; never contacted.
    def __init__(self, host, loss):
        self.host, self.loss = host, loss
        self.m = Maintenance(host)
        self.install = Mock(side_effect=manage.DeployError("SSH_CONNECTION_FAILED"))
    def info(self): return self.m.info()
    def abort(self, nonce): return self.m.abort(nonce)
    def snapshot(self, path, purpose, hold):
        if self.loss == "before": raise manage.DeployError("SSH_CONNECTION_FAILED")
        class Broken(io.BytesIO):
            def write(self, data): raise BrokenPipeError()
        try:
            output = Broken() if self.loss == "stream" else io.BytesIO()
            self.m.snapshot(purpose, hold, output)
            path.write_bytes(output.getvalue())
        except BrokenPipeError:
            raise manage.DeployError("SSH_CONNECTION_FAILED") from None
        if self.loss == "after": raise manage.DeployError("SSH_CONNECTION_FAILED")
        return backup.validate_bundle(path)


class RecoveryAudit(unittest.TestCase):
    def test_connection_loss_before_during_and_after_snapshot_never_runs_update(self):
        for phase in ("before", "stream", "after"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                host = FakeHost(Path(directory)); peer = LocalPeer(host, phase)
                with self.assertRaises(manage.DeployError):
                    manage.run_install(peer, FakeStore(), PHRASE, Path("/unused"), "b" * 40)
                peer.install.assert_not_called()
                self.assertTrue(host.active)
                self.assertEqual(host.state["phase"], "ready")
                self.assertTrue(all(cmd[2] == host.SERVICE for cmd in host.commands))

    def test_transfer_failure_after_verified_backup_resumes_unchanged_source_and_keeps_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            host = FakeHost(Path(directory)); peer = LocalPeer(host, "none"); store = FakeStore()
            with self.assertRaises(manage.DeployError):
                manage.run_install(peer, store, PHRASE, Path("/unused"), "b" * 40)
            self.assertTrue(host.active)
            self.assertEqual(host.state["phase"], "ready")
            self.assertEqual(len(store.items), 1)
            self.assertTrue(backup.managed(store.items[0])["pending"])

    def test_lost_commit_reply_is_not_reported_success_and_next_run_reconciles(self):
        with tempfile.TemporaryDirectory() as directory:
            host = FakeHost(Path(directory)); peer = LocalPeer(host, "none"); store = FakeStore()
            def commit_then_lose(*args):
                # Host finished and durably committed ready state, but HTTP/SSH
                # acknowledgement did not arrive. No database rollback occurs.
                host.state = host.state["pending"]["prior"]
                host.state["version"] = "b" * 40; host.active = True
                raise manage.DeployError("SSH_CONNECTION_FAILED")
            peer.install.side_effect = commit_then_lose
            with self.assertRaises(manage.DeployError):
                manage.run_install(peer, store, PHRASE, Path("/unused"), "b" * 40)
            self.assertEqual(host.state["version"], "b" * 40)
            self.assertTrue(backup.managed(store.items[0])["pending"])
            peer.install.side_effect = None
            peer.install.return_value = {"status": "SUCCESS", "operation": "already-current", "port": 3000}
            with patch.object(manage, "public_access", return_value="unreachable"):
                result = manage.run_install(peer, store, PHRASE, Path("/unused"), "b" * 40)
            self.assertEqual(result["operation"], "already-current")
            self.assertFalse(backup.managed(store.items[0])["pending"])

    def test_disconnected_incompatible_migration_cannot_resume_old_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            host = FakeHost(Path(directory)); peer = LocalPeer(host, "none"); store = FakeStore()
            def migrate_then_lose(*args):
                import sqlite3
                db = sqlite3.connect(host.DATA / "studio.sqlite")
                db.execute("CREATE TABLE new_schema(value INTEGER)"); db.commit(); db.close()
                raise manage.DeployError("SSH_CONNECTION_FAILED")
            peer.install.side_effect = migrate_then_lose
            with self.assertRaises(manage.DeployError):
                manage.run_install(peer, store, PHRASE, Path("/unused"), "b" * 40)
            self.assertFalse(host.active)
            self.assertTrue(backup.managed(store.items[0])["pending"])
            self.assertTrue((host.DATA / "studio.sqlite").is_file())

    def test_unreachable_abort_preserves_unknown_state_and_protected_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            host = FakeHost(Path(directory)); peer = LocalPeer(host, "none"); store = FakeStore()
            peer.abort = Mock(side_effect=manage.DeployError("SSH_CONNECTION_FAILED"))
            with self.assertRaises(manage.DeployError):
                manage.run_install(peer, store, PHRASE, Path("/unused"), "b" * 40)
            self.assertFalse(host.active)
            self.assertEqual(host.state["phase"], "backup-pending")
            self.assertTrue(backup.managed(store.items[0])["pending"])

    def test_api_upload_readback_corruption_and_delete_failure_prohibit_update(self):
        for failure in ("upload", "readback", "corrupt", "delete"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); host = FakeHost(root); peer = LocalPeer(host, "none"); store = FakeStore()
                if failure == "upload": store.fail_upload = True
                elif failure == "readback": store.fail_download = True
                elif failure == "corrupt": store.download = lambda release, path: path.write_bytes(b"corrupted download")
                else:
                    # A verified new copy exists but retention API fails. The
                    # source must resume; no migration or update is permitted.
                    for day in range(1, 5):
                        cipher = root / "snapshot.tar.gz.gpg"; cipher.write_bytes(b"mock ciphertext")
                        _, meta = bundle(root, day)
                        receipt = backup.publish(store, cipher, meta, "preupdate")
                        if day < 4:
                            backup.complete_update(store, receipt)
                        else:
                            # Simulate a prior acknowledged update whose cleanup
                            # failed, leaving four eligible completed copies.
                            row = next(r for r in store.items if r["tag_name"] == receipt["tag"])
                            meta = backup.managed(row); meta["pending"] = False
                            store.edit(row, meta)
                    store.delete = Mock(side_effect=backup.BackupError("DELETE_FAILED"))
                with patch.object(backup.time, "sleep"), self.assertRaises(backup.BackupError):
                    manage.run_install(peer, store, PHRASE, Path("/unused"), "b" * 40)
                peer.install.assert_not_called()
                self.assertTrue(host.active)
                self.assertEqual(host.state["phase"], "ready")
                self.assertTrue((host.DATA / "studio.sqlite").is_file())

    def test_tag_then_release_delete_can_resume_each_partial_api_failure(self):
        client = backup.GitHubStore("owner/private-backups", "synthetic-token")
        tag = "studio1925-daily-" + "a" * 32 + "-20261105T001500Z-" + "b" * 32
        release = {"tag_name": tag, "id": 12, "draft": False}
        for fail_at in ("tag", "release", "lost-tag-reply"):
            with self.subTest(failure=fail_at):
                state = {"tag": True, "release": True, "fail": True}
                def api(path, method="GET", payload=None, missing_ok=False):
                    if method == "GET": return {"ref": tag} if state["tag"] else None
                    target = "tag" if path.startswith("/git/") else "release"
                    if state["fail"] and fail_at == target:
                        state["fail"] = False; raise backup.BackupError("DELETE_FAILED")
                    state[target] = False
                    if state["fail"] and fail_at == "lost-tag-reply" and target == "tag":
                        state["fail"] = False; raise backup.BackupError("LOST_REPLY")
                with patch.object(client, "api", side_effect=api):
                    if fail_at != "lost-tag-reply":
                        with self.assertRaises(backup.BackupError): client.delete(release)
                        self.assertTrue(state["release"], "release disappeared before cleanup could be retried")
                    client.delete(release)
                self.assertFalse(state["tag"])
                self.assertFalse(state["release"])

    def test_retention_failure_after_committed_update_keeps_new_app_and_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); host = FakeHost(root); peer = LocalPeer(host, "none"); store = FakeStore()
            for day in range(1, 4):
                cipher = root / "snapshot.tar.gz.gpg"; cipher.write_bytes(b"mock ciphertext")
                _, meta = bundle(root, day)
                receipt = backup.publish(store, cipher, meta, "preupdate")
                backup.complete_update(store, receipt)
            def commit(*args):
                host.state = host.state["pending"]["prior"]
                host.state["version"] = "b" * 40; host.active = True
                return {"status": "SUCCESS", "operation": "update", "port": 3000}
            peer.install.side_effect = commit
            store.delete = Mock(side_effect=backup.BackupError("DELETE_FAILED"))
            with self.assertRaisesRegex(backup.BackupError, "DELETE_FAILED"):
                manage.run_install(peer, store, PHRASE, Path("/unused"), "b" * 40)
            self.assertTrue(host.active)
            self.assertEqual(host.state["version"], "b" * 40)
            self.assertTrue((host.DATA / "studio.sqlite").exists())
            self.assertEqual(len(store.items), 4)  # Retry later, never delete data to hide API failure.

    def test_only_http_404_is_tolerated_not_403_500_or_transport_error(self):
        client = backup.GitHubStore("owner/private-backups", "synthetic-token")
        for status, success in ((404, True), (403, False), (500, False)):
            response = SimpleNamespace(returncode=1, stdout=f'HTTP/2.0 {status} Error\r\nContent-Type: application/json\r\n\r\n{{"status":"{status}"}}'.encode())
            with patch.object(backup.subprocess, "run", return_value=response):
                if success: self.assertIsNone(client.api("/git/ref/tags/fixture", missing_ok=True))
                else:
                    with self.assertRaises(backup.BackupError): client.api("/git/ref/tags/fixture", missing_ok=True)
        with patch.object(backup.subprocess, "run", side_effect=OSError("synthetic transport error")):
            with self.assertRaises(backup.BackupError): client.api("/git/ref/tags/fixture", missing_ok=True)

    def test_restore_to_another_independent_host_preserves_records_and_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source_root = root / "source"; target_root = root / "target"
            source_root.mkdir(); target_root.mkdir()
            source = FakeHost(source_root); target = FakeHost(target_root)
            snap = io.BytesIO(); Maintenance(source).snapshot("daily", output=snap)
            plain = root / "snapshot.tar.gz"; plain.write_bytes(snap.getvalue())
            cipher = root / "snapshot.tar.gz.gpg"; backup.crypt(plain, cipher, PHRASE)
            store = FakeStore(); receipt = backup.publish(store, cipher, backup.validate_bundle(plain), "daily")
            restored = root / "restored.tar.gz"; backup.retrieve(store, receipt["tag"], restored, PHRASE)
            m = Maintenance(target); stage, meta = m.stage_restore(restored, target.release, target.account)
            recovery = m.swap_restore(stage)
            import sqlite3
            db = sqlite3.connect(target.DATA / "studio.sqlite")
            try: self.assertEqual(db.execute("SELECT id FROM bookings").fetchall(), [("synthetic",)])
            finally: db.close()
            self.assertEqual((target.DATA / "photos/logo.jpg").read_bytes(), b"owned-original-fixture")
            self.assertTrue((source.DATA / "studio.sqlite").exists())
            self.assertTrue((recovery / "studio.sqlite").exists())
            self.assertTrue(source.active)


if __name__ == "__main__": unittest.main()
