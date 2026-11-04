import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/installer"
sys.path.insert(0, str(SCRIPTS))
from maintenance import Maintenance
from backup import validate_bundle
from remote import InstallError
sys.path.pop(0)


class FakeHost:
    """Real local files/SQLite, mock only systemd/root identity and helper launch."""
    def __init__(self, root):
        self.DATA, self.BACKUPS, self.BASE = root / "data", root / "backups", root / "code"
        for directory in (self.DATA, self.BACKUPS, self.BASE): directory.mkdir(mode=0o700)
        self.release = self.BASE / "releases/release"
        (self.release / "root/app/public/images").mkdir(parents=True)
        (self.release / "root/app/public/images/logo.jpg").write_bytes(b"owned-original-fixture")
        (self.release / "manifest.json").write_text('{"migrations":{}}')
        self.state = {"phase":"ready", "current":"release", "version":"a"*40, "instance":"b"*32, "port":3000}
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.SERVICE = "studio1925.service"
        self.active = True
        self.commands = []
        self.fail_backup = False
        db=sqlite3.connect(self.DATA/"studio.sqlite")
        db.execute("CREATE TABLE bookings(id TEXT)");db.execute("INSERT INTO bookings VALUES ('synthetic')");db.commit();db.close()

    def require(self, condition, code):
        if not condition: raise InstallError(code)

    def load_state(self, **kwargs): return copy.deepcopy(self.state)
    def store_state(self, value): self.state=copy.deepcopy(value)
    def managed_account(self, state): return self.account
    def host_facts(self): return {"arch":"x64"}
    def health(self, port, **kwargs): self.require(self.active,"APP_HEALTH_FAILED")
    def owned_directory(self,path,uid,gid,create=False): path.mkdir(mode=0o700,exist_ok=True)
    def run(self,args,*extra,**kwargs):
        self.commands.append(args)
        self.require(args[0]=="systemctl" and args[2]==self.SERVICE,"UNEXPECTED_SERVICE")
        if args[1]=="is-active": return 0 if self.active else 3
        if args[1]=="stop": self.active=False
        if args[1]=="start": self.active=True

    def schema(self,release,data_dir=None):
        db=sqlite3.connect((data_dir or self.DATA)/"studio.sqlite")
        try: return hashlib.sha256(str(db.execute("SELECT sql FROM sqlite_schema ORDER BY name").fetchall()).encode()).hexdigest()
        finally: db.close()

    def helper(self, release, arguments, code, data_dir=None):
        db=sqlite3.connect((data_dir or self.DATA)/"studio.sqlite")
        try:
            if arguments[1]=="backup":
                if self.fail_backup: raise InstallError("SNAPSHOT_SQLITE_FAILED")
                destination=self.BACKUPS/Path(arguments[-1]).relative_to("/backups")
                target=sqlite3.connect(destination);db.backup(target);target.close()
            else: self.require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok",code)
        finally: db.close()


class MaintenanceTests(unittest.TestCase):
    def test_daily_failure_resumes_original_service_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            host=FakeHost(Path(directory));host.fail_backup=True
            with self.assertRaises(InstallError): Maintenance(host).snapshot("daily", output=io.BytesIO())
            self.assertTrue(host.active)
            self.assertEqual(host.state["phase"],"ready")

    def test_hold_requires_verified_matching_receipt_and_abort_resumes(self):
        with tempfile.TemporaryDirectory() as directory:
            host=FakeHost(Path(directory));m=Maintenance(host);stream=io.BytesIO()
            m.snapshot("update",hold=True,output=stream)
            self.assertFalse(host.active)
            self.assertEqual(host.state["phase"],"backup-pending")
            pending=host.state["pending"]
            receipt={"verified":True,"nonce":pending["nonce"],"bundle_sha256":pending["bundle_sha256"],
                     "tag":"studio1925-preupdate-test","cipher_sha256":"a"*64}
            self.assertEqual(m.check_receipt(host.state,receipt,"update")["phase"],"ready")
            for bad in ({**receipt,"verified":False},{**receipt,"nonce":"wrong"},{**receipt,"bundle_sha256":"wrong"}):
                with self.assertRaises(InstallError): m.check_receipt(host.state,bad,"update")
            m.abort(pending["nonce"])
            self.assertTrue(host.active)

    def test_restore_swap_keeps_original_wal_photos_and_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);host=FakeHost(root);m=Maintenance(host);stream=io.BytesIO()
            m.snapshot("daily",output=stream)
            bundle=root/"snapshot.tar.gz";bundle.write_bytes(stream.getvalue())
            validate_bundle(bundle)
            (host.DATA/"photos/logo.jpg").write_bytes(b"newer-working-photo")
            (host.DATA/"settings/studio.json").write_text('{"test":"newer-state"}')
            # Preserve the entire old dataset, not an unsafe copy of one DB file.
            (host.DATA/"studio.sqlite-wal").write_bytes(b"synthetic-wal-preservation-marker")
            stage,manifest=m.stage_restore(bundle,host.release,host.account)
            recovery=m.swap_restore(stage)
            self.assertEqual((host.DATA/"photos/logo.jpg").read_bytes(),b"owned-original-fixture")
            self.assertEqual((recovery/"studio.sqlite-wal").read_bytes(),b"synthetic-wal-preservation-marker")
            m.undo_restore(recovery)
            self.assertEqual((host.DATA/"photos/logo.jpg").read_bytes(),b"newer-working-photo")
            self.assertEqual(json.loads((host.DATA/"settings/studio.json").read_text()),{"test":"newer-state"})

    def test_incompatible_restore_does_not_swap_live_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);host=FakeHost(root);m=Maintenance(host);stream=io.BytesIO()
            m.snapshot("daily",output=stream)
            bundle=root/"snapshot.tar.gz";bundle.write_bytes(stream.getvalue())
            (host.release/"manifest.json").write_text('{"migrations":{"0003_new.sql":"different"}}')
            before=(host.DATA/"studio.sqlite").read_bytes()
            with self.assertRaisesRegex(InstallError,"RESTORE_VERSION_SCHEMA_INCOMPATIBLE"):
                m.stage_restore(bundle,host.release,host.account)
            self.assertEqual((host.DATA/"studio.sqlite").read_bytes(),before)

    def test_photo_symlink_is_rejected_not_read_or_archived(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);host=FakeHost(root);m=Maintenance(host)
            m.persistent(host.release,host.account)
            (root/"outside").write_text("not permitted")
            (host.DATA/"photos/unsafe").symlink_to(root/"outside")
            with self.assertRaisesRegex(InstallError,"UNSAFE_PERSISTENT_FILE"):
                m.snapshot("daily",output=io.BytesIO())
            self.assertTrue(host.active)


if __name__=="__main__": unittest.main()
