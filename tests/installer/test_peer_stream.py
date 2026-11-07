"""Real local Popen/FD regression; substitutes only SSH argv, never contacts a host."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/installer"
sys.path.insert(0, str(SCRIPTS))
import deploy
import manage
sys.path.pop(0)
from test_backups import FakeStore, PHRASE, bundle

PASSWORD = "synthetic-stdin-test-password-not-a-secret"
ADDRESS = "192.0.2.1"  # TEST-NET; no connection is made to this address.
VERSION = "c" * 40

# This child reads real inherited stdin. It validates, but NEVER executes,
# installer source or the bootstrap; all remote/VPS operations are simulated.
RECEIVER = r'''
import hashlib,json,sys,time
from pathlib import Path
mode, expected, fixture, config = sys.argv[1:]
config=json.loads(config)
payload=sys.stdin.buffer.read()
if mode == "restore":
    header, rest=payload.split(b"\n",1)
    header=json.loads(header)
    code=rest[:header["code_size"]]; rest=rest[header["code_size"]:]
    archive=rest[:header["archive_size"]]; snapshot=rest[header["archive_size"]:]
    assert hashlib.sha256(code).hexdigest()==expected
    assert hashlib.sha256(archive).hexdigest()==config["archive_sha256"]==header["sha256"]
    assert len(snapshot)==header["bundle_size"]
    assert hashlib.sha256(snapshot).hexdigest()==header["bundle_sha256"]==config["restore_sha256"]
    assert header["confirmed"] is True and header["receipt"]["verified"] is True
    assert header["origin_host"]==config["address"]
    print(json.dumps({"status":"SUCCESS","version":config["version"],"operation":"restore",
      "migrations":"verified","service":"active-enabled","health":200,"port":3100,
      "url":"http://"+config["address"]+":3100","technical_acceptance":"passed"}))
else:
    assert hashlib.sha256(payload).hexdigest()==expected
    if mode=="fail": sys.exit(255)
    if mode=="hang": time.sleep(30)
    elif mode=="info": print(json.dumps(config["info"]))
    elif mode=="snapshot": sys.stdout.buffer.write(Path(fixture).read_bytes())
    elif mode=="abort": print('{"status":"RESUMED"}')
    else: sys.exit(7)
'''


class LocalSSH(deploy.SSH):
    def __init__(self, fixture=None, **config):
        super().__init__(ADDRESS, PASSWORD)
        self.fixture, self.config = fixture, config
        self.commands, self.streams, self.children, self.modes = [], [], [], []
        self.fail = self.hang = False

    def arguments(self, command):
        self.commands.append(shlex.split(command))
        args = self.commands[-1]
        mode = "restore" if args[:2] == ["python3", "-c"] else args[args.index("--action") + 1]
        mode = "fail" if self.fail else "hang" if self.hang else mode
        return [sys.executable, "-c", RECEIVER, mode, hashlib.sha256(manage.remote_source()).hexdigest(),
                str(self.fixture or ""), json.dumps(self.config)]

    def execute(self, command, stream=None, timeout=45, output_file=None):
        self.streams.append(stream)
        actual = subprocess.Popen
        def launch(*args, **kwargs):
            # Spy delegates to the actual OS process API: BytesIO must fail here.
            child = actual(*args, **kwargs)
            self.children.append(child)
            return child
        with patch.object(deploy.subprocess, "Popen", side_effect=launch):
            result = super().execute(command, stream, timeout=0.1 if self.hang else timeout, output_file=output_file)
            self.modes.append(stat.S_IMODE(os.fstat(stream.fileno()).st_mode))
            return result


class PeerStreamTests(unittest.TestCase):
    def assert_closed_and_reaped(self, ssh):
        self.assertTrue(ssh.streams)
        self.assertTrue(all(stream.closed for stream in ssh.streams))
        self.assertTrue(all(child.poll() is not None for child in ssh.children))
        for child in ssh.children:
            for pipe in (child.stdout, child.stderr):
                if pipe is not None:
                    self.assertTrue(pipe.closed)

    def test_first_info_command_reaches_real_process_with_complete_source_and_eof(self):
        info = {"status": "INFO", "installed": False, "arch": "x64"}
        ssh = LocalSSH(info=info)
        with contextlib.redirect_stdout(io.StringIO()) as logs:
            self.assertEqual(manage.Peer(ssh, ADDRESS).info(), info)
        self.assertEqual(ssh.commands, [["python3", "-", "--action", "info"]])
        self.assertEqual(len(ssh.children), 1)
        self.assertEqual(ssh.modes, [0o600])
        self.assertNotIn(PASSWORD, logs.getvalue())
        self.assertNotIn(PASSWORD.encode(), manage.remote_source())
        self.assert_closed_and_reaped(ssh)

    def test_daily_and_preupdate_backup_stream_binary_output_without_truncation(self):
        for purpose, hold in (("daily", False), ("update", True)):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as directory:
                directory = Path(directory); snapshot, manifest = bundle(directory)
                ssh = LocalSSH(snapshot); output = directory / "downloaded.tar.gz"
                self.assertEqual(manage.Peer(ssh, ADDRESS).snapshot(output, purpose, hold), manifest)
                self.assertEqual(output.read_bytes(), snapshot.read_bytes())
                self.assertEqual(ssh.commands[0][:6], ["python3", "-", "--action", "snapshot", "--purpose", purpose])
                self.assertEqual("--hold" in ssh.commands[0], hold)
                self.assertEqual(ssh.modes, [0o600])
                self.assert_closed_and_reaped(ssh)

    def test_restore_coordinator_info_backup_and_framed_upload_use_real_process_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); snapshot, manifest = bundle(directory)
            packages = directory / "packages"; package = packages / "studio-server-x64/server.tar.gz"
            package.parent.mkdir(parents=True); package.write_bytes(b"synthetic package; not executed")
            digest = deploy.hashlib.sha256(package.read_bytes()).hexdigest()
            Path(str(package) + ".sha256").write_text(digest)
            info = {"status": "INFO", "installed": True, "arch": "x64", "phase": "ready", "healthy": True,
                    "instance": manifest["instance"], "version": manifest["version"], "port": 3100}
            ssh = LocalSSH(snapshot, info=info, archive_sha256=digest,
                           restore_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(), address=ADDRESS, version=VERSION)
            store = FakeStore()
            with patch.object(manage, "public_access", return_value="unreachable"):
                result = manage.run_install(manage.Peer(ssh, ADDRESS), store, PHRASE, packages, VERSION, bundle=snapshot)
            self.assertEqual(result["operation"], "restore")
            self.assertEqual(result["version"], VERSION)
            self.assertEqual(ssh.commands[0], ["python3", "-", "--action", "info"])
            self.assertEqual(ssh.commands[1], ["python3", "-", "--action", "snapshot", "--purpose", "restore", "--hold"])
            self.assertEqual(ssh.commands[2][:2], ["python3", "-c"])
            self.assertEqual(len(ssh.children), 3)
            self.assertEqual(ssh.modes, [0o600] * 3)
            self.assertEqual(len(store.items), 1)
            self.assertFalse(json.loads(store.items[0]["body"])["pending"])
            self.assert_closed_and_reaped(ssh)

    def test_failed_child_closes_source_without_reporting_a_success(self):
        ssh = LocalSSH(); ssh.fail = True
        with self.assertRaisesRegex(deploy.DeployError, "^SSH_CONNECTION_FAILED$"):
            manage.Peer(ssh, ADDRESS).call(["--action", "info"])
        self.assertEqual(len(ssh.children), 1)
        self.assert_closed_and_reaped(ssh)

    def test_real_timeout_reaps_local_child_and_closes_source(self):
        ssh = LocalSSH(); ssh.hang = True
        with self.assertRaisesRegex(deploy.DeployError, "^SSH_TIMEOUT_OR_TRANSPORT_FAILED$"):
            manage.Peer(ssh, ADDRESS).call(["--action", "info"])
        self.assertEqual(len(ssh.children), 1)
        self.assert_closed_and_reaped(ssh)

    def test_unsupported_local_stream_is_not_classified_as_a_transport_outage(self):
        ssh = LocalSSH()
        with io.BytesIO(b"synthetic input") as source:
            with self.assertRaisesRegex(deploy.DeployError, "^SSH_STREAM_UNSUPPORTED$"):
                ssh.execute("python3 - --action info", source)
        self.assertEqual(ssh.children, [])


if __name__ == "__main__": unittest.main()
