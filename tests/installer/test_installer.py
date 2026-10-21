import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/installer"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


remote = load("remote", "remote.py")
deploy = load("deploy", "deploy.py")
packager = load("packager", "package.py")
sys.path.insert(0, str(SCRIPTS))
gate = load("gate", "verify-main.py")
sys.path.pop(0)
SECRET = "secret-example-not-an-actual-password"
VERSION = "a" * 40


class InstallerTests(unittest.TestCase):
    def test_main_gate_rejects_other_refs_missing_secret_and_failed_newest_check(self):
        env = {"STUDIO_SERVER_IP": "203.0.113.9", "STUDIO_PASSWORD_PRESENT": "true", "GITHUB_SHA": VERSION,
               "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": "owner/repo"}
        names = ("Check backend foundation", "Check read-only VPS audit tool", "Check universal installer")
        runs = [{"name": name, "databaseId": i, "status": "completed", "conclusion": "success"} for i, name in enumerate(names)]
        def check(overrides, checks, expected):
            with patch.dict(os.environ, {**env, **overrides}), patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(checks))), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(), expected)
        import os
        check({}, runs, 0)
        check({"GITHUB_REF": "refs/heads/feature"}, runs, 1)
        check({"STUDIO_PASSWORD_PRESENT": "false"}, runs, 1)
        check({}, runs + [{"name": names[0], "databaseId": 99, "status": "completed", "conclusion": "failure"}], 1)
    def test_generated_next_external_link_materialized_but_host_escape_refused(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            previous = Path.cwd()
            try:
                os.chdir(temporary)
                Path("node_modules/pkg").mkdir(parents=True)
                Path("node_modules/pkg/code.js").write_text("module.exports = 1")
                Path(".next-server/node_modules").mkdir(parents=True)
                Path(".next-server/node_modules/pkg-generated").symlink_to(Path("node_modules/pkg").resolve(), target_is_directory=True)
                packager.copy_tree(Path(".next-server"), Path("copy"))
                self.assertFalse(Path("copy/node_modules/pkg-generated").is_symlink())
                self.assertEqual(Path("copy/node_modules/pkg-generated/code.js").read_text(), "module.exports = 1")
                Path("outside").write_text(SECRET)
                Path(".next-server/escape").symlink_to(Path("outside").resolve())
                with self.assertRaisesRegex(RuntimeError, "SOURCE_SYMLINK_ESCAPE"):
                    packager.copy_tree(Path(".next-server"), Path("blocked"))
            finally:
                os.chdir(previous)

    def test_literal_ip_only_ipv4_and_ipv6(self):
        self.assertEqual(deploy.server_ip("203.0.113.9"), "203.0.113.9")
        self.assertEqual(deploy.server_ip("2001:0db8:0000::2"), "2001:db8::2")
        for value in ("host.example", "127.0.0.1", "::1", "::", "0.0.0.0", "fe80::1%eth0", "x;id", "--help", "1.2.3.4\n", "224.0.0.1", "::ffff:127.0.0.1"):
            with self.assertRaises(deploy.DeployError, msg=value):
                deploy.server_ip(value)

    def test_password_not_in_argv_and_host_key_exception_local_to_ssh(self):
        client = deploy.SSH("2001:db8::2", SECRET)
        args = client.arguments("python3 - --probe")
        self.assertNotIn(SECRET, " ".join(args))
        self.assertEqual(args[:4], ["sshpass", "-e", "ssh", "-F"])
        self.assertIn("StrictHostKeyChecking=no", args)
        self.assertIn("UserKnownHostsFile=/dev/null", args)
        self.assertIn("root@2001:db8::2", args)
        self.assertEqual(args[args.index("-p") + 1], "22")

    def test_auth_connection_and_timeout_errors_are_safe(self):
        for code, expected in ((5, "SSH_AUTH_FAILED"), (255, "SSH_CONNECTION_FAILED")):
            with patch.object(deploy.subprocess, "Popen") as popen:
                child = popen.return_value
                child.communicate.return_value = (SECRET.encode(), None)
                child.returncode = code
                child.poll.return_value = code
                with self.assertRaisesRegex(deploy.DeployError, expected):
                    deploy.SSH("203.0.113.9", SECRET).execute("true")
                self.assertEqual(popen.call_args.kwargs["env"]["SSHPASS"], SECRET)
                self.assertNotIn("STUDIO_SSH_PASSWORD", popen.call_args.kwargs["env"])
        with patch.object(deploy.subprocess, "Popen", side_effect=subprocess.TimeoutExpired(SECRET, 2)):
            with self.assertRaisesRegex(deploy.DeployError, "SSH_TIMEOUT_OR_TRANSPORT_FAILED"):
                deploy.SSH("203.0.113.9", SECRET).execute("true")

    def test_raw_remote_output_and_untrusted_error_never_logged(self):
        for output in (SECRET, json.dumps({"status": "FAILED", "code": SECRET})):
            with patch.object(deploy.subprocess, "Popen") as popen:
                child = popen.return_value
                child.communicate.return_value = (output.encode(), None)
                child.returncode = 1
                child.poll.return_value = 1
                with self.assertRaises(deploy.DeployError) as error:
                    deploy.SSH("203.0.113.9", SECRET).execute("true")
                self.assertNotIn(SECRET, str(error.exception))

    def test_single_prompt_password_rejection_can_return_255(self):
        with patch.object(deploy.subprocess, "Popen") as popen:
            child = popen.return_value
            child.communicate.return_value = (b"", b"root@host: Permission denied (password). " + SECRET.encode())
            child.returncode = 255
            child.poll.return_value = 255
            with self.assertRaisesRegex(deploy.DeployError, "^SSH_AUTH_FAILED$"):
                deploy.SSH("203.0.113.9", SECRET).execute("true")

    def test_success_is_whitelisted_and_requires_health_200(self):
        result = {"status": "SUCCESS", "version": VERSION, "health": 200, "service": "active-enabled",
                  "migrations": "verified", "operation": "install", "listener": "127.0.0.1:3100", "secret": SECRET}
        self.assertNotIn(SECRET, json.dumps(deploy.safe_result(result, VERSION)))
        for key, bad in (("health", 503), ("listener", "0.0.0.0:3100"), ("version", "b" * 40), ("operation", SECRET)):
            with self.assertRaises(deploy.DeployError):
                deploy.safe_result({**result, key: bad}, VERSION)

    def test_missing_secret_fails_before_ssh_without_dumping_environment(self):
        with patch.dict(deploy.os.environ, {"STUDIO_SSH_PASSWORD": "", "GITHUB_STEP_SUMMARY": ""}), \
                patch.object(sys, "argv", ["deploy.py", "--artifacts", "/tmp/not-used", "--version", VERSION]), \
                patch.object(deploy, "deploy") as execute, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(deploy.main(), 1)
            execute.assert_not_called()
            self.assertEqual(output.getvalue().strip(), "FAILED: STUDIO_SSH_PASSWORD_MISSING")

    def archive(self, folder, arch="x64", extra=None):
        path = Path(folder) / "test.tar.gz"
        manifest = {"format": 1, "version": VERSION, "os": "ubuntu", "os_version": "24.04", "mode": "server",
                    "arch": arch, "node": "v24.12.0", "node_abi": "137", "migrations": {}, "unpacked_bytes": 0}
        with tarfile.open(path, "w:gz") as tar:
            data = json.dumps(manifest).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
            if extra:
                tar.addfile(extra)
        return path, remote.digest(path)

    def test_checksum_and_architecture_fail_before_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            path, checksum = self.archive(folder)
            self.assertEqual(remote.inspect_archive(path, checksum, VERSION, "x64")["arch"], "x64")
            with self.assertRaisesRegex(remote.InstallError, "ARCH_MISMATCH"):
                remote.inspect_archive(path, checksum, VERSION, "arm64")
            with self.assertRaisesRegex(remote.InstallError, "CHECKSUM_MISMATCH"):
                remote.inspect_archive(path, "0" * 64, VERSION, "x64")

    def test_archive_traversal_links_devices_and_duplicates_refused(self):
        for name, kind in (("../escape", tarfile.DIRTYPE), ("/escape", tarfile.DIRTYPE),
                           ("root/link", tarfile.SYMTYPE), ("root/device", tarfile.CHRTYPE),
                           ("manifest.json", tarfile.REGTYPE)):
            with tempfile.TemporaryDirectory() as folder:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = "/etc/shadow"
                path, checksum = self.archive(folder, extra=info)
                with self.assertRaises(remote.InstallError):
                    remote.inspect_archive(path, checksum, VERSION, "x64")

    def test_occupied_port_is_not_seized(self):
        with socket.socket() as held:
            try:
                held.bind(("127.0.0.1", 3000))
                held.listen()
            except OSError:
                pass  # It was already occupied; the same assertion applies.
            self.assertIn(remote.choose_port(), range(3100, 3200))

    def test_service_is_private_root_directory_and_only_studio_paths(self):
        unit = remote.service_text(Path("/opt/studio1925/releases/example"), 3100)
        for expected in ("RootDirectory=", "--hostname 127.0.0.1", "User=studio1925", "Restart=on-failure", "ProtectSystem=strict"):
            self.assertIn(expected, unit)
        for forbidden in ("0.0.0.0", "/etc/xray", "/usr/local/x-ui", "PartOf=", "Requires=", "MemoryMax=", "ExecStart=/bin/sh"):
            self.assertNotIn(forbidden, unit)
        self.assertNotIn("/backups", unit)
        self.assertIn("API_TRUST_PROXY=false", remote.environment_text(3100))

    def test_user_and_paths_are_not_adopted_without_installer_state(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            with contextlib.ExitStack() as stack:
                for name in ("BASE", "CONFIG", "DATA", "BACKUPS", "CACHE", "UNIT"):
                    stack.enter_context(patch.object(remote, name, base / name))
                (base / "DATA").mkdir()
                with self.assertRaisesRegex(remote.InstallError, "UNMANAGED_PATH_COLLISION"):
                    remote.load_state()

    def test_parallel_installations_use_same_non_unlinked_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            actual_fstat = remote.os.fstat
            def root_file(fd):
                info = actual_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink)
            # Mock only ownership for unprivileged unit tests; flock is real.
            with patch.object(remote, "LOCK", Path(folder) / "lock"), patch.object(remote.os, "fstat", side_effect=root_file):
                with remote.install_lock():
                    with self.assertRaisesRegex(remote.InstallError, "INSTALL_ALREADY_RUNNING"):
                        with remote.install_lock():
                            self.fail("concurrent installation acquired lock")
                self.assertTrue(remote.LOCK.exists())
                with remote.install_lock():
                    pass

    def test_manual_workflow_has_only_one_input_and_no_automatic_push(self):
        # YAML need not be a runtime dependency: validate input/action boundary text here.
        text = (SCRIPTS.parents[1] / ".github/workflows/install-studio.yml").read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("  push:", text)
        self.assertEqual(text.count("required: true"), 1)
        self.assertIn("server_ip:", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("${{ secrets.STUDIO_SSH_PASSWORD }}", text)
        self.assertNotIn("ssh-keyscan", text)


if __name__ == "__main__":
    unittest.main()
