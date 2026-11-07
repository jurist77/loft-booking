"""Actual audited UFW parser/serializer/CLI, isolated files and fake kernel I/O.

The .deb is extracted as test data, NEVER installed. Every subprocess boundary
is replaced; assertions forbid capability-test chains, flush, reload and delete.
"""
import contextlib
import gettext
import hashlib
import importlib
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_studio_http_access import fixture
import host


@unittest.skipUnless(os.environ.get("STUDIO_UFW_TEST_SOURCE"), "set STUDIO_UFW_TEST_SOURCE to the checksum-verified extracted Ubuntu UFW package")
class AuditedUFWTests(unittest.TestCase):
    def setUp(self):
        self.source = Path(os.environ["STUDIO_UFW_TEST_SOURCE"]).resolve()
        for path, expected in host.UFW_HASHES.items():
            self.assertEqual(hashlib.sha256((self.source / path.lstrip("/")).read_bytes()).hexdigest(), expected)
        self.old_modules = {key: value for key, value in sys.modules.items() if key == "ufw" or key.startswith("ufw.")}
        for key in self.old_modules: del sys.modules[key]
        self.old_path = sys.path[:]
        sys.path.insert(0, str(self.source / "usr/lib/python3/dist-packages"))
        gettext.install("ufw")
        self.ufw = importlib.import_module("ufw")
        self.backend = importlib.import_module("ufw.backend")
        self.backend_ip = importlib.import_module("ufw.backend_iptables")
        self.common = importlib.import_module("ufw.common")
        self.util = importlib.import_module("ufw.util")
        self.frontend = importlib.import_module("ufw.frontend")
        self.temp = tempfile.TemporaryDirectory(prefix="studio-ufw-fixture-")
        self.root = Path(self.temp.name)
        (self.root / "etc/default").mkdir(parents=True)
        (self.root / "etc/ufw/applications.d").mkdir(parents=True)
        shutil.copyfile(self.source / "etc/default/ufw", self.root / "etc/default/ufw")
        (self.root / "etc/ufw/ufw.conf").write_text("ENABLED=yes\nLOGLEVEL=low\n")
        self.data = fixture(); self.commands = []
        for version, name in ((4, "user.rules"), (6, "user6.rules")):
            (self.root / "etc/ufw" / name).write_text(self.data["user" + str(version)])
        self.patches = []
        self.addCleanup(self.cleanup)
        def patch_value(obj, name, value):
            p = patch.object(obj, name, value); p.start(); self.patches.append(p)
        self.patch_value = patch_value
        patch_value(self.common, "do_checks", False)
        # Assert no actual process, including reads, can be launched by UFW.
        self.real_popen = patch("subprocess.Popen", side_effect=AssertionError("real subprocess forbidden")); self.real_popen.start()
        def kernel(argv, allow_append=False):
            self.commands.append(argv[:]); args = argv[1:]
            if args in (["--version"], ["-V"]): return 0, "iptables v1.8.10 (nf_tables)"
            if args[:1] in (["-L"], ["-n"]): return 0, ""
            if argv[0] == "sysctl" and args in (["net.ipv4.ip_forward"], ["net.ipv6.conf.default.forwarding"], ["net.ipv6.conf.all.forwarding"]): return 0, args[0] + " = 1"
            if args[:1] == ["-A"] and args[1] in ("ufw-user-input", "ufw6-user-input") and args[2:] == ["-p", "tcp", "--dport", "3000", "-j", "ACCEPT"]: return 0, ""
            raise AssertionError("forbidden firewall command")
        for module in (self.util, self.backend_ip): patch_value(module, "cmd", kernel)
        patch_value(host, "ufw_io", kernel)
        ctor = self.backend_ip.UFWBackendIptables.__init__
        def isolated_constructor(obj, dryrun, rootdir=None, datadir=None):
            return ctor(obj, dryrun, rootdir=str(self.root), datadir=str(self.root))
        patch_value(self.backend_ip.UFWBackendIptables, "__init__", isolated_constructor)
        # Generate real, complete starting files using the audited serializer.
        backend = self.backend_ip.UFWBackendIptables(False)
        backend.caps = {"limit": {"4": True, "6": True}}
        for version, name in ((4, "user.rules"), (6, "user6.rules")):
            backend._write_rules(version == 6)
            self.data["user" + str(version)] = (self.root / "etc/ufw" / name).read_text()
        real_run = host.runpy.run_path
        patch_value(host.runpy, "run_path", lambda path, **kwargs: real_run(str(self.source / "usr/sbin/ufw"), **kwargs))
        self.commands.clear()

    def cleanup(self):
        for p in reversed(self.patches): p.stop()
        self.real_popen.stop()
        self.temp.cleanup(); sys.path[:] = self.old_path
        for key in list(sys.modules):
            if key == "ufw" or key.startswith("ufw."): del sys.modules[key]
        sys.modules.update(self.old_modules)

    def test_real_ufw_plan_has_no_writes_then_one_allow_each_family(self):
        old4 = (self.root / "etc/ufw/user.rules").read_bytes()
        old6 = (self.root / "etc/ufw/user6.rules").read_bytes()
        host.ufw_operation(self.data, apply=False)
        self.assertEqual((self.root / "etc/ufw/user.rules").read_bytes(), old4)
        self.assertEqual((self.root / "etc/ufw/user6.rules").read_bytes(), old6)
        self.assertFalse(any("-A" in args for args in self.commands))
        self.commands.clear()
        host.ufw_operation(self.data, apply=True)
        appends = [args for args in self.commands if "-A" in args]
        self.assertEqual(len(appends), 2)
        self.assertEqual([args[2] for args in appends], ["ufw-user-input", "ufw6-user-input"])
        for version, name in ((4, "user.rules"), (6, "user6.rules")):
            new = (self.root / "etc/ufw" / name).read_text()
            self.assertTrue(host.persistent_delta(self.data["user" + str(version)], new, version))
        for command in self.commands:
            self.assertFalse(any(arg in command for arg in ("-N", "-D", "-F", "-X", "-I", "-P", "reload", "reset")))

    def test_unrepresented_persisted_rule_aborts_plan_without_changes(self):
        path = self.root / "etc/ufw/user.rules"
        text = path.read_text().replace("COMMIT", "-A ufw-user-input -p tcp --dport 4444 -j ACCEPT\nCOMMIT")
        path.write_text(text); self.data["user4"] = text
        with self.assertRaises(host.Unsafe): host.ufw_operation(self.data, apply=False)
        self.assertEqual(path.read_text(), text)
        self.assertFalse(any("-A" in args for args in self.commands))

    def test_actual_ufw_append_error_stops_without_other_family_or_rollback(self):
        real_io = host.ufw_io
        def fail_append(argv, allow_append=False):
            if allow_append: return 1, "not logged"
            return real_io(argv)
        with patch.object(host, "ufw_io", fail_append), self.assertRaisesRegex(host.Unsafe, "UFW_ADD_FAILED"):
            # Error text is not exposed; partial persisted state is retained for
            # manual review, never followed by any delete/flush/reload command.
            host.ufw_operation(self.data, apply=True)
        self.assertEqual((self.root / "etc/ufw/user6.rules").read_text(), self.data["user6"])
        self.assertFalse(any("-D" in args or "-F" in args for args in self.commands))

    def test_read_status_uses_no_caps_probe_or_mutation(self):
        with patch.object(host, "ufw_implementation"), patch.object(self.util, "_print") as log:
            state, status = host.read_host("ufw")
        self.assertEqual(state, "ok"); log.assert_not_called()
        self.assertIn("Status: active", status)
        for command in self.commands: self.assertFalse(any(arg in command for arg in ("-N", "-D", "-F", "-X", "-A")))

    def test_import_time_stdout_messages_cannot_leak_from_cli(self):
        actual_run = host.runpy.run_path
        def noisy_cli(path, **kwargs):
            self.util.msg("SYNTHETIC_SECRET_MUST_NOT_APPEAR")
            return actual_run(path, **kwargs)
        with patch.object(self.util, "_print") as log, patch.object(host.runpy, "run_path", noisy_cli), contextlib.redirect_stdout(io.StringIO()) as output:
            host.ufw_operation(self.data, apply=False)
        log.assert_not_called(); self.assertEqual(output.getvalue(), "")


if __name__ == "__main__": unittest.main()
