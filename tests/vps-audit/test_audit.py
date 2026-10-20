"""Security/parsing tests use fixtures; no SSH or real privileged commands."""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/vps-audit.py"
spec = importlib.util.spec_from_file_location("audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
SECRET = "CLIENT_SECRET_MUST_NOT_ESCAPE"


class AuditTests(unittest.TestCase):
    def test_service_and_process_names_are_closed_categories(self):
        self.assertEqual(audit.category("xray@" + SECRET + ".service"), "xray")
        self.assertEqual(audit.category(SECRET), "other")
        self.assertEqual(audit.category("vpn-manager.service"), "vpn-manager")
        self.assertEqual(audit.category("next-server (v16"), "node/next")
        self.assertEqual(audit.services("xray.service loaded active running secret description\n"
                                        + SECRET + ".service loaded active running secret"), {"other": 1, "xray": 1})

    def test_ports_ipv4_ipv6_udp_and_no_client_addresses(self):
        raw = ('tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=8,fd=3))\n'
               'tcp LISTEN 0 128 [::1]:3000 [::]:* users:(("node",pid=9,fd=3))\n'
               'udp UNCONN 0 0 203.0.113.77:51820 0.0.0.0:* users:(("' + SECRET + '",pid=10,fd=1))\n'
               'tcp LISTEN 0 10 127.0.0.1:80 0.0.0.0:*\n')
        result = audit.listeners(raw)
        self.assertEqual([row["port"] for row in result], [80, 443, 3000, 51820])
        self.assertEqual(result[1]["owners"], ["xray"])
        self.assertEqual(result[2]["bind"], "loopback")
        self.assertEqual(result[3]["bind"], "specific-redacted")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn("203.0.113.77", json.dumps(result))
        self.assertEqual(audit.listeners("arbitrary malformed " + SECRET), [])

    def test_firewall_has_only_policies_and_counts(self):
        result = audit.firewall("iptables", "-P INPUT DROP\n-N " + SECRET + "\n-A INPUT -s 203.0.113.77 -m comment --comment " + SECRET)
        self.assertEqual(result, {"default_policies": {"INPUT": "DROP"}, "rule_count": 1})
        self.assertEqual(audit.firewall("nft", "table inet " + SECRET), {"table_count": 1})
        self.assertEqual(audit.firewall("ufw", "Status: active\n" + SECRET), {"state": "active"})

    def test_cpu_pressure_memory_parsing(self):
        self.assertEqual(audit.numbers("MemTotal: 1024 kB\nVmHWM: 888 kB\noom_kill 2\n"), {"MemTotal": 1024, "VmHWM": 888, "oom_kill": 2})
        self.assertEqual(audit.cpu_ticks("cpu 10 0 20 50 10 2 3 5 10 0\n"), (100, 60))
        self.assertEqual(audit.cpu_usage((100, 60), (200, 110)), 50)
        self.assertIsNone(audit.cpu_usage(None, (100, 10)))
        self.assertIsNone(audit.cpu_usage((100, 50), (100, 50)))
        self.assertEqual(audit.pressure("some avg10=1.25 avg60=0.00 avg300=0.50 total=25\n"), {"some": {"avg10": 1.25, "avg60": 0., "avg300": .5, "total": 25.}})
        self.assertIsNone(audit.pressure(None))

    def test_missing_permission_timeout_never_return_raw_errors(self):
        with patch.object(audit.shutil, "which", return_value=None):
            self.assertEqual(audit.run_command("listeners"), {"status": "missing"})
        with patch.object(audit.shutil, "which", return_value="/usr/bin/ss"):
            with patch.object(audit.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, SECRET, SECRET)) as run:
                self.assertEqual(audit.run_command("listeners"), {"status": "unavailable"})
                self.assertNotIn("shell", run.call_args.kwargs)
                self.assertEqual(run.call_args.args[0], ["/usr/bin/ss", "-H", "-lntup"])
                self.assertEqual(run.call_args.kwargs["timeout"], 8)
            with patch.object(audit.subprocess, "run", side_effect=subprocess.TimeoutExpired(SECRET, 8)):
                self.assertEqual(audit.run_command("listeners"), {"status": "timeout"})

    def test_degraded_is_not_healthy_and_failed_units_are_redacted(self):
        self.assertEqual(audit.command_report("system_state", {"status": "ok", "raw": "degraded\n"}), {"status": "ok", "value": "degraded"})
        self.assertEqual(audit.command_report("system_state", {"status": "ok", "raw": SECRET})["value"], "unknown")
        self.assertEqual(audit.command_report("node", {"status": "ok", "raw": SECRET})["value"], "unknown")
        self.assertEqual(audit.command_report("node", {"status": "ok", "raw": "v24.19.0\n"})["value"], "v24.19.0")
        self.assertEqual(audit.command_report("ufw", {"status": "unavailable"}), {"status": "unavailable"})

    def test_snapshot_is_read_only_and_does_not_read_argv_configs_or_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "777").mkdir()
            fixtures = {"meminfo": "MemTotal: 2000 kB\nMemAvailable: 1000 kB\n", "stat": "cpu 10 0 20 50 10 2 3 5\n",
                        "uptime": "1234.0 1234.0", "vmstat": "oom_kill 2\n",
                        "777/comm": SECRET, "777/status": "VmRSS: 100 kB\nVmHWM: 200 kB\n",
                        "777/cmdline": SECRET, "777/environ": SECRET}
            for name, value in fixtures.items():
                (proc / name).write_text(value)
            before = {name: (proc / name).read_bytes() for name in fixtures}
            reads = []
            actual_read = audit.read_text

            def reader(path):
                reads.append(str(path))
                return actual_read(path)

            with patch.object(audit, "read_text", side_effect=reader):
                result = audit.snapshot("sweden", proc=proc, runner=lambda _: {"status": "missing"}, pause=lambda _: None)
            self.assertEqual(result["memory_kib"]["MemAvailable"], 1000)
            self.assertEqual(result["vm_counters_since_boot"]["oom_kill"], 2)
            self.assertEqual(result["process_memory"]["top_rss"][0], {"category": "other", "rss_kib": 100, "lifetime_hwm_kib": 200})
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertFalse(any(name.endswith(("cmdline", "environ")) or "/etc/x-ui" in name or "/journal" in name for name in reads))
            self.assertEqual(before, {name: (proc / name).read_bytes() for name in fixtures})

    def test_missing_essential_data_is_not_success(self):
        with patch.object(audit, "snapshot", return_value={"memory_kib": {"MemTotal": None}, "system": {"uptime_seconds": 2}}), \
                patch("sys.argv", [str(SCRIPT), "--label", "finland"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(), 2)

    def test_unexpected_os_error_is_safe(self):
        with patch.object(audit, "snapshot", side_effect=OSError(SECRET)), \
                patch("sys.argv", [str(SCRIPT), "--label", "finland"]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(), 2)
            self.assertNotIn(SECRET, output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["error"], "AUDIT_UNAVAILABLE")

    def test_read_only_command_allowlist_and_no_write_apis(self):
        expected = {"systemctl", "ss", "ufw", "nft", "iptables", "ip6tables", "node"}
        self.assertEqual({args[0] for args in audit.COMMANDS.values()}, expected)
        allowed_actions = {"systemctl": {"list-units", "list-unit-files", "is-system-running"},
                           "ss": {"-H"}, "ufw": {"status"}, "nft": {"list"},
                           "iptables": {"-S"}, "ip6tables": {"-S"}, "node": {"--version"}}
        for args in audit.COMMANDS.values():
            self.assertIn(args[1], allowed_actions[args[0]])
        self.assertEqual(audit.COMMANDS["nft"], ("nft", "list", "tables"))
        tree = ast.parse(SCRIPT.read_text())
        forbidden = {"write_text", "write_bytes", "unlink", "mkdir", "chmod", "chown", "rename", "replace", "rmdir", "system", "popen", "exec", "eval"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)
        self.assertNotIn("shell=True", SCRIPT.read_text())

    def test_all_command_reports_drop_secrets_even_in_successful_stdout(self):
        for key in audit.COMMANDS:
            raw = SECRET + ".service secret description\n203.0.113.77 " + SECRET
            report = audit.command_report(key, {"status": "ok", "raw": raw})
            self.assertNotIn(SECRET, json.dumps(report), key)
            self.assertNotIn("203.0.113.77", json.dumps(report), key)


if __name__ == "__main__":
    unittest.main()
