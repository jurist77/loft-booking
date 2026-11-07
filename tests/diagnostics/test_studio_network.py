"""No real SSH, VPS, firewall query or production diagnostic is invoked."""
import contextlib
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/diagnostics"
sys.path.insert(0, str(SCRIPTS))
import studio_network as runner
import probe_studio_network as probe
sys.path.pop(0)

MARKER = "SYNTHETIC_SENSITIVE_CANARY_NEVER_LOG"
ADDRESS = "192.0.2.10"  # TEST-NET, never contacted.
OK = {"http": 200, "ok": True, "error": "none"}
REFUSED = {"http": None, "ok": False, "error": "refused"}


def fixture(**overrides):
    values = {
        "service": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4321\n",
        "sockets4": f'LISTEN 0 511 0.0.0.0:3000 0.0.0.0:* users:(("{MARKER}",pid=4321,fd=4))\n'
                    f'LISTEN 0 511 198.51.100.99:443 0.0.0.0:* users:(("{MARKER}",pid=999,fd=5))\n',
        "sockets6": "", "ufw": "Status: inactive\n", "nft": '{"nftables":[]}',
        "iptables": "*filter\n:INPUT ACCEPT [10:20]\nCOMMIT\n", "ip6tables": "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
    }
    values.update(overrides)
    return probe.collect(lambda name: values[name] if isinstance(values[name], tuple) else ("ok", values[name]), lambda address: copy.deepcopy(OK))


class DiagnosticTests(unittest.TestCase):
    def test_read_only_command_allowlist_and_isolated_remote_python(self):
        self.assertEqual(probe.COMMANDS, {
            "service": ("systemctl", "show", "studio1925.service", "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID"),
            "sockets4": ("ss", "-H", "-4", "-lntp"), "sockets6": ("ss", "-H", "-6", "-lntp"),
            "ufw": ("ufw", "status", "verbose"), "nft": ("nft", "-j", "list", "ruleset"),
            "iptables": ("iptables-save", "-t", "filter"), "ip6tables": ("ip6tables-save", "-t", "filter"),
        })
        self.assertEqual(runner.REMOTE_COMMAND, "python3 -I -B -S -")
        with self.assertRaises(KeyError): probe.read_command("restart")
        source = (SCRIPTS / "probe_studio_network.py").read_text()
        for forbidden in ("write_text", "write_bytes", "loadEnv", "journalctl", "readlink", "/etc/", "os.system", "shell=True", "apt-get"):
            self.assertNotIn(forbidden, source)

    def test_only_studio_and_port_3000_binds_are_reported(self):
        result = runner.validate_remote(fixture())
        self.assertEqual(result["sockets"][0]["bindings"], [{"address": "0.0.0.0", "family": 4, "port": 3000, "scoped": False, "kind": "wildcard", "owner": "studio"}])
        self.assertNotIn(MARKER, json.dumps(result))
        self.assertNotIn("198.51.100.99", json.dumps(result))
        self.assertNotIn("MainPID", result["service"])

    def test_another_studio_port_and_unknown_process_ownership(self):
        data = fixture(sockets4='LISTEN 0 100 127.0.0.1:3100 0.0.0.0:* users:(("node",pid=4321,fd=5))')
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "STUDIO_USES_DIFFERENT_PORT")
        data = fixture(service="LoadState=loaded\nActiveState=active\nMainPID=0\n")
        self.assertEqual(data["sockets"][0]["bindings"][0]["owner"], "unknown")
        data = fixture(sockets4='LISTEN 0 100 0.0.0.0:3000 0.0.0.0:* users:(("other",pid=999,fd=5))')
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "PORT_OWNED_BY_OTHER_PROCESS")
        self.assertEqual(runner.probable_cause(data, OK, ADDRESS), "SERVICE_STATUS_DISAGREES")

    def test_ipv6_wildcard_scope_and_malformed_addresses(self):
        data = fixture(sockets4="", sockets6=f'LISTEN 0 100 [::]:3000 [::]:* users:(("node",pid=4321,fd=4))\nLISTEN 0 10 [fe80::1%{MARKER}]:3100 [::]:* users:(("node",pid=4321,fd=6))\nLISTEN 0 100 not-an-ip:3000 *:*')
        runner.validate_remote(data)
        self.assertEqual(data["sockets"][1]["bindings"][0]["address"], "::")
        self.assertEqual(data["sockets"][1]["bindings"][1]["address"], "fe80::1")
        self.assertNotIn(MARKER, json.dumps(data))
        data["local4"] = REFUSED
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "IP_FAMILY_BIND_MISMATCH")

    def test_cause_service_bind_port_and_health_failure(self):
        data = fixture(); data["service"]["ActiveState"] = "failed"
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "SERVICE_NOT_ACTIVE")
        self.assertEqual(runner.probable_cause(data, OK, ADDRESS), "SERVICE_STATUS_DISAGREES")
        data = fixture(sockets4="")
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "NO_PORT_3000_LISTENER")
        data = fixture(sockets4=("missing", ""))
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "SOCKET_STATE_UNKNOWN")
        data = fixture(sockets4='LISTEN 0 100 127.0.0.1:3000 *:* users:(("node",pid=4321,fd=5))')
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "LOOPBACK_BIND")
        data = fixture(); data["local4"] = {"http": 503, "ok": False, "error": "unexpected_response"}
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "LOCAL_HEALTH_FAILED")
        self.assertEqual(runner.probable_cause(fixture(), OK, ADDRESS), "EXTERNAL_HEALTHY")
        incomplete = fixture(sockets6=("missing", ""))
        self.assertEqual(runner.probable_cause(incomplete, OK, ADDRESS), "SERVICE_STATUS_DISAGREES")
        self.assertEqual(runner.probable_cause(fixture(), REFUSED, ADDRESS), "HOST_OR_UPSTREAM_UNDETERMINED")

    def test_firewall_summaries_never_disclose_comments_addresses_or_chain_names(self):
        nft = {"nftables": [
            {"chain": {"family": "inet", "table": MARKER, "name": MARKER, "hook": "input", "policy": "drop"}},
            {"rule": {"family": "inet", "table": MARKER, "chain": MARKER, "comment": MARKER, "expr": [
                {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 3000}},
                {"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "op": "==", "right": "198.51.100.77"}}, {"drop": None}]}},
            {"rule": {"family": "inet", "table": MARKER, "chain": MARKER, "expr": [{"jump": {"target": MARKER}}]}},
        ]}
        data = fixture(ufw=f'Status: active\nDefault: deny (incoming), allow (outgoing)\n3000/tcp ALLOW IN 198.51.100.77 # {MARKER}\n443/tcp ALLOW IN Anywhere # {MARKER}\n',
                       nft=json.dumps(nft), iptables=f'*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 3000 -s 198.51.100.77 -m comment --comment "{MARKER}" -j REJECT\n-A INPUT -j {MARKER}\n')
        runner.validate_remote(data)
        self.assertEqual(data["firewall"]["nft"]["direct_port3000"]["drop"], 1)
        self.assertTrue(data["firewall"]["nft"]["indirect"])
        self.assertEqual(data["firewall"]["iptables4"]["direct_port3000"]["reject"], 1)
        self.assertTrue(data["firewall"]["iptables4"]["indirect"])
        self.assertNotIn(MARKER, json.dumps(data)); self.assertNotIn("198.51.100.77", json.dumps(data))
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "HOST_FIREWALL_POSSIBLE")

    def test_missing_tools_and_unsupported_rules_are_uncertain_not_free_schedule(self):
        data = fixture(ufw=("missing", ""), nft=("ok", '{"broken":true}'), iptables=("timeout", ""), ip6tables=("error", MARKER))
        runner.validate_remote(data)
        self.assertEqual(data["firewall"]["nft"]["read"], "error")
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "HOST_OR_UPSTREAM_UNDETERMINED")
        self.assertNotIn(MARKER, json.dumps(data))
        data["sockets"][0]["limited"] = True
        self.assertEqual(runner.probable_cause(data, REFUSED, ADDRESS), "SOCKET_STATE_UNKNOWN")

    def test_nft_output_chain_and_comments_cannot_be_treated_as_input_drop(self):
        raw = json.dumps({"nftables": [{"chain": {"family": "inet", "table": "x", "name": "out", "hook": "output", "policy": "drop"}},
            {"rule": {"family": "inet", "table": "x", "chain": "out", "expr": [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 3000}}, {"drop": None}]}}]})
        result = probe.nft_summary("ok", raw)
        self.assertEqual(result["input_policies"], []); self.assertEqual(result["direct_port3000"]["drop"], 0)
        self.assertEqual(probe.ufw_summary("ok", f'443/tcp ALLOW IN Anywhere # 3000 {MARKER}')['port3000']['accept'], 0)

    def test_remote_schema_rejects_untrusted_extra_fields_and_values(self):
        for mutate in (lambda d: d.update(secret=MARKER), lambda d: d["service"].update(ActiveState=MARKER),
                       lambda d: d["sockets"][0]["bindings"][0].update(address=MARKER),
                       lambda d: d["local4"].update(body=MARKER), lambda d: d["firewall"]["ufw"].update(default_incoming=MARKER)):
            data = fixture(); mutate(data)
            with self.assertRaises(runner.ProtocolError): runner.validate_remote(data)

    def test_coordinator_uses_existing_ssh_policy_and_private_file_closes_on_failure(self):
        streams = []
        def execute(command, source, **kwargs):
            self.assertEqual(command, runner.REMOTE_COMMAND)
            self.assertIsInstance(source.fileno(), int); self.assertEqual(os.fstat(source.fileno()).st_mode & 0o777, 0o600)
            self.assertEqual(source.read(), (SCRIPTS / "probe_studio_network.py").read_bytes())
            streams.append(source); return fixture()
        ssh = Mock(); ssh.execute.side_effect = execute
        factory = Mock(return_value=ssh); health = Mock(return_value=OK)
        report = runner.diagnose(ADDRESS, MARKER, factory, health)
        self.assertEqual(report["probable_cause"], "EXTERNAL_HEALTHY")
        factory.assert_called_once_with(ADDRESS, MARKER); health.assert_called_once_with(ADDRESS, 3000)
        self.assertTrue(streams[0].closed)
        transport = runner.SSH(ADDRESS, MARKER)
        args = transport.arguments("true")
        self.assertIn("StrictHostKeyChecking=no", args); self.assertIn("root@" + ADDRESS, args); self.assertNotIn(MARKER, " ".join(args))
        ssh.execute.side_effect = runner.DeployError("SSH_AUTH_FAILED")
        report = runner.diagnose(ADDRESS, MARKER, factory, Mock(return_value=REFUSED))
        self.assertEqual(report["status"], "partial"); self.assertEqual(report["ssh"], "SSH_AUTH_FAILED")
        self.assertNotIn(MARKER, json.dumps(report))

    def test_malicious_remote_payload_is_not_emitted_in_summary(self):
        data = fixture(); data["secret"] = MARKER
        ssh = Mock(); ssh.execute.return_value = data
        report = runner.diagnose(ADDRESS, MARKER, lambda *args: ssh, lambda *args: REFUSED)
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}), contextlib.redirect_stdout(io.StringIO()) as log:
                runner.emit(report)
            self.assertNotIn(MARKER, log.getvalue() + summary.read_text())
            self.assertEqual(report["ssh"], "REMOTE_PROTOCOL_FAILED")

    def test_input_and_missing_secret_fail_before_any_network_operation(self):
        for address, password in (("$(touch /tmp/never)", MARKER), ("https://192.0.2.1", MARKER), ("127.0.0.1", MARKER), (ADDRESS, "")):
            with patch.dict(os.environ, {"STUDIO_SERVER_IP": address, "STUDIO_SSH_PASSWORD": password, "GITHUB_STEP_SUMMARY": ""}), \
                    patch.object(runner, "diagnose") as diagnose, contextlib.redirect_stdout(io.StringIO()) as log:
                self.assertEqual(runner.main(), 1); diagnose.assert_not_called(); self.assertNotIn(MARKER, log.getvalue())

    def test_ipv6_external_url_and_partial_results(self):
        ssh = Mock(); ssh.execute.return_value = fixture(ufw=("missing", ""))
        report = runner.diagnose("2001:db8::1", MARKER, lambda *a: ssh, lambda *a: REFUSED)
        self.assertEqual(report["checked_url"], "http://[2001:db8::1]:3000/api/health")
        self.assertEqual(report["status"], "partial")

    def test_bounded_reader_uses_only_own_child_and_handles_limit_timeout_missing(self):
        actual_popen = subprocess.Popen; children = []
        def start(*a, **kw):
            self.assertNotIn("shell", kw); self.assertEqual(kw["env"]["PYTHONDONTWRITEBYTECODE"], "1")
            child = actual_popen(*a, **kw); children.append(child); return child
        for code, expected in (("print('fixture')", "ok"), ("print('x'*100)", "output_limit"), ("import time;time.sleep(30)", "timeout")):
            with patch.dict(probe.COMMANDS, {"fixture": (sys.executable, "-c", code)}), \
                    patch.object(probe.shutil, "which", return_value=sys.executable), patch.object(probe.subprocess, "Popen", side_effect=start), \
                    patch.object(probe, "LIMIT", 64), patch.object(probe, "deadline", side_effect=lambda _: self.real_deadline(.15)):
                status, raw = probe.read_command("fixture")
                self.assertEqual(status, expected)
                if status != "ok": self.assertEqual(raw, "")
        for child in children: self.assertIsNotNone(child.poll()); self.assertTrue(child.stdout.closed)
        with patch.object(probe.shutil, "which", return_value=None): self.assertEqual(probe.read_command("service"), ("missing", ""))

    real_deadline = staticmethod(probe.deadline)

    def test_real_local_fixture_http_only_get_no_redirect_or_sensitive_body(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                requests.append(self.path)
                self.send_response(self.server.code)
                if self.server.code == 302: self.send_header("Location", "http://192.0.2.99/never-follow")
                self.end_headers()
                try:
                    if self.server.slow: time.sleep(.3)
                    self.wfile.write(self.server.body)
                except OSError: pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler); server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            for code, body, ok in ((200, b'{"status":"ok"}', True), (503, b'{"status":"unavailable"}', False),
                                   (302, MARKER.encode(), False), (200, b'x'*600, False)):
                server.code = code; server.body = body; server.slow = False
                result = probe.read_health("127.0.0.1", server.server_port)
                self.assertEqual(result["ok"], ok); self.assertEqual(result["http"], code)
                self.assertNotIn(MARKER, json.dumps(result))
            server.code = 200; server.body = b'{"status":"ok"}'; server.slow = True
            with patch.object(probe, "deadline", side_effect=lambda _: self.real_deadline(.1)):
                self.assertEqual(probe.read_health("127.0.0.1", server.server_port)["error"], "timeout")
            self.assertEqual(requests, ["/api/health"] * 5)
        finally: server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_workflow_is_manual_only_and_never_deploys_or_mutates_host(self):
        workflow = (SCRIPTS.parents[1] / ".github/workflows/diagnose-studio-network.yml").read_text()
        self.assertIn("name: Diagnose Studio network", workflow)
        self.assertIn("workflow_dispatch:", workflow); self.assertNotIn("  push:", workflow); self.assertNotIn("  schedule:", workflow)
        self.assertEqual(workflow.count("required: true"), 1); self.assertIn("server_ip:", workflow)
        self.assertIn("secrets.STUDIO_SSH_PASSWORD", workflow); self.assertIn("contents: read", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        for text in ("systemctl restart", "systemctl stop", "ufw allow", "ufw enable", "nft add", "iptables -A", "manage.py install", "STUDIO_BACKUP_TOKEN"):
            self.assertNotIn(text, workflow)


if __name__ == "__main__": unittest.main()
