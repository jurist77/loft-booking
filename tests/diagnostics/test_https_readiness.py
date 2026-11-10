"""Fixtures only. Never execute the inventory on this host or any VPS."""
import ast
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/diagnostics"))
import https_readiness as runner
import probe_https_readiness as probe

IP = "192.0.2.10"  # TEST-NET. All tests intercept this address before a socket.
CANARY = "SYNTHETIC_SECRET_NAME_PHONE_VPN_KEY_DO_NOT_LOG"
HEALTH = {"http": 200, "ok": True, "error": "none"}
EXTERNAL = {"tcp80": "refused", "tcp443": "refused", "tls443_for_ip": "not_checked", "certificate_lifetime": "unknown"}
SOCKET = 'LISTEN 0 511 0.0.0.0:3000 0.0.0.0:* users:(("node",pid=4321,fd=4)) ino:123 sk:abcd'


def fixture(overrides=None, mutate_read=None, collector=probe.collect, **kwargs):
    kwargs.setdefault('residue', probe.tls_empty_report)
    values = {"service": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4321\nUser=studio1925\nRootDirectory=/opt/studio1925/releases/test/root\nWorkingDirectory=/app\nPrivateNetwork=no\nNetworkNamespacePath=\nDropInPaths=\n",
        "sockets4": SOCKET, "sockets6": "", "web4": "", "web6": "", "units": "", "clock": "status: 0\n",
        "ufw": "Status: inactive\n", "nft": '{"nftables":[{"chain":{"hook":"input","policy":"accept"}}]}'}
    values.update({name: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n" for name in ("iptables", "ip6tables", "legacy4", "legacy6")})
    values.update(overrides or {})
    reads = {}
    def run(name):
        reads[name] = reads.get(name, 0) + 1
        value = values[name] if isinstance(values[name], tuple) else ("ok", values[name])
        return mutate_read(name, reads[name], value) if mutate_read else value
    def inspect(path):
        directory = path in ("/etc/studio1925", "/var/lib/studio1925")
        return SimpleNamespace(st_mode=(stat.S_IFDIR | 0o700) if directory else stat.S_IFREG | 0o600,
                               st_uid=1001 if path == "/var/lib/studio1925" else 0)
    return collector(run=run, health=lambda *a: copy.deepcopy(HEALTH), inspect=inspect,
        readlink=lambda path: "socket:[123]", available=lambda name: None,
        files=lambda path: 'ID=ubuntu\nVERSION_ID="24.04"\n', machine=lambda: "x86_64", euid=lambda: 0,
        account=lambda name: SimpleNamespace(pw_uid=1001, pw_gid=1001), **kwargs)


class HttpsReadinessTests(unittest.TestCase):
    def test_free_ports_are_not_install_authorization(self):
        value = runner.validate(fixture())
        self.assertEqual(runner.verdict(value, EXTERNAL), "FREE_PORTS_OBSERVED_REVIEW_REQUIRED")
        self.assertTrue(value["studio"]["listener_owned"])
        self.assertLess(len(json.dumps(value).encode()), 10000)
        self.assertEqual(value["mechanisms"]["custom_configuration"], "not_inspected")

    def test_occupied_443_always_blocks_regardless_of_program_or_loopback(self):
        for program in ("nginx", "caddy", "xray", "x-ui", CANARY):
            for bind in ("0.0.0.0", "127.0.0.1", "198.51.100.77"):
                value = fixture({"web4": f'LISTEN 0 511 {bind}:443 *:* users:(("{program}",pid=88,fd=9)) ino:88 sk:abc'})
                self.assertEqual(runner.verdict(runner.validate(value), EXTERNAL), "EXISTING_443_LISTENER")
                self.assertNotIn(CANARY, json.dumps(value)); self.assertNotIn("198.51.100.77", json.dumps(value))
                self.assertNotIn('"pid"', json.dumps(value))

    def test_ipv6_wildcard_v6only_and_dual_stack_are_observations_not_free_ipv4(self):
        for option in ("v6only:0", "v6only:1", ""):
            value = fixture({"web6": f'LISTEN 0 511 [::]:443 [::]:* users:(("xray",pid=88,fd=9)) ino:88 sk:abc {option}'})
            runner.validate(value)
            self.assertEqual(runner.verdict(value, EXTERNAL), "EXISTING_443_LISTENER")
            self.assertEqual(value["ports"]["6"]["listeners"][0]["v6only"], option[-1] if option else "unknown")

    def test_occupied_80_requires_alternative_challenge_without_stopping_owner(self):
        value = fixture({"web4": 'LISTEN 0 511 0.0.0.0:80 *:* users:(("apache2",pid=88,fd=9))'})
        self.assertEqual(runner.verdict(value, EXTERNAL), "PORT_80_CHALLENGE_REVIEW")

    def test_missing_tools_malformed_or_truncated_ss_never_proves_free_ports(self):
        for value in (("missing", ""), ("timeout", ""), ("output_limit", ""), "malformed line"):
            self.assertEqual(runner.verdict(fixture({"web4": value}), EXTERNAL), "INCONCLUSIVE")
        raw = '\n'.join('LISTEN 0 511 0.0.0.0:80 *:* users:(("nginx",pid=88,fd=9))' for _ in range(5))
        value = fixture({"web4": raw}); self.assertTrue(value["ports"]["4"]["limited"])
        self.assertEqual(runner.verdict(value, EXTERNAL), "INCONCLUSIVE")

    def test_studio_health_ownership_restart_and_systemd_namespace_checks(self):
        for change in (lambda v: v["studio"].update(listener_owned=False), lambda v: v["studio"].update(managed_rootfs=False),
                       lambda v: v["studio"].update(isolated_user=False), lambda v: v["studio"].update(permissions_compatible=False), lambda v: v["studio"].update(private_network="yes"),
                       lambda v: v["studio"].update(network_namespace=True), lambda v: v["host"].update(ubuntu24=False),
                       lambda v: v["host"].update(arch="unsupported"), lambda v: v["host"].update(root=False),
                       lambda v: v["studio"]["local_health"].update(http=503, ok=False, error="unexpected_response")):
            value = fixture(); change(value)
            self.assertEqual(runner.verdict(value, EXTERNAL), "STUDIO_PREFLIGHT_FAILED")
        value = fixture({"sockets4": SOCKET.replace("pid=4321", "pid=999")})
        self.assertFalse(value["studio"]["listener_owned"])
        self.assertEqual(runner.verdict(value, EXTERNAL), "STUDIO_PREFLIGHT_FAILED")
        # A different socket cookie or restarted service invalidates ownership.
        for changed in ("sockets4", "service"):
            def unstable(name, count, value):
                if name == changed and count > 1: return ("ok", value[1].replace("sk:abcd", "sk:ffff").replace("MainPID=4321", "MainPID=9876"))
                return value
            data = fixture(mutate_read=unstable)
            self.assertFalse(data["studio"]["snapshot_stable"])
            self.assertFalse(data["studio"]["listener_owned"])
            self.assertEqual(runner.verdict(data, EXTERNAL), "STUDIO_PREFLIGHT_FAILED")

    def test_layered_firewall_sets_jumps_nat_and_legacy_are_never_bypassed(self):
        for name, raw in (("nft", json.dumps({"nftables": [{"rule": {"expr": [{"jump": {"target": CANARY}}]}}]})),
                          ("nft", json.dumps({"nftables": [{"chain": {"hook": "prerouting", "policy": "accept"}}]})),
                          ("legacy4", '*filter\n:INPUT DROP [0:0]\n-A INPUT -j ' + CANARY + '\nCOMMIT\n'),
                          ("iptables", '*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443\nCOMMIT\n'),
                          ("ufw", "Status: active\nDefault: deny (incoming)\n443/tcp ALLOW IN 198.51.100.77 # " + CANARY),
                          ("nft", '{"bad":"' + CANARY + '"}')):
            value = fixture({name: raw}); runner.validate(value)
            self.assertEqual(runner.verdict(value, EXTERNAL), "NETWORK_PATH_REVIEW_REQUIRED")
            self.assertNotIn(CANARY, json.dumps(value)); self.assertNotIn("198.51.100.77", json.dumps(value))
        value = fixture({"legacy6": ("missing", "")})
        self.assertEqual(runner.verdict(value, EXTERNAL), "NETWORK_PATH_REVIEW_REQUIRED")
        ext = {**EXTERNAL, "tcp443": "open"}
        self.assertEqual(runner.verdict(fixture(), ext), "NETWORK_PATH_REVIEW_REQUIRED")

    def test_literal_port_counts_are_not_authorization_and_comments_are_private(self):
        raw = '*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 443 -j ACCEPT\n-A INPUT -p tcp --dport 3000 -j DROP\nCOMMIT\n'
        value = probe.firewall_summary("iptables", "ok", raw)
        self.assertEqual(value["port_rules"]["443"]["accept"], 1)
        self.assertEqual(value["port_rules"]["3000"]["drop"], 1)
        value = probe.firewall_summary("ufw", "ok", 'Status: active\nDefault: deny (incoming)\n22/tcp ALLOW IN Anywhere # 443 ' + CANARY)
        self.assertEqual(value["port_rules"]["443"]["accept"], 0)

    def test_dns_acme_inventory_only_recognized_names_and_metadata_no_config_contents(self):
        value = fixture({"units": f'caddy.service loaded active running {CANARY}\ncertbot.timer loaded active waiting {CANARY}\n{CANARY}.timer loaded active waiting\n'})
        self.assertEqual(value["mechanisms"]["units"]["caddy.service"], "active")
        self.assertEqual(value["mechanisms"]["units"]["certbot.timer"], "active")
        self.assertNotIn(CANARY, json.dumps(value))
        for mode, expected in ((stat.S_IFLNK | 0o777, "symlink"), (stat.S_IFREG | 0o666, "unsafe"),
                               (stat.S_IFREG | 0o600, "private"), (stat.S_IFREG | 0o644, "root_owned")):
            self.assertEqual(probe.metadata("fixed", lambda _: SimpleNamespace(st_mode=mode, st_uid=0)), expected)
        with self.assertRaises(ValueError): probe.fixed_file("/etc/studio1925/server.env")

    def test_permissions_never_follow_symlinks_or_accept_root_alias_app_account(self):
        def inspect(path):
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_uid=0)
        self.assertFalse(probe.studio_permissions(inspect, lambda name: SimpleNamespace(pw_uid=1001, pw_gid=1001)))
        self.assertFalse(probe.studio_permissions(Mock(side_effect=AssertionError("no stat for root alias")), lambda name: SimpleNamespace(pw_uid=0, pw_gid=0)))
        data = fixture({"nft": '{"nftables":[{"chain":{"hook":"input","policy":"drop"}}]}'})
        self.assertEqual(runner.verdict(data, EXTERNAL), "NETWORK_PATH_REVIEW_REQUIRED")

    def test_strict_remote_schema_rejects_extra_nested_values_and_secret_errors(self):
        mutations = (lambda v: v.update(secret=CANARY), lambda v: v["studio"]["service"].update(ActiveState=CANARY),
                     lambda v: v["ports"]["4"].update(listeners=[{"raw": CANARY}]),
                     lambda v: v["mechanisms"]["tools"].update(token=CANARY), lambda v: v["firewall"]["ufw"].update(rules=-1))
        for mutate in mutations:
            value = fixture(); mutate(value)
            ssh = Mock(); ssh.execute.return_value = value; external = Mock()
            result = runner.diagnose(IP, CANARY, lambda *args: ssh, external)
            self.assertEqual(result["ssh"], "REMOTE_PROTOCOL_FAILED"); external.assert_not_called()
            with contextlib.redirect_stdout(io.StringIO()) as output: runner.emit(result)
            self.assertNotIn(CANARY, output.getvalue())

    def test_contradictory_remote_health_or_socket_proof_is_rejected(self):
        for mutate in (lambda v: v["studio"]["local_health"].update(http=503),
                       lambda v: v["studio"].update(snapshot_stable=False),
                       lambda v: v["studio"].update(listener_owned=False)):
            value = fixture(); mutate(value)
            ssh = SimpleNamespace(execute=lambda *a, **k: value); external = Mock()
            report = runner.diagnose(IP, CANARY, lambda *a: ssh, external)
            self.assertEqual(report["ssh"], "REMOTE_PROTOCOL_FAILED"); external.assert_not_called()

    def test_unknown_clock_drop_ins_and_erroring_inventory_remain_inconclusive(self):
        for change in (lambda v: v["host"].update(clock_sync="unknown"), lambda v: v["studio"].update(drop_ins=True),
                       lambda v: v["mechanisms"].update(read="timeout")):
            value = fixture(); change(value)
            self.assertEqual(runner.verdict(value, EXTERNAL), "INCONCLUSIVE")

    def test_private_file_stream_existing_ssh_policy_and_failed_auth_cleanup(self):
        streams = []
        def execute(command, source, **kwargs):
            self.assertEqual(command, "python3 -I -B -S -")
            self.assertEqual(os.fstat(source.fileno()).st_mode & 0o777, 0o600)
            self.assertEqual(source.read(), runner.payload()); streams.append(source)
            return fixture()
        ssh = Mock(); ssh.execute.side_effect = execute
        report = runner.diagnose(IP, CANARY, lambda *args: ssh, lambda *args: EXTERNAL)
        self.assertEqual(report["changes"], "none"); self.assertTrue(streams[0].closed)
        args = runner.SSH(IP, CANARY).arguments(runner.REMOTE_COMMAND)
        self.assertIn("StrictHostKeyChecking=no", args); self.assertIn("root@" + IP, args)
        self.assertNotIn(CANARY, ' '.join(args))
        ssh.execute.side_effect = runner.DeployError("SSH_AUTH_FAILED"); external = Mock()
        report = runner.diagnose(IP, CANARY, lambda *args: ssh, external)
        self.assertEqual(report["ssh"], "SSH_AUTH_FAILED"); external.assert_not_called()

    def test_input_and_missing_secret_fail_before_any_network_and_event_file_input(self):
        for address, password in (("$(danger)", CANARY), ("https://192.0.2.10", CANARY), ("127.0.0.1", CANARY), (IP, "")):
            with patch.dict(os.environ, {"STUDIO_SERVER_IP": address, "STUDIO_SSH_PASSWORD": password, "GITHUB_STEP_SUMMARY": ""}), patch.object(runner, "diagnose") as call, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 1); call.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"; event.write_text(json.dumps({"inputs": {"server_ip": "2001:db8::10"}}))
            env = {k: v for k, v in os.environ.items() if k != "STUDIO_SERVER_IP"}
            env.update(GITHUB_EVENT_PATH=str(event), STUDIO_SSH_PASSWORD=CANARY, GITHUB_STEP_SUMMARY="")
            with patch.dict(os.environ, env, clear=True), patch.object(runner, "diagnose", return_value={"status": "observed"}) as call, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 0); call.assert_called_once_with("2001:db8::10", CANARY)

    def test_sanitized_summary_no_target_or_sensitive_addresses(self):
        report = runner.diagnose(IP, CANARY, lambda *a: SimpleNamespace(execute=lambda *a, **k: fixture()), lambda *a: EXTERNAL)
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary"
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}), contextlib.redirect_stdout(io.StringIO()) as output:
                runner.emit(report)
            raw = output.getvalue() + summary.read_text()
            self.assertNotIn(IP, raw); self.assertNotIn(CANARY, raw); self.assertNotIn("/opt/", raw)

    def test_bounded_reader_only_fixed_read_commands_payload_has_no_remote_writes(self):
        self.assertEqual(probe.HTTPS_COMMANDS["nft"], ("nft", "-j", "list", "ruleset"))
        self.assertEqual(probe.HTTPS_COMMANDS["legacy4"], ("iptables-legacy-save",))
        self.assertNotIn("Environment", ' '.join(probe.HTTPS_COMMANDS["service"]))
        with self.assertRaises(KeyError): probe.read_https("install")
        source = runner.payload().decode(); ast.parse(source)
        for forbidden in ("journalctl", "timedatectl", "systemctl restart", "systemctl stop", "ufw allow", "nft add", "iptables -A", "os.system", "shell=True", "sqlite3", "write_text(", "write_bytes("):
            self.assertNotIn(forbidden, source)
        # The only text file reader accepts the public OS metadata path.
        self.assertEqual(probe.PATHS["studio_config"], "/etc/studio1925/server.env")
        self.assertNotIn("STUDIO_SSH_PASSWORD", source)
        self.assertEqual(set(probe.HTTPS_COMMANDS), {"service", "sockets4", "sockets6", "web4", "web6", "units", "clock", "ufw", "nft", "iptables", "ip6tables", "legacy4", "legacy6", "tls_dependencies", "tls_unit_paths"})
        for key in ("service", "units"):
            self.assertEqual(probe.HTTPS_COMMANDS[key][0], "systemctl")
            self.assertIn(probe.HTTPS_COMMANDS[key][1], ("show", "list-units"))

    def test_partial_tls_preparation_is_reported_by_metadata_without_reading_files(self):
        staged={'studio_tls_base','studio_tls_releases','studio_tls_config','studio_tls_data'}
        visited=[]
        def inspect(path):
            visited.append(path)
            if path not in {probe.PATHS[key] for key in staged}:raise FileNotFoundError()
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)
        value=probe.mechanisms('ok','',lambda name:False,inspect)
        for key in staged:self.assertEqual(value['paths'][key],'private')
        for key in ('studio_tls_owner','studio_tls_checkpoint','studio_tls_unit','studio_tls_recover_timer','studio_tls_monitor_timer'):
            self.assertEqual(value['paths'][key],'missing')
        self.assertEqual(value['units']['studio1925-tls.service'],'not_observed')
        self.assertEqual(value['custom_configuration'],'not_inspected')
        self.assertEqual(set(visited),set(probe.PATHS.values()))
        self.assertNotIn(CANARY,json.dumps(value))

    def test_new_command_reader_retains_output_limit_and_own_child_cleanup(self):
        base = probe.read_command.__globals__
        with patch.dict(probe.HTTPS_COMMANDS, {"fixture": (sys.executable, "-c", "print('x'*100)")}), \
                patch.dict(base, {"LIMIT": 32}), patch.object(probe.shutil, "which", return_value=sys.executable):
            self.assertEqual(probe.read_https("fixture"), ("output_limit", ""))

    def test_embedded_probe_uses_same_fixture_semantics_without_remote_imports_or_host_reads(self):
        # Execute definitions only; the appended real collect() call is removed.
        definitions = runner.payload().decode().rsplit('\ntry: print(json.dumps(collect()', 1)[0]
        namespace = {"__name__": "fixture_only"}
        exec(compile(definitions, "https-readiness-fixture", "exec"), namespace)
        actual = fixture(collector=namespace["collect"])
        self.assertEqual(actual, fixture()); runner.validate(actual)

    def test_workflow_is_main_manual_only_no_interpolated_input_commands_or_deploy(self):
        source = (ROOT / ".github/workflows/diagnose-studio-https-readiness.yml").read_text()
        self.assertIn("name: Diagnose Studio HTTPS readiness", source)
        self.assertIn("workflow_dispatch:", source); self.assertEqual(source.count("required: true"), 1)
        self.assertIn("github.ref == 'refs/heads/main'", source); self.assertIn("contents: read", source)
        self.assertIn("secrets.STUDIO_SSH_PASSWORD", source); self.assertIn("::add-mask::", source)
        self.assertNotIn("${{ inputs.server_ip }}", source)
        for forbidden in ("  push:", "  schedule:", "STUDIO_SSH_KNOWN_HOSTS", "ufw allow", "deploy.py", "manage.py", "certbot certonly"):
            self.assertNotIn(forbidden, source)

    def test_external_ipv6_probe_bounded_and_no_unverified_tls_or_http_request(self):
        connection = Mock(); connection.__enter__ = Mock(return_value=connection); connection.__exit__ = Mock(return_value=False)
        connection.connect.side_effect = ConnectionRefusedError(CANARY)
        with patch.object(runner.socket, "socket", return_value=connection) as factory:
            result = runner.external_checks("2001:db8::10")
        self.assertEqual(result, EXTERNAL)
        self.assertTrue(all(c.args[0] == socket.AF_INET6 for c in factory.call_args_list))
        self.assertEqual(connection.connect.call_args_list[0].args, (("2001:db8::10", 80),))
        self.assertNotIn(CANARY, json.dumps(result))

    @unittest.skipUnless(probe.shutil.which("openssl"), "openssl needed only for local TLS fixture")
    def test_real_local_tls_trust_ip_san_expiry_and_redaction(self):
        original_socket = socket.socket; original_context = ssl.create_default_context
        with tempfile.TemporaryDirectory(prefix="studio-https-test-") as tmp:
            cert = Path(tmp) / "certificate.pem"; key = Path(tmp) / "private-key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                "-days", "2", "-subj", "/CN=" + CANARY, "-addext", "subjectAltName=IP:" + IP],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
            class Handler(socketserver.BaseRequestHandler):
                def handle(self):
                    try:
                        self.request.settimeout(2)
                        with context.wrap_socket(self.request, server_side=True): pass
                    except (OSError, ssl.SSLError): pass
            class Server(socketserver.ThreadingTCPServer):
                daemon_threads = True
                def handle_error(self, *args): pass
            server = Server(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            parent = self
            class LocalOnlySocket(original_socket):
                def connect(self, target):
                    parent.assertEqual(target[0], IP); parent.assertIn(target[1], (80, 443))
                    return super().connect(("127.0.0.1", server.server_address[1]))
            try:
                with patch.object(runner.socket, "socket", LocalOnlySocket):
                    result = runner.external_checks(IP)
                    self.assertEqual(result["tcp443"], "open")
                    self.assertEqual(result["tls443_for_ip"], "not_verified_for_ip")
                    trusted = original_context(cafile=str(cert))
                    with patch.object(runner.ssl, "create_default_context", return_value=trusted):
                        result = runner.external_checks(IP)
                    self.assertEqual(result["tls443_for_ip"], "verified")
                    self.assertEqual(result["certificate_lifetime"], "under_48h")
                    self.assertNotIn(CANARY, json.dumps(result))
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == "__main__": unittest.main()
