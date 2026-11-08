"""Isolated stateful fixtures; no real SSH, UFW, nftables or VPS operations."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/firewall"))
import host
import rules
import studio_http_access as runner

ADDRESS = "192.0.2.10"  # RFC 5737; never contacted.
CANARY = "SYNTHETIC_SECRET_MUST_NOT_APPEAR"
OK = {"http": 200, "ok": True, "error": "none"}
TIMEOUT = {"http": None, "ok": False, "error": "timeout"}


def fixture():
    data = {"service": "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4321\n",
            "sockets4": 'LISTEN 0 511 0.0.0.0:3000 0.0.0.0:* users:(("node",pid=4321,fd=4))',
            "sockets6": 'LISTEN 0 511 [::]:3000 [::]:* users:(("node",pid=4321,fd=4))',
            "ufw": "Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n22/tcp ALLOW IN Anywhere\n",
            "protected": {name: b"fixture-only".hex() for name in host.PROTECTED},
            "local4": True, "local6": True, "version4": "iptables v1.8.10 (nf_tables)", "version6": "ip6tables v1.8.10 (nf_tables)",
            "legacy4": "", "legacy6": ""}
    data["protected"]["/etc/default/ufw"] = b'IPV6=yes\nMANAGE_BUILTINS=no\n'.hex()
    data["protected"]["/etc/ufw/ufw.conf"] = b'ENABLED=yes\nLOGLEVEL=low\n'.hex()
    nft = []
    for family, nf in ((4, "ip"), (6, "ip6")):
        prefix = "ufw" if family == 4 else "ufw6"
        user = prefix + "-user-input"
        user_chains = [prefix + "-user-" + s for s in ("input", "output", "forward", "limit", "limit-accept")]
        headers = "".join(f":{chain} - [0:0]\n" for chain in user_chains)
        zero = "0.0.0.0/0" if family == 4 else "::/0"
        stored = f"### tuple ### allow tcp 22 {zero} any {zero} in\n-A {user} -p tcp --dport 22 -j ACCEPT\n"
        data["user" + str(family)] = "*filter\n" + headers + stored + "COMMIT\n"
        data["ip" + str(family)] = "*filter\n:INPUT DROP [4:5]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [2:3]\n" + headers + f"-A INPUT -j {user}\n-A {user} -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"
        nft.append({"table": {"family": nf, "name": "filter", "handle": family}})
        for chain, policy in (("INPUT", "drop"), ("FORWARD", "drop"), ("OUTPUT", "accept")):
            nft.append({"chain": {"family": nf, "table": "filter", "name": chain, "type": "filter", "hook": chain.lower(), "prio": 0, "policy": policy}})
        nft.extend({"chain": {"family": nf, "table": "filter", "name": chain}} for chain in user_chains)
        nft.append({"rule": {"family": nf, "table": "filter", "chain": "INPUT", "expr": [{"jump": {"target": user}}]}})
        nft.append(nft_allow(nf, user, 22))
    data["nft"] = json.dumps({"nftables": nft})
    return data


def nft_allow(family, chain, port):
    return {"rule": {"family": family, "table": "filter", "chain": chain,
                     "expr": [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                              {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]}}


def add_rule(data):
    nft = json.loads(data["nft"])
    for family, nf in ((4, "ip"), (6, "ip6")):
        user = ("ufw" if family == 4 else "ufw6") + "-user-input"
        data["ip" + str(family)] = data["ip" + str(family)].replace("COMMIT", f"-A {user} -p tcp -m tcp --dport 3000 -j ACCEPT\nCOMMIT")
        zero = "0.0.0.0/0" if family == 4 else "::/0"
        data["user" + str(family)] = data["user" + str(family)].replace("COMMIT", f"### tuple ### allow tcp 3000 {zero} any {zero} in\n-A {user} -p tcp --dport 3000 -j ACCEPT\nCOMMIT")
        nft["nftables"].append(nft_allow(nf, user, 3000))
    data["nft"] = json.dumps(nft)
    data["ufw"] += "3000/tcp ALLOW IN Anywhere\n3000/tcp (v6) ALLOW IN Anywhere (v6)\n"


class FakeHost:
    def __init__(self, data=None): self.data = data or fixture(); self.writes = 0; self.failure = None; self.after = None
    def take(self): return copy.deepcopy(self.data)
    def write(self):
        self.writes += 1
        if self.failure: raise self.failure
        add_rule(self.data)
        if self.after: self.after(self.data)
    def operate(self, **options):
        return host.operate(take=self.take, write=self.write, implementation=lambda: None, **options)
    def check(self, **kw): return self.operate(mode="check", confirmation="", family=4, **kw)
    def apply(self, **kw):
        defaults = {"mode": "apply", "confirmation": host.CONFIRMATION, "family": 4, "expected": self.check().get("fingerprint")}
        return self.operate(**{**defaults, **kw})
    def call(self, ssh, options): return runner.validate(self.operate(**options))


class SafetyTests(unittest.TestCase):
    def test_check_is_read_only_and_proves_both_views(self):
        server = FakeHost(); before = server.take()
        report = server.check()
        self.assertEqual(report["status"], "READY_TO_APPLY", report)
        self.assertTrue(report["observations"]["path_and_method_proven"])
        self.assertEqual(server.writes, 0); self.assertEqual(before, server.data)

    def test_apply_exact_delta_and_external_success(self):
        server = FakeHost(); old = server.take()
        report = runner.run(ADDRESS, CANARY, "apply", host.CONFIRMATION, ssh_factory=Mock(), remote_call=server.call, health=Mock(side_effect=[TIMEOUT, OK]))
        self.assertEqual(report["status"], "SUCCESS", report); self.assertEqual(server.writes, 1)
        self.assertTrue(rules.expected_delta(old, server.data, "nft"))
        for v in (4, 6): self.assertTrue(host.persistent_delta(old["user" + str(v)], server.data["user" + str(v)], v))

    def test_missing_wrong_and_whitespace_confirmation_never_connect(self):
        for confirmation in ("", "ENABLE STUDIO TCP 22", "ENABLE STUDIO TCP 3000 "):
            connect = Mock(); server = FakeHost()
            report = runner.run(ADDRESS, CANARY, "apply", confirmation, ssh_factory=connect, remote_call=server.call)
            self.assertEqual(report["status"], "FAILED_NO_CHANGE"); connect.assert_not_called()
            self.assertEqual(server.apply(confirmation=confirmation)["status"], "FAILED_NO_CHANGE")
            self.assertEqual(server.writes, 0)

    def test_inactive_service_wrong_owner_bind_and_health_never_write(self):
        cases = {"service": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n", "sockets4": fixture()["sockets4"].replace("pid=4321", "pid=9999"), "local4": False}
        for key, value in cases.items():
            server = FakeHost(); server.data[key] = value
            self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE"); self.assertEqual(server.writes, 0)
        server = FakeHost(); server.data["sockets4"] = server.data["sockets4"].replace("0.0.0.0:3000", "127.0.0.1:3000")
        self.assertEqual(server.check()["reason"], "PUBLIC_BIND_NOT_CONFIRMED")

    def test_inactive_ufw_or_non_deny_policy(self):
        for text in ("Status: inactive", "Status: active\nDefault: allow (incoming)"):
            server = FakeHost(); server.data["ufw"] = text
            self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE"); self.assertEqual(server.writes, 0)

    def test_existing_allow_and_repeat_do_not_duplicate(self):
        server = FakeHost(); self.assertEqual(server.apply()["status"], "APPLIED_PENDING_EXTERNAL")
        self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE"); self.assertEqual(server.writes, 1)
        self.assertEqual(server.check(accessible=True)["status"], "ALREADY_ACCESSIBLE")
        report = runner.run(ADDRESS, CANARY, "apply", host.CONFIRMATION, ssh_factory=Mock(), remote_call=server.call, health=lambda _: OK)
        self.assertEqual(report["status"], "NO_CHANGE_REQUIRED"); self.assertEqual(server.writes, 1)

    def test_conflicting_scoped_deny_and_multiport_rules_refused(self):
        for rule in ("-p tcp --dport 3000 -j DROP", "-p tcp --dport 3000 -s 198.51.100.0/24 -j ACCEPT", "-p tcp -m multiport --dports 22,3000 -j REJECT"):
            server = FakeHost(); server.data["ip4"] = server.data["ip4"].replace("COMMIT", "-A ufw-user-input " + rule + "\nCOMMIT")
            self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE"); self.assertEqual(server.writes, 0)

    def test_foreign_chains_nat_legacy_and_unknown_nft_hooks_refused(self):
        for key, raw in (("ip4", fixture()["ip4"].replace(":INPUT", ":OTHER_APPLICATION - [0:0]\n:INPUT")),
                         ("ip4", fixture()["ip4"] + "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 3000 -j DROP\nCOMMIT\n"),
                         ("legacy4", "*filter\n:INPUT DROP [0:0]\nCOMMIT\n")):
            server = FakeHost(); server.data[key] = raw
            self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE"); self.assertEqual(server.writes, 0)
        for entry in ({"table": {"family": "inet", "name": "other"}}, {"chain": {"family": "ip", "table": "filter", "name": "ufw-extra", "hook": "prerouting", "prio": -100, "type": "filter"}}, {"set": {"family": "ip", "table": "filter", "name": CANARY}}):
            server = FakeHost(); nf = json.loads(server.data["nft"]); nf["nftables"].append(entry); server.data["nft"] = json.dumps(nf)
            self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE"); self.assertEqual(server.writes, 0)

    def test_unknown_condition_never_guessed_safe(self):
        chains = {"INPUT": [(None, "DROP"), (True, "ufw-user-input")], "ufw-user-input": []}
        with self.assertRaises(rules.Unsafe): rules.prove(chains, "ufw-user-input")
        chains = {"INPUT": [(True, "ufw-user-input")], "ufw-user-input": [(None, "ACCEPT")]}
        with self.assertRaises(rules.Unsafe): rules.prove(chains, "ufw-user-input")
        self.assertEqual(rules.ip_rule(["-A", "INPUT", "-p", "udp", "--dport", "3000", "-j", "DROP"])[0], False)

    def test_native_nft_unknown_values_and_unknown_extensions_stay_unknown(self):
        for right in ("3000", [3000, 3001], {"range": [2000, 4000]}):
            expr = [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": right}}, {"drop": None}]
            self.assertIsNone(rules.nft_rule(expr)[0])
        with self.assertRaises(rules.Unsafe): rules.nft_rule([{"match": {"op": "==", "left": {}, "right": 3000, "flags": ["invert"]}}])
        with self.assertRaises(rules.Unsafe): rules.nft_rule([{"accept": None}, {"drop": None}])
        with self.assertRaises(rules.Unsafe): rules.nft_rule([{"jump": {"target": "ufw-user-input"}}, {"counter": None}])
        server = FakeHost(); server.data["sockets4"] = server.data["sockets4"].replace('pid=4321,fd=4', 'pid=4321,fd=4),("other",pid=999,fd=5')
        self.assertEqual(server.check()["reason"], "PORT_NOT_EXCLUSIVELY_STUDIO")

    def test_missing_reads_and_ssh_failure_are_not_permission_to_apply(self):
        with self.assertRaises(rules.Unsafe): host.snapshot(read=lambda name: ("missing", ""))
        connect = Mock(side_effect=runner.DeployError("SSH_AUTH_FAILED")); writer = Mock()
        report = runner.run(ADDRESS, CANARY, "apply", host.CONFIRMATION, ssh_factory=connect, remote_call=writer, health=lambda _: TIMEOUT)
        self.assertEqual(report["status"], "FAILED_NO_CHANGE"); self.assertEqual(report["reason"], "SSH_AUTH_FAILED"); writer.assert_not_called()

    def test_ufw_caps_chains_and_persisted_rules_must_match(self):
        server = FakeHost(); server.data["ip4"] = server.data["ip4"].replace(":ufw-user-limit - [0:0]\n", "")
        self.assertEqual(server.check()["reason"], "UFW_RELOAD_WOULD_BE_REQUIRED")
        server = FakeHost(); server.data["user4"] = server.data["user4"].replace("--dport 22", "--dport 443")
        self.assertEqual(server.check()["reason"], "PERSISTED_RULES_DIFFER")
        self.assertEqual(server.writes, 0)

    def test_changes_between_check_and_apply_refused_counters_ignored(self):
        server = FakeHost(); expected = server.check()["fingerprint"]
        server.data["ip4"] = server.data["ip4"].replace("[4:5]", "[100:9999]")
        self.assertEqual(expected, server.check()["fingerprint"])
        server.data["protected"]["/etc/ufw/after.rules"] = b"changed".hex()
        self.assertEqual(server.apply(expected=expected)["reason"], "STATE_CHANGED_SINCE_CHECK"); self.assertEqual(server.writes, 0)

    def test_write_error_is_uncertain_and_never_rolls_back(self):
        server = FakeHost(); server.failure = RuntimeError(CANARY)
        report = server.apply()
        self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED"); self.assertNotIn(CANARY, json.dumps(report)); self.assertEqual(server.writes, 1)

    def test_external_failure_after_add_is_not_success(self):
        server = FakeHost()
        report = runner.run(ADDRESS, CANARY, "apply", host.CONFIRMATION, ssh_factory=Mock(), remote_call=server.call, health=lambda _: TIMEOUT)
        self.assertEqual(report["status"], "APPLIED_BUT_UNREACHABLE"); self.assertEqual(server.writes, 1)

    def test_unexpected_policy_other_port_nft_or_file_change_is_manual_review(self):
        for mutate in (lambda d: d.update(ip4=d["ip4"].replace(":FORWARD DROP", ":FORWARD ACCEPT")),
                       lambda d: d.update(ip6=d["ip6"].replace("--dport 22", "--dport 443")),
                       lambda d: d["protected"].update({"/etc/default/ufw": b"changed".hex()}),
                       lambda d: d.update(version4="iptables v1.8.10 (legacy)"),
                       lambda d: d.update(nft=d["nft"].replace('"prio": 0', '"prio": -10')),
                       lambda d: d.update(local4=False)):
            server = FakeHost(); server.after = mutate
            self.assertEqual(server.apply()["status"], "MANUAL_REVIEW_REQUIRED"); self.assertEqual(server.writes, 1)

    def test_lost_ssh_reply_after_apply_is_manual_review(self):
        server = FakeHost(); count = [0]
        def call(ssh, options):
            count[0] += 1
            answer = server.call(ssh, options)
            if count[0] == 2: raise runner.DeployError(CANARY)
            return answer
        report = runner.run(ADDRESS, CANARY, "apply", host.CONFIRMATION, ssh_factory=Mock(), remote_call=call, health=lambda _: TIMEOUT)
        self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED"); self.assertEqual(server.writes, 1)
        self.assertNotIn(CANARY, json.dumps(report))

    def test_ipv6_and_legacy_supported_without_other_backend(self):
        server = FakeHost(); self.assertEqual(server.operate(mode="check", confirmation="", family=6)["status"], "READY_TO_APPLY")
        server = FakeHost(); server.data.update(version4="iptables (legacy)", version6="ip6tables (legacy)", nft='{"nftables":[]}')
        for v in (4, 6): server.data["legacy" + str(v)] = server.data["ip" + str(v)]
        server.after = lambda data: data.update(legacy4=data["ip4"], legacy6=data["ip6"], nft='{"nftables":[]}')
        self.assertEqual(server.apply()["status"], "APPLIED_PENDING_EXTERNAL")

    def test_malformed_missing_and_unverified_source_are_inconclusive(self):
        for bad in ("{}", "not-json"):
            server = FakeHost(); server.data["nft"] = bad
            self.assertEqual(server.check()["status"], "INCONCLUSIVE"); self.assertEqual(server.writes, 0)
        report = host.operate("check", "", 4, take=fixture, implementation=Mock(side_effect=rules.Unsafe("UNSUPPORTED_UFW_IMPLEMENTATION")))
        self.assertEqual(report["status"], "INCONCLUSIVE")


class BoundaryTests(unittest.TestCase):
    def test_ufw_io_rejects_unapproved_commands_before_subprocess(self):
        for args in (["/sbin/iptables", "-F"], ["/sbin/iptables", "-A", "ufw-user-input", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], ["sysctl", "-w", "net.ipv4.ip_forward=0"], ["systemctl", "restart", "studio1925.service"]):
            with patch("subprocess.Popen") as process, self.assertRaises(rules.Unsafe): host.ufw_io(args, allow_append=True)
            process.assert_not_called()

    def test_lock_failure_and_remote_confirmation_fail_before_operation(self):
        for mode in ("check", "apply"):
            with patch.object(host.os, "geteuid", return_value=0), patch.object(host.os, "open", side_effect=OSError()), patch.object(host, "operate") as operation:
                report = host.remote_main({"mode": mode, "confirmation": host.CONFIRMATION, "family": 4})
            self.assertEqual(report["status"], "INCONCLUSIVE" if mode == "check" else "FAILED_NO_CHANGE"); operation.assert_not_called()
        with patch.object(host.os, "geteuid", return_value=0), patch.object(host.os, "open") as opened:
            self.assertEqual(host.remote_main({"mode": "apply", "confirmation": "wrong", "family": 4})["status"], "FAILED_NO_CHANGE")
        opened.assert_not_called()

    def test_remote_protocol_does_not_echo_secrets_or_extra_keys(self):
        valid = FakeHost().check(); runner.validate(valid)
        for mutate in (lambda r: r.update(secret=CANARY), lambda r: r.update(reason=CANARY), lambda r: r["observations"].update(raw=CANARY)):
            value = copy.deepcopy(valid); mutate(value)
            with self.assertRaises(runner.ProtocolError): runner.validate(value)

    def test_ssh_stdin_has_fileno_and_payload_is_valid_python(self):
        class SSH:
            def execute(self, command, stream, timeout):
                self_fd = stream.fileno(); self_payload = stream.read()
                if self_fd < 0 or command != "python3 -I -B -S -": raise AssertionError()
                compile(self_payload, "<remote>", "exec")
                if CANARY.encode() in self_payload: raise AssertionError()
                return FakeHost().check()
        runner.call(SSH(), {"mode": "check", "confirmation": "", "family": 4})

    def test_main_rejects_wrong_branch_and_input_before_any_network(self):
        env = {"GITHUB_REF": "refs/heads/feature", "STUDIO_SERVER_IP": ADDRESS, "STUDIO_SSH_PASSWORD": CANARY}
        with patch.dict(os.environ, env, clear=True), patch.object(runner, "run") as network, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 1); network.assert_not_called()
        self.assertNotIn(CANARY, output.getvalue())

    def test_bounded_read_only_command_table_and_sole_ufw_write(self):
        self.assertEqual(host.ALLOW, ["/usr/sbin/ufw", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "3000"])
        for argv in host.HOST_COMMANDS.values():
            for bad in ("restart", "reload", "enable", "disable", "delete", "insert", "-A", "-F", "-X", "-P", "-I", "-D"): self.assertNotIn(bad, argv)
        source = (ROOT / "scripts/firewall/host.py").read_text()
        for bad in ("shell=True", "os.system", "ufw-init", "systemctl restart", "nft add", "iptables-restore", "write_text", "write_bytes", "vpn_automatic", "xray", "3x-ui"): self.assertNotIn(bad, source.lower())

    def test_workflow_manual_main_only_no_new_secret_or_injection(self):
        text = (ROOT / ".github/workflows/enable-studio-http-access.yml").read_text()
        for expected in ("name: Enable Studio HTTP access", "workflow_dispatch:", "default: check", "github.ref == 'refs/heads/main'", "permissions:\n  contents: read", "persist-credentials: false"):
            self.assertIn(expected, text)
        for forbidden in ("\n  push:", "\n  schedule:", "workflow_run:", "secrets.STUDIO_SSH_KNOWN_HOSTS", "StrictHostKeyChecking", "ufw allow", "${{ inputs.server_ip }}:"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(set(__import__('re').findall(r'secrets\.([A-Z_]+)', text)), {"STUDIO_SSH_PASSWORD"})


if __name__ == "__main__": unittest.main()
