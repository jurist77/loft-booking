"""Dual-stack regression fixtures. Never SSH or inspect/change a real VPS."""
import ast
import copy
import json
import unittest
from unittest.mock import Mock

from test_studio_http_access import FakeHost, fixture, ADDRESS, OK, TIMEOUT, CANARY
import bindings
import host
import rules
import studio_http_access as runner


def dual_fixture():
    data = fixture()
    data["sockets4"] = ""
    data["sockets6"] = data["sockets6"].replace("v6only:1", "v6only:0")
    data["listener_ownership"] = {"4321:5:1006": True}
    return data


def capture(data, on_health=None, readlink=None):
    def read(name): return "ok", data[name]
    def files(name):
        if name in data["protected"]: return bytes.fromhex(data["protected"][name])
        return data["user4" if name.endswith("user.rules") else "user6"].encode()
    def health(address):
        if on_health: on_health(address)
        return copy.deepcopy(OK)
    return host.snapshot(read=read, files=files, health=health, readlink=readlink or (lambda path: "socket:[1006]"))


class DualStackTests(unittest.TestCase):
    def test_embedded_ssh_payload_executes_same_bind_guard_without_host_modules(self):
        tree = ast.parse(runner.payload({"mode": "check", "confirmation": "", "family": 4}).decode())
        self.assertIsInstance(tree.body[-1], ast.Expr)
        self.assertEqual(tree.body[-1].value.func.id, "print")
        # Only load definitions/imports. Never execute the remote entrypoint.
        tree.body.pop(); namespace = {"__name__": "__main__"}
        exec(compile(tree, "<isolated-payload>", "exec"), namespace)
        self.assertEqual(namespace["studio_ok"](dual_fixture(), 4), "ipv4_dual_stack")
        self.assertEqual(namespace["HOST_COMMANDS"]["sockets6"], ("ss", "-H", "-O", "-6", "-lntpe", "sport", "=", ":3000"))

    def test_ipv6_wildcard_v6only_zero_and_both_healths_accept_ipv4(self):
        for address in ("[::]", "::", "*"):
            with self.subTest(address=address):
                data = dual_fixture(); data["sockets6"] = data["sockets6"].replace("[::]:3000", address + ":3000")
                server = FakeHost(data); report = server.check()
                self.assertEqual(report["status"], "READY_TO_APPLY", report)
                self.assertTrue(report["observations"]["public_bind"])
                self.assertTrue(report["observations"]["port_owned_by_studio"])
                self.assertEqual(report["observations"]["bind_proof"], "ipv4_dual_stack")
                self.assertTrue(report["observations"]["path_and_method_proven"])
                self.assertEqual(server.writes, 0)

    def test_bind_fix_continues_to_real_firewall_gates(self):
        for key, value, reason in (
            ("ufw", "Status: inactive", "UFW_NOT_ACTIVE"),
            ("ip4", dual_fixture()["ip4"].replace(":INPUT", ":foreign-vpn - [0:0]\n:INPUT"), "FOREIGN_CHAINS"),
            ("nft", '{"nftables":[{"table":{"family":"inet","name":"foreign"}}]}', "ADDITIONAL_NFT_FILTERING"),
            ("legacy4", "*filter\n:INPUT DROP [0:0]\nCOMMIT\n", "OTHER_FILTERING_BACKEND"),
        ):
            with self.subTest(reason=reason):
                server = FakeHost(dual_fixture()); server.data[key] = value
                report = server.check()
                self.assertEqual(report["reason"], reason)
                self.assertTrue(report["observations"]["public_bind"])
                self.assertFalse(report["observations"]["path_and_method_proven"])
                self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE")
                self.assertEqual(server.writes, 0)

    def test_v6only_one_or_missing_never_inferred_from_http_or_default(self):
        for option in ("v6only:1", ""):
            data = dual_fixture(); data["sockets6"] = data["sockets6"].replace("v6only:0", option)
            # A global default is deliberately irrelevant to this socket.
            data["net.ipv6.bindv6only"] = 0
            server = FakeHost(data)
            self.assertEqual(server.check()["reason"], "PUBLIC_BIND_NOT_CONFIRMED")
            self.assertEqual(server.apply()["status"], "FAILED_NO_CHANGE")
            self.assertEqual(server.writes, 0)

    def test_quoted_process_name_cannot_supply_kernel_option_or_ownership(self):
        data = dual_fixture()
        data["sockets6"] = data["sockets6"].replace(" v6only:0", "").replace('"node"', '"node v6only:0 ino:1006 sk:a006 pid=4321,fd=5 "')
        self.assertEqual(FakeHost(data).check()["reason"], "PUBLIC_BIND_NOT_CONFIRMED")
        data = dual_fixture()
        data["sockets6"] = data["sockets6"].replace('"node"', '"node pid=9999,fd=8 v6only:1 "')
        self.assertEqual(FakeHost(data).check()["status"], "READY_TO_APPLY")

    def test_both_healths_required_for_dual_stack(self):
        for name in ("local4", "local6"):
            server = FakeHost(dual_fixture()); server.data[name] = False
            self.assertEqual(server.check()["reason"], "LOCAL_HEALTH_FAILED")
            self.assertEqual(server.writes, 0)

    def test_separate_ipv4_loopback_socket_does_not_prove_dual_stack(self):
        for option in ("0", "1"):
            data = dual_fixture()
            data["sockets6"] = data["sockets6"].replace("v6only:0", "v6only:" + option)
            data["sockets4"] = fixture()["sockets4"].replace("0.0.0.0:3000", "127.0.0.1:3000")
            data["listener_ownership"]["4321:4:1004"] = True
            server = FakeHost(data)
            self.assertEqual(server.check()["reason"], "PUBLIC_BIND_NOT_CONFIRMED")
            self.assertEqual(server.writes, 0)

    def test_other_process_shared_owner_or_unknown_fd_blocks(self):
        variants = [dual_fixture() for _ in range(4)]
        variants[0]["sockets6"] = variants[0]["sockets6"].replace("pid=4321", "pid=9999")
        variants[1]["sockets6"] = variants[1]["sockets6"].replace('pid=4321,fd=5', 'pid=4321,fd=5),("other",pid=9999,fd=8')
        variants[2]["listener_ownership"]["4321:5:1006"] = False
        variants[3]["sockets4"] = fixture()["sockets4"].replace("0.0.0.0:3000", "127.0.0.1:3000").replace("pid=4321", "pid=9999")
        for data in variants:
            server = FakeHost(data)
            self.assertEqual(server.check()["reason"], "PORT_NOT_EXCLUSIVELY_STUDIO")
            self.assertEqual(server.writes, 0)

    def test_multiple_ipv6_sockets_and_specific_bind_are_ambiguous_for_ipv4(self):
        for option in ("0", "1"):
            data = dual_fixture()
            extra = data["sockets6"].replace("ino:1006", "ino:1007").replace("sk:a006", "sk:a007").replace("fd=5", "fd=6").replace("v6only:0", "v6only:" + option)
            data["sockets6"] += "\n" + extra
            data["listener_ownership"]["4321:6:1007"] = True
            self.assertEqual(FakeHost(data).check()["reason"], "PUBLIC_BIND_NOT_CONFIRMED")
        data = dual_fixture(); data["sockets6"] = data["sockets6"].replace("[::]:3000", "[::1]:3000")
        self.assertEqual(FakeHost(data).check()["reason"], "PUBLIC_BIND_NOT_CONFIRMED")

    def test_native_ipv4_and_ipv6_keep_their_behavior(self):
        self.assertEqual(FakeHost().check()["observations"]["bind_proof"], "native_ipv4")
        data = dual_fixture(); data["sockets6"] = data["sockets6"].replace("v6only:0", "v6only:1")
        report = FakeHost(data).operate(mode="check", confirmation="", family=6)
        self.assertEqual(report["status"], "READY_TO_APPLY")
        self.assertEqual(report["observations"]["bind_proof"], "native_ipv6")

    def test_replaced_socket_same_pid_is_detected_before_apply(self):
        server = FakeHost(dual_fixture()); old = server.check()["fingerprint"]
        server.data["sockets6"] = server.data["sockets6"].replace("ino:1006", "ino:2006").replace("sk:a006", "sk:b006")
        server.data["listener_ownership"] = {"4321:5:2006": True}
        self.assertNotEqual(old, server.check()["fingerprint"])
        self.assertEqual(server.apply(expected=old)["reason"], "STATE_CHANGED_SINCE_CHECK")
        self.assertEqual(server.writes, 0)

    def test_valid_dual_stack_can_apply_in_fixture_and_postflight_rechecks(self):
        server = FakeHost(dual_fixture())
        report = runner.run(ADDRESS, CANARY, "apply", host.CONFIRMATION, ssh_factory=Mock(), health=Mock(side_effect=[TIMEOUT, OK]), remote_call=server.call)
        self.assertEqual(report["status"], "SUCCESS", report)
        self.assertEqual(server.writes, 1)
        server = FakeHost(dual_fixture())
        server.after = lambda d: d.update(sockets6=d["sockets6"].replace("v6only:0", "v6only:1"))
        self.assertEqual(server.apply()["status"], "MANUAL_REVIEW_REQUIRED")
        self.assertEqual(server.writes, 1)

    def test_readlink_checks_only_studio_fds_and_requires_matching_inode(self):
        data = dual_fixture(); readlink = Mock(return_value="socket:[1006]")
        self.assertEqual(bindings.listener_ownership(data, 4321, readlink), {"4321:5:1006": True})
        readlink.assert_called_once_with("/proc/4321/fd/5")
        for read in (Mock(return_value="socket:[9999]"), Mock(return_value="/sensitive/" + CANARY), Mock(side_effect=PermissionError(CANARY))):
            self.assertEqual(bindings.listener_ownership(data, 4321, read), {"4321:5:1006": False})
        data["sockets6"] = data["sockets6"].replace("pid=4321", "pid=9999")
        readlink.reset_mock()
        self.assertEqual(bindings.listener_ownership(data, 4321, readlink), {})
        readlink.assert_not_called()

    def test_missing_or_malformed_extended_metadata_fails_closed(self):
        for old, new in ((" ino:1006", ""), (" sk:a006", ""), ("v6only:0", "v6only:2"), ("v6only:0", "v6only:0 v6only:1"), (" sk:a006", " sk:a006 sk:a007")):
            data = dual_fixture(); data["sockets6"] = data["sockets6"].replace(old, new)
            report = FakeHost(data).check()
            self.assertEqual(report["status"], "INCONCLUSIVE")
            self.assertEqual(report["reason"], "READS_INCOMPLETE")

    def test_identity_is_private_and_bind_proof_protocol_is_strict(self):
        report = FakeHost(dual_fixture()).check(); runner.validate(report)
        serialized = json.dumps(report)
        for private in ("a006", "inode", "cookie", "/proc/", "4321:5", CANARY): self.assertNotIn(private, serialized)
        for value in (CANARY, "ipv4_default_is_zero"):
            bad = copy.deepcopy(report); bad["observations"]["bind_proof"] = value
            with self.assertRaises(runner.ProtocolError): runner.validate(bad)
        bad = copy.deepcopy(report); bad["observations"]["public_bind"] = False
        with self.assertRaises(runner.ProtocolError): runner.validate(bad)
        bad = copy.deepcopy(report); bad["observations"]["port_owned_by_studio"] = False
        with self.assertRaises(runner.ProtocolError): runner.validate(bad)


class SnapshotStabilityTests(unittest.TestCase):
    def test_stable_snapshot_verifies_fd_links_without_logging_paths(self):
        value = capture(dual_fixture())
        self.assertEqual(value["listener_ownership"], {"4321:5:1006": True})
        self.assertEqual(host.studio_ok(value, 4), "ipv4_dual_stack")

    def test_socket_pid_option_and_fd_change_during_health_are_rejected(self):
        for change in (
            lambda d: d.update(sockets6=d["sockets6"].replace("ino:1006", "ino:2006")),
            lambda d: d.update(sockets6=d["sockets6"].replace("sk:a006", "sk:b006")),
            lambda d: d.update(sockets6=d["sockets6"].replace("v6only:0", "v6only:1")),
            lambda d: d.update(service=d["service"].replace("4321", "4322")),
            lambda d: d.update(sockets6=d["sockets6"].replace("fd=5", "fd=6")),
        ):
            data = dual_fixture()
            with self.assertRaises(rules.Unsafe) as error:
                capture(data, on_health=lambda address: change(data) if address == "127.0.0.1" else None)
            self.assertEqual(error.exception.code, "LISTENER_STATE_CHANGED")

    def test_queue_sizes_may_change_without_rejecting_same_socket(self):
        data = dual_fixture()
        captured = capture(data, on_health=lambda address: data.update(sockets6=data["sockets6"].replace("0 511", "2 512")))
        self.assertEqual(host.studio_ok(captured, 4), "ipv4_dual_stack")

    def test_fd_loss_between_healths_is_detected(self):
        readlink = Mock(side_effect=["socket:[1006]", "socket:[2006]"])
        with self.assertRaises(rules.Unsafe) as error: capture(dual_fixture(), readlink=readlink)
        self.assertEqual(error.exception.code, "LISTENER_STATE_CHANGED")


if __name__ == "__main__": unittest.main()
