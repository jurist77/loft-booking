#!/usr/bin/env python3
"""Main-only manual runner. Bidirectional SSH with bounded PIPE I/O, not BytesIO."""
import argparse
import ast
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "installer"))
from deploy import SSH, DeployError, SAFE_CODES
from configuration import inputs
from checks import HttpsError, require, dns_records, https_health, closed, port_challenge, dns_report
from artifacts import RELEASE, download

SAFE_REMOTE_CODES = SAFE_CODES | {node.value for name in ("host", "inventory", "checks", "configuration")
    for node in ast.walk(ast.parse((HERE / (name + ".py")).read_text()))
    if isinstance(node, ast.Constant) and type(node.value) is str and re.fullmatch(r"[A-Z0-9_]{1,100}", node.value)}

BOOTSTRAP = r'''
import json,sys
def exact(n):
    data=sys.stdin.buffer.read(n)
    if len(data)!=n: raise ValueError()
    return data
try:
    import signal
    signal.alarm(120)
    header=json.loads(sys.stdin.buffer.readline(8193))
    c,a=header['code_size'],header['archive_size']
    if type(c) is not int or type(a) is not int or not 0<c<500000 or not 0<=a<64*1024**2: raise ValueError()
    code=exact(c);archive=exact(a)
    signal.alarm(0)
    scope={'__name__':'__main__','_STUDIO_OPTIONS':header['options'],'_STUDIO_ARCHIVE':archive,'_STUDIO_SOURCE':code.decode()}
    exec(compile(code,'studio-https-control','exec'),scope)
    status=scope.get('_exit',1)
except BaseException:
    print('{"event":"result","status":"FAILED","code":"HTTPS_BOOTSTRAP_FAILED"}',flush=True)
    status=1
sys.exit(status)
'''


def source():
    paths = {name: HERE.parent / "installer" / (filename + ".py") for name, filename in
             (("transport_settings", "transport_settings"), ("backup", "backup"), ("maintenance", "maintenance"), ("studio_installer", "remote"))}
    paths.update({"probe_studio_network": HERE.parent / "diagnostics/probe_studio_network.py",
                  "rules": HERE.parent / "firewall/rules.py", "bindings": HERE.parent / "firewall/bindings.py"})
    paths.update({name: HERE / (name + ".py") for name in ("configuration", "checks", "inventory", "host")})
    modules = {name: path.read_text() for name, path in paths.items()}
    prefix = "import sys,types\nfor _name,_code in " + repr(modules) + ".items():\n _module=types.ModuleType(_name);_module.__file__='/opt/studio1925-https/'+_name+'.py';sys.modules[_name]=_module;exec(compile(_code,_name,'exec'),_module.__dict__)\n"
    prefix += "sys.modules['host'].RELEASE=" + repr(RELEASE) + "\n"
    prefix += "from host import entry\nif '_STUDIO_OPTIONS' in globals():\n _exit=entry(_STUDIO_OPTIONS,_STUDIO_ARCHIVE,_STUDIO_SOURCE)\nelse:\n sys.exit(entry())\n"
    # Don't raise SystemExit inside the framing bootstrap's broad catch.
    return prefix.encode()


class Session:
    def __init__(self, ssh, limit=1000): self.ssh, self.limit, self.child, self.buffer = ssh, limit, None, b""

    def write(self, data, timeout=120):
        end = time.monotonic() + timeout; view = memoryview(data)
        while view:
            require(time.monotonic() < end, "SSH_INPUT_TIMEOUT")
            if select.select([], [self.child.stdin], [], min(1, max(0, end-time.monotonic())))[1]:
                try: view = view[os.write(self.child.stdin.fileno(), view[:65536]):]
                except BlockingIOError: continue
                except BrokenPipeError: raise HttpsError("SSH_CLOSED_OUTCOME_UNKNOWN") from None

    def record(self, timeout=360):
        end = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            require(time.monotonic() < end, "SSH_EVENT_TIMEOUT_OUTCOME_UNKNOWN")
            if select.select([self.child.stdout], [], [], min(1, max(0, end-time.monotonic())))[0]:
                data = os.read(self.child.stdout.fileno(), 8193)
                if not data:
                    try: code = self.child.wait(timeout=1)
                    except subprocess.TimeoutExpired: code = None
                    raise HttpsError("SSH_AUTH_FAILED" if code == 5 else "SSH_CONNECTION_FAILED" if code == 255 else "SSH_CLOSED_OUTCOME_UNKNOWN")
                require(len(self.buffer) + len(data) <= 8192, "INVALID_REMOTE_PROTOCOL")
                self.buffer += data
        line, self.buffer = self.buffer.split(b"\n", 1)
        try: value = json.loads(line)
        except ValueError: raise HttpsError("INVALID_REMOTE_PROTOCOL") from None
        require(isinstance(value, dict), "INVALID_REMOTE_PROTOCOL")
        return value

    def run(self, options, archive=b"", verify=None):
        require(options.get("mode") in ("check", "apply"), "INVALID_REMOTE_PROTOCOL")
        history = []
        cutover = ["ports-probe", "certificate-ready", "cutover-ready"]
        code = source(); packet = json.dumps({"code_size": len(code), "archive_size": len(archive), "options": options}).encode()+b"\n"+code+archive
        try:
            self.child = subprocess.Popen(self.ssh.arguments("python3 -I -B -S -c " + shlex.quote(BOOTSTRAP)),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "SSHPASS": self.ssh.password})
            os.set_blocking(self.child.stdin.fileno(), False)
            self.write(packet)
            end = time.monotonic() + self.limit
            while True:
                require(time.monotonic() < end, "SSH_OPERATION_TIMEOUT_OUTCOME_UNKNOWN")
                event = self.record(min(360, end-time.monotonic()))
                phase = event.get("event")
                require(phase in ("result", "ports-probe", "certificate-ready", "cutover-ready", "verify-existing"), "INVALID_REMOTE_PROTOCOL")
                if phase == "result":
                    require(set(event) <= {"event", "status", "operation", "changes", "arch", "certificate", "port", "code"}, "INVALID_REMOTE_PROTOCOL")
                    status = event.get("status")
                    require(status in ("FAILED", "SUCCESS", "CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED", "CHECK_EXISTING_HTTPS", "CHECK_MANAGED_TLS_STOPPED"), "INVALID_REMOTE_PROTOCOL")
                    if status == "FAILED":
                        code = event.get("code", "")
                        raise HttpsError(code if type(code) is str and code in SAFE_REMOTE_CODES else "REMOTE_HTTPS_FAILED")
                    if status == "SUCCESS":
                        required = cutover if event.get("operation") == "https-enabled" else ["verify-existing"]
                        require(options["mode"] == "apply" and history == required, "EXTERNAL_PROOF_SEQUENCE_REQUIRED")
                    else:
                        require(options["mode"] == "check" and not history, "INVALID_REMOTE_PROTOCOL")
                    if status == "CHECK_EXISTING_HTTPS": verify("verify-existing", event)
                    require(event.get("operation") in (None, "already-https", "https-enabled", "https-service-recovered") and event.get("changes") in ("none", "studio-tls-only") and event.get("arch") in (None, "x64", "arm64"), "INVALID_REMOTE_PROTOCOL")
                    require(status == "SUCCESS" or event.get("arch") in ("x64", "arm64"), "INVALID_REMOTE_PROTOCOL")
                    require(status != "SUCCESS" or event.get("operation") in ("already-https", "https-enabled", "https-service-recovered"), "INVALID_REMOTE_PROTOCOL")
                    # No arbitrary remote strings are printed or returned.
                    return {"status": status, "arch": event.get("arch"), "operation": event.get("operation"), "changes": event.get("changes", "none")}
                expected = {"event"} if phase == "ports-probe" else {"event", "fingerprint", "port"}
                require(set(event) == expected, "INVALID_REMOTE_PROTOCOL")
                require(options["mode"] == "apply" and (
                    history == cutover[:len(history)] and len(history) < len(cutover) and phase == cutover[len(history)] or
                    not history and phase == "verify-existing"), "EXTERNAL_PROOF_SEQUENCE_REQUIRED")
                verify(phase, event)
                self.write(json.dumps({"phase": phase, "nonce": options["nonce"], "ok": True}).encode()+b"\n", timeout=10)
                history.append(phase)
                print("VERIFIED_" + phase.replace("-", "_").upper(), flush=True)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise HttpsError("SSH_TRANSPORT_FAILED_OUTCOME_UNKNOWN") from None
        finally:
            if self.child:
                # EOF first: remote trap rolls back or preserves a committed
                # HTTPS result. Timer recovery covers SIGKILL/reboot/partition.
                failure = sys.exc_info()[0] is not None
                self.child.stdin.close()
                try: self.child.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    os.killpg(self.child.pid, signal.SIGTERM)
                    try: self.child.wait(timeout=10)
                    except subprocess.TimeoutExpired: os.killpg(self.child.pid, signal.SIGKILL); self.child.wait()
                self.child.stdout.close()
                if not failure and self.child.returncode != 0: raise HttpsError("SSH_EXIT_AFTER_RESULT_CHECK_AGAIN")


def verifier(normalized, nonce, diagnostics=None):
    host, addresses = normalized["hostname"], normalized["addresses"]
    def verify(phase, event):
        dns_records(host, addresses, diagnostics=diagnostics)
        if phase == "ports-probe":
            for address in addresses:
                for port in (80, 443): port_challenge(address, port, nonce)
            return
        require(type(event.get("port")) is int and (event["port"] == 3000 or 3100 <= event["port"] <= 3199), "INVALID_REMOTE_PROTOCOL")
        fingerprint = event.get("fingerprint", (event.get("certificate") or {}).get("fingerprint"))
        require(type(fingerprint) is str and re.fullmatch(r"[a-f0-9]{64}", fingerprint), "INVALID_REMOTE_PROTOCOL")
        # All published A/AAAA must reach the exact verified local certificate.
        for address in addresses:
            require(https_health(host, address)["fingerprint"] == fingerprint, "CERTIFICATE_PATH_DISAGREES")
            if phase in ("cutover-ready", "verify-existing"): require(closed(address, event["port"]), "PUBLIC_BACKEND_STILL_REACHABLE")
    return verify


def verified_main():
    require(os.environ.get("GITHUB_REF") == "refs/heads/main" and re.fullmatch(r"[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")), "VERIFIED_MAIN_REQUIRED")
    result = subprocess.run(["gh", "run", "list", "--repo", os.environ["GITHUB_REPOSITORY"], "--commit", os.environ["GITHUB_SHA"], "--event", "push", "--limit", "100", "--json", "name,status,conclusion,databaseId"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    require(result.returncode == 0, "MAIN_CHECKS_UNAVAILABLE")
    entries = json.loads(result.stdout)
    for name in ("Check backend foundation", "Check universal installer", "Check Studio HTTPS"):
        values = sorted((v for v in entries if v["name"] == name), key=lambda v: v["databaseId"], reverse=True)
        require(values and values[0]["status"] == "completed" and values[0]["conclusion"] == "success", "MAIN_CHECKS_NOT_SUCCESSFUL")


def main():
    diagnostics = []
    try:
        with open(os.environ["GITHUB_EVENT_PATH"]) as event: raw = json.load(event).get("inputs", {})
        raw = {k: raw.get(k, "") for k in ("server_ip", "additional_ip", "hostname", "mode", "confirmation")}
        normalized = inputs(raw)
        password = os.environ.get("STUDIO_SSH_PASSWORD", ""); require(bool(password), "STUDIO_SSH_PASSWORD_MISSING")
        for value in [normalized["hostname"], *normalized["addresses"]]: print("::add-mask::" + value)
        verified_main(); dns_records(normalized["hostname"], normalized["addresses"], diagnostics=diagnostics)
        nonce = secrets.token_hex(32)
        options = {**raw, "nonce": nonce}
        ssh = SSH(normalized["addresses"][0], password)
        checked = Session(ssh).run({**options, "mode": "check"}, verify=verifier(normalized, nonce, diagnostics))
        if normalized["mode"] == "check": result = checked
        else:
            with tempfile.TemporaryDirectory(prefix="studio-caddy-") as tmp:
                archive = download(checked["arch"], Path(tmp) / "caddy.tar.gz")
                result = Session(ssh).run(options, archive.read_bytes(), verifier(normalized, nonce, diagnostics))
        message = json.dumps(result, sort_keys=True)
        print(message)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
                output.write("## Studio managed HTTPS\n\n```json\n" + message + "\n```\n\nNo production booking POST was sent. Browser/SQLite acceptance is required in CI; this run verifies live TLS, health, read-only API and backend closure.\n")
        return 0
    except BaseException as error:
        code = str(error) if isinstance(error, (HttpsError, ValueError)) and re.fullmatch(r"[A-Z0-9_]{1,100}", str(error)) else "HTTPS_WORKFLOW_FAILED"
        print("FAILED: " + code)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out: out.write("## Studio HTTPS — FAILED\n\nSafe code: `"+code+"`. No success claimed. On transport loss run check after the recovery timer; never force an HTTP downgrade.\n")
        return 1

    finally:
        if diagnostics and os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output: output.write(dns_report(diagnostics))


if __name__ == "__main__": raise SystemExit(main())
