#!/usr/bin/env python3
"""Manual runner coordinator. No default apply; never accepts arbitrary commands."""
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "diagnostics"))
from deploy import SSH, DeployError, server_ip
from probe_studio_network import read_health
from studio_network import health_valid, ProtocolError, SSH_ERRORS

CONFIRMATION = "ENABLE STUDIO TCP 3000"
STATUSES = ("READY_TO_APPLY", "ALREADY_ACCESSIBLE", "BLOCKED_FOR_SAFETY", "INCONCLUSIVE", "NO_CHANGE_REQUIRED", "FAILED_NO_CHANGE", "MANUAL_REVIEW_REQUIRED", "APPLIED_PENDING_EXTERNAL")
REASONS = ("CONFIRMATION_REQUIRED", "EXTERNAL_HEALTH_CONFIRMED", "PATH_AND_APPEND_PROVEN", "STATE_CHANGED_SINCE_CHECK", "UNEXPECTED_FIREWALL_DELTA", "ONLY_TCP_3000_ALLOW_ADDED", "OPERATION_NOT_CONFIRMED", "LOCK_OR_ROOT_UNAVAILABLE", "STUDIO_NOT_ACTIVE", "READS_INCOMPLETE", "PORT_NOT_EXCLUSIVELY_STUDIO", "PUBLIC_BIND_NOT_CONFIRMED", "LOCAL_HEALTH_FAILED", "UFW_NOT_ACTIVE", "POLICY_NOT_SUPPORTED", "EXISTING_OR_CONFLICTING_3000_RULE", "UNSUPPORTED_UFW_DEFAULTS", "UNSUPPORTED_UFW_IMPLEMENTATION", "UNSUPPORTED_HOST", "MIXED_OR_UNKNOWN_BACKEND", "OTHER_FILTERING_BACKEND", "ADDITIONAL_FILTERING", "FOREIGN_CHAINS", "UFW_RELOAD_WOULD_BE_REQUIRED", "PERSISTED_RULES_DIFFER", "ADDITIONAL_NFT_FILTERING", "PATH_NOT_PROVEN", "UFW_ADD_FAILED", "UNEXPECTED_UFW_COMMAND")


def validate(value):
    if not isinstance(value, dict) or set(value) - {"status", "reason", "change_possible", "fingerprint", "observations", "postflight"} or not {"status", "reason", "change_possible"} <= set(value): raise ProtocolError()
    if value["status"] not in STATUSES or value["reason"] not in REASONS or type(value["change_possible"]) is not bool: raise ProtocolError()
    if (value["status"] == "READY_TO_APPLY") != ("fingerprint" in value): raise ProtocolError()
    if "fingerprint" in value and (type(value["fingerprint"]) is not str or not re.fullmatch("[0-9a-f]{64}", value["fingerprint"])): raise ProtocolError()
    if value["status"] in ("READY_TO_APPLY", "ALREADY_ACCESSIBLE", "BLOCKED_FOR_SAFETY", "INCONCLUSIVE", "NO_CHANGE_REQUIRED", "FAILED_NO_CHANGE") and value["change_possible"]: raise ProtocolError()
    if value["status"] == "APPLIED_PENDING_EXTERNAL" and not value["change_possible"]: raise ProtocolError()
    if (value["status"] == "APPLIED_PENDING_EXTERNAL") != ("postflight" in value): raise ProtocolError()
    if "postflight" in value:
        post = value["postflight"]
        if not isinstance(post, dict) or set(post) != {"only_expected_firewall_delta", "persistent_allow", "ufw_allow", "studio_active", "local_health"} or any(v is not True for v in post.values()): raise ProtocolError()
    if "observations" in value:
        obs = value["observations"]
        flags = ("studio_active", "port_owned_by_studio", "public_bind", "local_health", "path_and_method_proven")
        if not isinstance(obs, dict) or set(obs) != {*flags, "ufw", "incoming", "allow3000", "deny3000"}: raise ProtocolError()
        if any(type(obs[key]) is not bool for key in flags): raise ProtocolError()
        if obs["ufw"] not in ("active", "inactive", "unknown") or obs["incoming"] not in ("allow", "deny", "reject", "unknown"): raise ProtocolError()
        if any(type(obs[key]) is not int or not 0 <= obs[key] <= 100000 for key in ("allow3000", "deny3000")): raise ProtocolError()
    return value


def payload(options):
    # No remote files/modules or host Python site customization. Dependencies
    # are embedded from this checkout; all inputs are JSON data, never code.
    probe = (ROOT / "diagnostics/probe_studio_network.py").read_text().split('\nif __name__ == "__main__":')[0]
    source = probe + "\n" + Path(__file__).with_name("rules.py").read_text() + "\n" + Path(__file__).with_name("host.py").read_text()
    source += "\nCOMMANDS = HOST_COMMANDS\n"
    source += "\nprint(json.dumps(remote_main(json.loads(" + repr(json.dumps(options)) + "))))\n"
    return source.encode()


def call(ssh, options):
    with tempfile.TemporaryFile(mode="w+b") as stream:
        stream.write(payload(options)); stream.seek(0)
        return validate(ssh.execute("python3 -I -B -S -", stream, timeout=240))


def run(address, password, mode, confirmation, ssh_factory=SSH, health=read_health, remote_call=call):
    if mode not in ("check", "apply") or (mode == "apply" and confirmation != CONFIRMATION):
        return {"status": "FAILED_NO_CHANGE", "reason": "CONFIRMATION_REQUIRED", "change_possible": False}
    attempted = False; external = None
    try:
        ssh = ssh_factory(address, password)
        external = health(address); health_valid(external)
        options = {"mode": "check", "confirmation": "", "family": ipaddress.ip_address(address).version, "accessible": external["ok"]}
        preflight = remote_call(ssh, options)
        if preflight["status"] not in ("READY_TO_APPLY", "ALREADY_ACCESSIBLE", "BLOCKED_FOR_SAFETY", "INCONCLUSIVE"): raise ProtocolError()
        if mode == "check": return {**preflight, "external_before": external}
        if preflight["status"] == "ALREADY_ACCESSIBLE": return {**preflight, "status": "NO_CHANGE_REQUIRED", "external_before": external}
        if preflight["status"] != "READY_TO_APPLY": return {**preflight, "status": "FAILED_NO_CHANGE", "external_before": external}
        attempted = True  # A lost reply after this point has unknown outcome.
        applied = remote_call(ssh, {**options, "mode": "apply", "confirmation": confirmation, "expected": preflight["fingerprint"]})
        if applied["status"] not in ("FAILED_NO_CHANGE", "MANUAL_REVIEW_REQUIRED", "APPLIED_PENDING_EXTERNAL"): raise ProtocolError()
        if applied["status"] != "APPLIED_PENDING_EXTERNAL": return {**applied, "external_before": external}
        after = health(address); health_valid(after)
        return {**applied, "status": "SUCCESS" if after["ok"] else "APPLIED_BUT_UNREACHABLE", "external_before": external, "external_after": after}
    except Exception as error:
        # Do not echo SSH stderr, SQL/HTTP bodies, raw remote JSON or exceptions.
        return {"status": "MANUAL_REVIEW_REQUIRED" if attempted else "FAILED_NO_CHANGE" if mode == "apply" else "INCONCLUSIVE",
                "reason": str(error) if isinstance(error, DeployError) and str(error) in SSH_ERRORS else "SSH_OR_PROTOCOL_NOT_CONFIRMED", "change_possible": attempted,
                **({"external_before": external} if external is not None else {})}


def emit(report):
    # Only locally generated or schema-validated values reach logs/summary.
    report.pop("fingerprint", None)
    text = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2)
    print(text)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a") as stream:
            stream.write("## Studio HTTP access\n\n```json\n" + text + "\n```\n\n")
            stream.write("Only TCP/3000 UFW allow is permitted. No automatic rollback. A firewall change can affect existing connections; VPN continuity is not guaranteed. HTTP is for synthetic technical tests only; use HTTPS before real contact data.\n")


def main():
    try:
        mode = os.environ.get("STUDIO_HTTP_MODE", "check")
        confirmation = os.environ.get("STUDIO_HTTP_CONFIRMATION", "")
        if mode not in ("check", "apply") or (mode == "apply" and confirmation != CONFIRMATION): raise ValueError()
        address = server_ip(os.environ.get("STUDIO_SERVER_IP", ""))
        password = os.environ.get("STUDIO_SSH_PASSWORD", "")
        if not password: raise ValueError()
        if os.environ.get("GITHUB_REF") != "refs/heads/main": raise ValueError()
    except (DeployError, ValueError):
        emit({"status": "FAILED_NO_CHANGE", "reason": "INVALID_INPUT_SECRET_OR_REF", "change_possible": False}); return 1
    report = run(address, password, mode, confirmation)
    emit(report)
    return 0 if report["status"] in ("READY_TO_APPLY", "ALREADY_ACCESSIBLE", "SUCCESS", "NO_CHANGE_REQUIRED") else 1


if __name__ == "__main__": raise SystemExit(main())
