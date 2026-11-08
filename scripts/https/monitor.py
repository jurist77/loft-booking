#!/usr/bin/env python3
"""Public-only certificate monitor. No SSH, secrets, issuance or booking POST."""
import ipaddress
import json
import os
import re
import sys
from configuration import hostname
from checks import fetch_json, dns_records, https_health, HttpsError, require


def check(host):
    host = hostname(host)
    addresses = []
    for kind in (1, 28):
        data, _ = fetch_json("https://dns.google/resolve?name=" + host + "&type=" + str(kind), "application/dns-json")
        require(data.get("Status") == 0, "MONITOR_DNS_FAILED")
        for record in data.get("Answer", []):
            require(record.get("type") == kind and record.get("name", "").rstrip(".") == host, "MONITOR_DNS_ALIAS_REFUSED")
            ip = ipaddress.ip_address(record["data"])
            require(ip.is_global and not getattr(ip, "ipv4_mapped", None), "MONITOR_NONPUBLIC_ADDRESS_REFUSED")
            addresses.append(ip.compressed)
    require(1 <= len(addresses) <= 2 and len(set(addresses)) == len(addresses), "MONITOR_DNS_FAILED")
    dns_records(host, addresses)
    for address in addresses: https_health(host, address)


def main():
    try:
        require(os.environ.get("GITHUB_REF") == "refs/heads/main", "MAIN_REQUIRED")
        if os.environ.get("STUDIO_TEST_NOTIFICATION") == "true": raise HttpsError("MONITOR_NOTIFICATION_TEST_NO_NETWORK")
        check(os.environ.get("STUDIO_HTTPS_HOSTNAME", ""))
        code = "HEALTHY_CERTIFICATE_OVER_7_DAYS"; status = 0
    except Exception as error:
        code = str(error) if isinstance(error, (HttpsError, ValueError)) and re.fullmatch(r"[A-Z0-9_]+", str(error)) else "HTTPS_MONITOR_FAILED"
        status = 1
    print(code)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write("## Studio HTTPS monitoring\n\n" + code + "\n\nFailures require owner attention: inspect renewal/availability before expiration. Enable GitHub Actions failure notifications and verify delivery. No SSH, repair or production booking was performed.\n")
    return status


if __name__ == "__main__": raise SystemExit(main())
