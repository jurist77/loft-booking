#!/usr/bin/env python3
"""Public DNS-only check. No SSH, Secrets, VPS connection, ACME or DNS writes."""
import json
import os
from configuration import inputs
from checks import DnsQueries, PROVIDERS, HttpsError, dns_report, fetch_json


def run(host, addresses, fetch=fetch_json):
    rows=[];probe=DnsQueries(fetch,rows)
    try:probe.verify(host,addresses);outcome="DNS_CHECK_PASSED";success=True
    except HttpsError as error:outcome=str(error);success=False
    # Inspect unvisited ancestors separately for diagnosis. Their results cannot
    # override the nearest CAA RRset or a failed required hostname lookup.
    for provider,_ in PROVIDERS:
        for scope,name in (("HOST",host),("PARENT","duckdns.org"),("TLD","org"),("ROOT",".")):
            if (provider,scope,name,257) not in probe.cache:
                try:probe.query(provider,scope,name,257,required=False)
                except HttpsError:pass
    return rows,outcome,success


def main():
    try:
        with open(os.environ["GITHUB_EVENT_PATH"]) as stream:raw=json.load(stream)["inputs"]
        value=inputs({**raw,"mode":"check","confirmation":""})
        rows,outcome,success=run(value["hostname"],value["addresses"])
        report=dns_report(rows)+"\n"+outcome+"\n\nDNS-only: no SSH, Secrets, VPS connection, ACME issuance, DNS/firewall writes or apply.\n"
        print(report)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as stream:stream.write(report)
        return 0 if success else 1
    except Exception:
        print("DNS_CHECK_INPUT_OR_REPORT_FAILED");return 1


if __name__=="__main__":raise SystemExit(main())
