"""Bounded verified TLS/DNS checks; no redirects, POSTs or response logging."""
import datetime as dt
import email.utils
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from configuration import ACME, hostname
try:
    from probe_studio_network import deadline
except ModuleNotFoundError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "diagnostics"))
    from probe_studio_network import deadline


class HttpsError(Exception): pass


def require(condition, code):
    if not condition: raise HttpsError(code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): raise HttpsError("REDIRECT_REFUSED")


def fetch_json(url, accept="application/json"):
    opener = urllib.request.build_opener(NoRedirect())
    with deadline(10), opener.open(urllib.request.Request(url, headers={"Accept": accept}), timeout=8) as response:
        body = response.read(32769)
        require(response.status == 200, "HTTP_STATUS_UNEXPECTED")
        require(len(body) <= 32768, "RESPONSE_TOO_LARGE")
        return json.loads(body), response.headers


def acme_ready(fetch=fetch_json):
    try:
        data, headers = fetch(ACME)
        require(all(isinstance(data.get(k), str) and data[k].startswith("https://") for k in ("newNonce", "newAccount", "newOrder")), "ACME_UNAVAILABLE")
        stamp = email.utils.parsedate_to_datetime(headers["Date"]).timestamp()
        require(abs(time.time() - stamp) <= 300, "CLOCK_OR_ACME_DATE_UNCONFIRMED")
    except HttpsError: raise
    except Exception: raise HttpsError("ACME_UNAVAILABLE") from None


PROVIDERS = (("GOOGLE", "https://dns.google/resolve"), ("CLOUDFLARE", "https://cloudflare-dns.com/dns-query"))
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
KINDS = {1: "A", 28: "AAAA", 257: "CAA"}


def caa_hierarchy(host):
    """Closest name first, then every parent through the DNS root.

    No public-suffix/provider shortcut: a CAA RRset at any intermediate label
    can govern issuance. Aliases remain unsupported and fail closed.
    """
    labels = hostname(host).split(".")
    return [("HOST" if i == 0 else "TLD" if i == len(labels) - 1 else "PARENT", ".".join(labels[i:]))
            for i in range(len(labels))] + [("ROOT", ".")]


def dns_report(rows):
    """Only generated labels/numbers. Never names, IPs, URLs or raw errors."""
    enums = {
        "resolver": {"GOOGLE", "CLOUDFLARE"}, "scope": {"HOST", "PARENT", "TLD", "ROOT", "POLICY"},
        "type": {"A", "AAAA", "CAA", "ADDRESSES", "CAA_POLICY"}, "attempt": {"1", "2"},
        "use": {"REQUIRED", "DIAGNOSTIC"}, "http": {"NOT_RECEIVED", "HTTP_ERROR"},
        "dns": {"NOT_RECEIVED", "STATUS_INVALID"}, "answer": {"NOT_RECEIVED", "MISSING", "EMPTY", "NULL", "RECORDS", "INVALID"},
        "result": {"NODATA", "RECORDS_RECEIVED", "IP_MATCH", "DNS_ADDRESS_MISMATCH", "CAA_ALLOWED", "CAA_NOT_CONFIRMED",
                   "TIMEOUT", "TLS_ERROR", "TRANSPORT_ERROR", "INVALID_JSON", "HTTP_ERROR", "TOTAL_TIMEOUT", "JSON_NOT_OBJECT", "DNSSEC_CHECKING_DISABLED",
                   "STATUS_MISSING", "STATUS_INVALID", "TRUNCATION_INVALID", "TRUNCATED", "QUESTION_MISMATCH", "ANSWER_NULL",
                   "ANSWER_NOT_ARRAY", "ANSWER_LIMIT", "DNS_ALIAS_OR_UNEXPECTED_ANSWER", "HTTP_STATUS_UNEXPECTED", "RESPONSE_TOO_LARGE",
                   "REDIRECT_REFUSED", "UNEXPECTED_RESPONSE", *RCODES.values()}}
    text = "## Public DNS diagnostics\n\n| Resolver | Scope | Type | Try | Use | HTTP | DNS | Answer | Result |\n|---|---|---|---|---|---|---|---|---|\n"
    for row in rows:
        values = []
        for key in ("resolver", "scope", "type", "attempt", "use", "http", "dns", "answer", "result"):
            value = str(row.get(key, "NOT_APPLICABLE"))
            numeric_http = key in ("http", "result") and re.fullmatch(r"HTTP_[1-5][0-9]{2}", value)
            numeric_dns = key in ("dns", "result") and re.fullmatch(r"RCODE_[0-9]{1,4}", value) and int(value[6:]) <= 4095
            values.append(value if value == "NOT_APPLICABLE" or value in enums[key] or numeric_http or numeric_dns else "REDACTED")
        text += "| " + " | ".join(values) + " |\n"
    return text + "\nNOERROR + MISSING/EMPTY is valid NODATA. SERVFAIL, NXDOMAIN, HTTP errors and malformed responses are never treated as an absent AAAA/CAA. DIAGNOSTIC ancestor queries do not override the nearest CAA policy.\n"


class DnsQueries:
    """Two independent resolvers, two bounded attempts for transient failures.

    The monotonic budget stops new requests after 60s; an in-flight fetch has
    its own hard 10s deadline. No DNSSEC bypass, fallback resolver or raw logs.
    """
    def __init__(self, fetch=fetch_json, diagnostics=None, sleep=None, attempts=2):
        self.fetch, self.rows, self.sleep = fetch, diagnostics if diagnostics is not None else [], time.sleep if sleep is None else sleep
        require(type(attempts) is int and 1 <= attempts <= 2, "DNS_INPUT_INVALID")
        self.attempts = attempts
        self.end = time.monotonic() + 60
        self.cache = {}

    def query(self, provider, scope, name, kind, required=True):
        key = (provider, scope, name, kind)
        if key in self.cache:
            result = self.cache[key]
            if isinstance(result, HttpsError): raise result
            return result
        endpoint = dict(PROVIDERS)[provider]
        prefix = "DNS_" + provider + "_" + scope + "_" + KINDS[kind] + "_"
        for attempt in range(1, self.attempts + 1):
            row = {"resolver": provider, "scope": scope, "type": KINDS[kind], "attempt": attempt,
                   "use": "REQUIRED" if required else "DIAGNOSTIC", "http": "NOT_RECEIVED", "dns": "NOT_RECEIVED", "answer": "NOT_RECEIVED"}
            retry = False; delay = 1
            try:
                require(time.monotonic() < self.end, "TOTAL_TIMEOUT")
                # CD controls resolver validation; DO only requests raw DNSSEC RRs.
                # Leave DO unset so signed A answers keep the same JSON contract.
                data, _ = self.fetch(endpoint + "?" + urllib.parse.urlencode({"name": name, "type": kind, "cd": "false"}), "application/dns-json")
                row["http"] = "HTTP_200"
                require(isinstance(data, dict), "JSON_NOT_OBJECT")
                status = data.get("Status")
                row["dns"] = "RCODE_" + str(status) if type(status) is int and 0 <= status <= 4095 else "STATUS_INVALID"
                answer = data.get("Answer", [])
                row["answer"] = "MISSING" if "Answer" not in data else "EMPTY" if answer == [] else "NULL" if answer is None else "RECORDS" if isinstance(answer, list) else "INVALID"
                require("Status" in data, "STATUS_MISSING")
                require(type(status) is int and 0 <= status <= 4095, "STATUS_INVALID")
                if status != 0:
                    retry = status == 2
                    raise HttpsError(RCODES.get(status, "RCODE_" + str(status)))
                require(type(data.get("CD", False)) is bool and not data.get("CD", False), "DNSSEC_CHECKING_DISABLED")
                require(type(data.get("TC", False)) is bool, "TRUNCATION_INVALID")
                require(not data.get("TC", False), "TRUNCATED")
                if "Question" in data:
                    q = data["Question"]
                    require(isinstance(q, list) and len(q) == 1 and isinstance(q[0], dict) and
                            type(q[0].get("type")) is int and q[0]["type"] == kind and
                            isinstance(q[0].get("name"), str) and q[0]["name"].lower().rstrip(".") == name.lower().rstrip("."), "QUESTION_MISMATCH")
                require(answer is not None, "ANSWER_NULL")
                require(isinstance(answer, list), "ANSWER_NOT_ARRAY")
                require(len(answer) <= 16, "ANSWER_LIMIT")
                for record in answer:
                    require(isinstance(record, dict) and type(record.get("type")) is int and record["type"] == kind and
                            isinstance(record.get("name"), str) and record["name"].lower().rstrip(".") == name.lower().rstrip(".") and
                            isinstance(record.get("data"), str) and len(record["data"]) <= 4096, "DNS_ALIAS_OR_UNEXPECTED_ANSWER")
                row["result"] = "NODATA" if not answer else "RECORDS_RECEIVED"
                self.rows.append(row); self.cache[key] = answer
                return answer
            except urllib.error.HTTPError as error:
                reason = "HTTP_" + str(error.code) if type(error.code) is int and 100 <= error.code <= 599 else "HTTP_ERROR"
                row["http"] = reason; retry = type(error.code) is int and (error.code == 429 or 500 <= error.code <= 599)
                if retry and error.headers and error.headers.get("Retry-After"):
                    try:
                        raw = error.headers["Retry-After"]
                        delay = max(1, int(raw) if raw.isascii() and raw.isdigit() else email.utils.parsedate_to_datetime(raw).timestamp() - time.time())
                        if delay > 5: retry = False  # Do not retry earlier than the server allows.
                    except (ValueError, TypeError, OverflowError): retry = False
            except (TimeoutError, socket.timeout): reason = "TIMEOUT"; retry = True
            except urllib.error.URLError as error:
                if isinstance(error.reason, (TimeoutError, socket.timeout)): reason = "TIMEOUT"; retry = True
                elif isinstance(error.reason, ssl.SSLError): reason = "TLS_ERROR"
                else: reason = "TRANSPORT_ERROR"; retry = True
            except ssl.SSLError: reason = "TLS_ERROR"
            except json.JSONDecodeError: reason = "INVALID_JSON"
            except HttpsError as error:
                reason = str(error) if str(error) in {"TOTAL_TIMEOUT", "JSON_NOT_OBJECT", "STATUS_MISSING", "STATUS_INVALID", "DNSSEC_CHECKING_DISABLED", "TRUNCATION_INVALID", "TRUNCATED", "QUESTION_MISMATCH", "ANSWER_NULL", "ANSWER_NOT_ARRAY", "ANSWER_LIMIT", "DNS_ALIAS_OR_UNEXPECTED_ANSWER", "HTTP_STATUS_UNEXPECTED", "RESPONSE_TOO_LARGE", "REDIRECT_REFUSED", *RCODES.values()} or re.fullmatch(r"RCODE_[0-9]{1,4}", str(error)) else "UNEXPECTED_RESPONSE"
            except Exception: reason = "UNEXPECTED_RESPONSE"
            row["result"] = reason; self.rows.append(row)
            if not retry or attempt == self.attempts or time.monotonic() + delay >= self.end:
                failure = HttpsError(prefix + reason); self.cache[key] = failure; raise failure from None
            self.sleep(delay)

    def verify(self, host, expected):
        hierarchy = caa_hierarchy(host)
        try:
            require(len(expected) in (1, 2), "DNS_INPUT_INVALID")
            desired = {ipaddress.ip_address(a).compressed for a in expected}
        except (TypeError, ValueError): raise HttpsError("DNS_INPUT_INVALID") from None
        failures = []
        for provider, _ in PROVIDERS:
            records = {}; address_error = False
            for kind in (1, 28):
                try: records[kind] = self.query(provider, "HOST", host, kind)
                except HttpsError as error: failures.append(error); address_error = True
            if not address_error:
                try:
                    actual = set()
                    for kind, answers in records.items():
                        for record in answers:
                            ip = ipaddress.ip_address(record["data"])
                            require(ip.version == (4 if kind == 1 else 6), "DNS_ADDRESS_MISMATCH")
                            actual.add(ip.compressed)
                    require(actual == desired, "DNS_ADDRESS_MISMATCH")
                except (ValueError, HttpsError):
                    failures.append(HttpsError("DNS_" + provider + "_HOST_DNS_ADDRESS_MISMATCH"))
                    self.rows.append({"resolver": provider, "scope": "HOST", "type": "ADDRESSES", "result": "DNS_ADDRESS_MISMATCH"})
                else: self.rows.append({"resolver": provider, "scope": "HOST", "type": "ADDRESSES", "result": "IP_MATCH"})
            try:
                for scope, name in hierarchy:
                    caa = self.query(provider, scope, name, 257)
                    if not caa: continue
                    issuers = []
                    for record in caa:
                        match = re.fullmatch(r'(\d+)\s+(\w+)\s+"([^"\n]*)"', record["data"])
                        require(match is not None and 0 <= int(match[1]) <= 255, "CAA_UNCONFIRMED")
                        flag, tag, value = int(match[1]), match[2].lower(), match[3]
                        require(not (flag & 128 and tag not in ("issue", "issuewild", "iodef")), "CAA_UNCONFIRMED")
                        if tag == "issue": issuers.append(value.strip())
                    require(not issuers or "letsencrypt.org" in issuers, "CAA_DISALLOWS_OR_CONSTRAINS_LE")
                    break
                self.rows.append({"resolver": provider, "scope": "POLICY", "type": "CAA", "result": "CAA_ALLOWED"})
            except HttpsError as error:
                failures.append(error if str(error).startswith("DNS_") else HttpsError("DNS_" + provider + "_" + scope + "_CAA_" + str(error)))
                self.rows.append({"resolver": provider, "scope": scope, "type": "CAA_POLICY", "result": "CAA_NOT_CONFIRMED"})
        if failures: raise failures[0]
        return True


def dns_records(host, expected, fetch=fetch_json, diagnostics=None):
    """A missing AAAA/CAA is allowed only after a successful NOERROR response."""
    return DnsQueries(fetch, diagnostics).verify(host, expected)


class DirectHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname, address, port=443, context=None):
        super().__init__(hostname, port, timeout=5, context=context or ssl.create_default_context())
        self.target = address

    def connect(self):
        raw = socket.create_connection((self.target, self.port), timeout=5)
        try: self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException: raw.close(); raise


def https_health(host, address, minimum=7 * 86400, context=None, api=True, port=443):
    with deadline(15): return _https_health(host, address, minimum, context, api, port)


def _https_health(host, address, minimum, context, api, port):
    connection = DirectHTTPS(host, address, port, context)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert()
        left = ssl.cert_time_to_seconds(certificate["notAfter"]) - time.time()
        require(left >= minimum, "CERTIFICATE_EXPIRING")
        fingerprint = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        def get(path):
            connection.request("GET", path, headers={"Connection": "keep-alive"})
            response = connection.getresponse(); raw = response.read(32769)
            require(response.status != 503, "HTTPS_APPLICATION_UNAVAILABLE")
            require(response.status != 429, "HTTPS_VERIFICATION_RATE_LIMITED")
            require(response.status == 200 and len(raw) <= 32768, "HTTPS_HEALTH_OR_API_FAILED")
            return json.loads(raw), response
        value, _ = get("/api/health")
        require(value == {"status": "ok"}, "HTTPS_HEALTH_OR_API_FAILED")
        if api:
            date = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)).strftime("%Y-%m-%d")
            value, response = get("/api/availability?date=" + date)
            require(set(value) == {"date", "resourceId", "timezone", "busy"} and value["date"] == date and value["resourceId"] == "studio-19-25" and value["timezone"] == "Europe/Moscow" and isinstance(value["busy"], list), "HTTPS_HEALTH_OR_API_FAILED")
            require(all(isinstance(v, dict) and set(v) == {"start", "end"} for v in value["busy"]) and "no-store" in response.getheader("Cache-Control", ""), "HTTPS_API_CONTRACT_FAILED")
        return {"fingerprint": fingerprint, "lifetime_ok": True}
    except HttpsError: raise
    except ssl.SSLCertVerificationError as error: raise HttpsError("CERTIFICATE_TRUST_OR_NAME_FAILED") from error
    except Exception as error: raise HttpsError("HTTPS_VERIFICATION_FAILED") from error
    finally: connection.close()


def closed(address, port):
    try:
        with socket.create_connection((address, port), timeout=3): return False
    except (TimeoutError, ConnectionRefusedError): return True
    except OSError: raise HttpsError("EXTERNAL_PATH_UNCONFIRMED") from None


def port_challenge(address, port, nonce):
    connection = http.client.HTTPConnection(address, port, timeout=4)
    try:
        expected = hashlib.sha256((nonce + ":ports").encode()).hexdigest().encode()
        connection.request("GET", "/.well-known/studio-probe/" + expected.decode(), headers={"Connection": "close"})
        result = connection.getresponse()
        require(result.status == 200 and result.read(129) == expected, "PUBLIC_PORT_CHALLENGE_FAILED")
    except HttpsError: raise
    except Exception: raise HttpsError("PUBLIC_PORT_CHALLENGE_FAILED") from None
    finally: connection.close()
