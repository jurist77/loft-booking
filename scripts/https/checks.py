"""Bounded verified TLS/DNS checks; no redirects, POSTs or response logging."""
import datetime as dt
import email.utils
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.parse
import urllib.request
from configuration import ACME
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
        require(response.status == 200 and len(body) <= 32768, "PUBLIC_SERVICE_UNAVAILABLE")
        return json.loads(body), response.headers


def acme_ready(fetch=fetch_json):
    try:
        data, headers = fetch(ACME)
        require(all(isinstance(data.get(k), str) and data[k].startswith("https://") for k in ("newNonce", "newAccount", "newOrder")), "ACME_UNAVAILABLE")
        stamp = email.utils.parsedate_to_datetime(headers["Date"]).timestamp()
        require(abs(time.time() - stamp) <= 300, "CLOCK_OR_ACME_DATE_UNCONFIRMED")
    except HttpsError: raise
    except Exception: raise HttpsError("ACME_UNAVAILABLE") from None


def dns_records(host, expected, fetch=fetch_json):
    """Two independent public resolvers, exact RRsets, no hidden CNAME/AAAA."""
    with deadline(60): return _dns_records(host, expected, fetch)


def _dns_records(host, expected, fetch):
    require(len(expected) in (1, 2), "DNS_INPUT_INVALID")
    desired = {ipaddress.ip_address(a).compressed for a in expected}
    try:
        for endpoint in ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"):
            def query(name, kind):
                data, _ = fetch(endpoint + "?" + urllib.parse.urlencode({"name": name, "type": kind}), "application/dns-json")
                require(type(data.get("Status")) is int and data["Status"] == 0 and not data.get("TC", False), "DNS_LOOKUP_FAILED")
                values = data.get("Answer", [])
                require(isinstance(values, list) and len(values) <= 16, "DNS_LOOKUP_FAILED")
                return values
            actual = set()
            for kind in (1, 28):
                for answer in query(host, kind):
                    require(answer.get("type") == kind and answer.get("name", "").rstrip(".").lower() == host, "DNS_ALIAS_OR_UNEXPECTED_ANSWER")
                    ip = ipaddress.ip_address(answer["data"])
                    require(ip.version == (4 if kind == 1 else 6), "DNS_LOOKUP_FAILED")
                    actual.add(ip.compressed)
            require(actual == desired, "DNS_ADDRESS_MISMATCH")
            for parent in (host, "duckdns.org", "org", "."):
                caa = query(parent, 257)
                if not caa: continue
                issuers = []
                for answer in caa:
                    require(answer.get("type") == 257, "CAA_UNCONFIRMED")
                    import re
                    m = re.fullmatch(r'(\d+)\s+(\w+)\s+"([^"\n]*)"', answer.get("data", ""))
                    require(m is not None, "CAA_UNCONFIRMED")
                    flag, tag, value = int(m[1]), m[2].lower(), m[3]
                    require(not (flag & 128 and tag not in ("issue", "issuewild", "iodef")), "CAA_UNCONFIRMED")
                    if tag == "issue": issuers.append(value.strip())
                # Parameters may constrain validation/account; do not guess them.
                require(not issuers or "letsencrypt.org" in issuers, "CAA_DISALLOWS_OR_CONSTRAINS_LE")
                break
    except HttpsError: raise
    except Exception: raise HttpsError("DNS_LOOKUP_FAILED") from None
    return True


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
    except Exception: raise HttpsError("HTTPS_VERIFICATION_FAILED") from None
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
