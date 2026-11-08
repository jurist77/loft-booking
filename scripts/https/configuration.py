"""HTTPS configuration rendering. All runtime inputs are data, never shell."""
import ipaddress
import json
from pathlib import Path
import re
import sys

if "transport_settings" not in sys.modules:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "installer"))
from transport_settings import hostname

CONFIRMATION = "ENABLE STUDIO HTTPS"
ACME = "https://acme-v02.api.letsencrypt.org/directory"
BASE = Path("/opt/studio1925-https")
ETC = Path("/etc/studio1925-https")
DATA = Path("/var/lib/studio1925-tls")
USER = "studio1925tls"
SERVICE = "studio1925-tls.service"
RECOVERY_SERVICE = "studio1925-https-recover.service"
RECOVERY_TIMER = "studio1925-https-recover.timer"
MONITOR_SERVICE = "studio1925-https-monitor.service"
MONITOR_TIMER = "studio1925-https-monitor.timer"
UNIT_DIR = Path("/etc/systemd/system")
ADMIN = "unix//run/studio1925-tls/admin.sock"


def inputs(value, fixture=False):
    if not isinstance(value, dict) or set(value) - {"server_ip", "additional_ip", "hostname", "mode", "confirmation"}: raise ValueError("INVALID_INPUT")
    host = hostname(value.get("hostname"))
    addresses = []
    for key in ("server_ip", "additional_ip"):
        raw = value.get(key, "")
        if key == "additional_ip" and raw == "": continue
        if type(raw) is not str or "%" in raw: raise ValueError("INVALID_SERVER_IP")
        ip = ipaddress.ip_address(raw)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or getattr(ip, "ipv4_mapped", None) or (not fixture and not ip.is_global): raise ValueError("PUBLIC_LITERAL_IP_REQUIRED")
        if any(ip.version == ipaddress.ip_address(a).version for a in addresses): raise ValueError("ONE_ADDRESS_PER_FAMILY_REQUIRED")
        addresses.append(ip.compressed)
    mode = value.get("mode", "check")
    if mode not in ("check", "apply"): raise ValueError("INVALID_MODE")
    if mode == "apply" and value.get("confirmation") != CONFIRMATION: raise ValueError("CONFIRMATION_REQUIRED")
    return {"hostname": host, "addresses": addresses, "mode": mode}


def caddy_config(host, port):
    hostname(host)
    if type(port) is not int or not (port == 3000 or 3100 <= port <= 3199): raise ValueError("INVALID_BACKEND_PORT")
    response = {"X-Content-Type-Options": ["nosniff"], "Referrer-Policy": ["no-referrer"],
        "Permissions-Policy": ["camera=(), microphone=(), geolocation=()"], "X-Frame-Options": ["DENY"],
        "Strict-Transport-Security": ["max-age=300"],
        "Content-Security-Policy": ["frame-ancestors 'none'; base-uri 'self'; object-src 'none'"]}
    clean = ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Studio-Client-IP"]
    return {"admin": {"listen": ADMIN}, "storage": {"module": "file_system", "root": str(DATA / "storage")},
        "apps": {"http": {"servers": {
            "studio_https": {"listen": [":443"], "protocols": ["h1", "h2"], "automatic_https": {"disable_redirects": True},
                "routes": [{"match": [{"host": [host]}], "handle": [
                    {"handler": "headers", "request": {"delete": clean}, "response": {"set": response}},
                    {"handler": "reverse_proxy", "upstreams": [{"dial": f"127.0.0.1:{port}"}],
                     "headers": {"request": {"set": {"Host": [host], "X-Studio-Client-IP": ["{http.request.remote.host}"], "X-Forwarded-Host": [host], "X-Forwarded-Proto": ["https"]}}}}]},
                    {"handle": [{"handler": "static_response", "status_code": 421}]}]},
            "studio_http": {"listen": [":80"], "protocols": ["h1"], "routes": [
                {"match": [{"host": [host], "method": ["GET", "HEAD"]}], "handle": [{"handler": "static_response", "status_code": 308, "headers": {"Location": ["https://" + host + "{http.request.uri}"]}}]},
                {"handle": [{"handler": "static_response", "status_code": 405}]}]}}},
            "tls": {"automation": {"policies": [{"subjects": [host], "issuers": [{"module": "acme", "ca": ACME,
                "challenges": {"tls-alpn": {"disabled": True}}}]}]}}}}


def service(binary):
    if not re.fullmatch(re.escape(str(BASE)) + r"/releases/[0-9a-f]{64}/caddy", str(binary)): raise ValueError("INVALID_CADDY_PATH")
    return f"""# Managed Studio TLS only; no VPN/proxy dependencies.
[Unit]
Description=Studio 19.25 TLS
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5
[Service]
User={USER}
Group={USER}
ExecStart={binary} run --config {ETC}/caddy.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
RuntimeDirectory=studio1925-tls
RuntimeDirectoryMode=0700
UMask=0077
Environment=XDG_DATA_HOME={DATA} XDG_CONFIG_HOME={DATA}/config
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths={DATA} /run/studio1925-tls
InaccessiblePaths=-/etc/studio1925 -/var/lib/studio1925 -/var/backups/studio1925 -/etc/x-ui -/usr/local/x-ui -/etc/xray -/usr/local/etc/xray
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CPUAccounting=true
MemoryAccounting=true
IOAccounting=true
CPUWeight=25
IOWeight=25
OOMScoreAdjust=500
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
"""


def auxiliary_units():
    result = {}
    for action, unit in (("recover", RECOVERY_SERVICE), ("monitor", MONITOR_SERVICE)):
        result[unit] = f"""# Managed Studio TLS {action}; no other services.
[Unit]
Description=Studio TLS {action}
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {BASE}/control.py {action}
UMask=0077
NoNewPrivileges=true
ProtectHome=true
TimeoutStartSec=180
Nice=10
CPUWeight=25
IOWeight=25
OOMScoreAdjust=500
LogRateLimitIntervalSec=1h
LogRateLimitBurst=3
StandardOutput=journal
StandardError=null
"""
    result[RECOVERY_TIMER] = f"[Unit]\nDescription=Studio pending TLS recovery\n[Timer]\nOnBootSec=30s\nOnUnitInactiveSec=30s\nUnit={RECOVERY_SERVICE}\n[Install]\nWantedBy=timers.target\n"
    result[MONITOR_TIMER] = f"[Unit]\nDescription=Studio certificate watchdog\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=1h\nUnit={MONITOR_SERVICE}\n[Install]\nWantedBy=timers.target\n"
    return result
