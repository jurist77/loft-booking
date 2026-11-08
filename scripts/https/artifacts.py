"""Pinned public Caddy archives. No latest tag, custom URL or credentials."""
import hashlib
import json
from pathlib import Path
import urllib.request
from checks import require

RELEASE = json.loads(Path(__file__).with_name("caddy-release.json").read_text())


def download(arch, destination):
    item = RELEASE["archives"][arch]
    url = "https://github.com/caddyserver/caddy/releases/download/v" + RELEASE["version"] + "/" + item["asset"]
    destination = Path(destination)
    digest = hashlib.sha256(); total = 0
    with urllib.request.urlopen(url, timeout=30) as response, destination.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk); require(total < 64 * 1024**2, "CADDY_ARCHIVE_TOO_LARGE")
            digest.update(chunk); output.write(chunk)
    require(digest.hexdigest() == item["sha256"], "CADDY_CHECKSUM_MISMATCH")
    return destination
