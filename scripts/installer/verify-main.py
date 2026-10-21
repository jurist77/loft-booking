#!/usr/bin/env python3
"""No SSH: gate manual installation on main's exact successful push checks."""
import json
import os
import re
import subprocess
from deploy import DeployError, server_ip


def main():
    try:
        server_ip(os.environ.get("STUDIO_SERVER_IP", ""))
        sha = os.environ.get("GITHUB_SHA", "")
        if os.environ.get("GITHUB_REF") != "refs/heads/main" or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise DeployError("MAIN_REQUIRED")
        result = subprocess.run(["gh", "run", "list", "--repo", os.environ["GITHUB_REPOSITORY"],
                                 "--commit", sha, "--event", "push", "--limit", "50",
                                 "--json", "name,status,conclusion,databaseId"], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise DeployError("MAIN_CHECKS_UNAVAILABLE")
        runs = json.loads(result.stdout)
        for name in ("Check backend foundation", "Check read-only VPS audit tool", "Check universal installer"):
            matches = sorted([run for run in runs if run["name"] == name], key=lambda run: run["databaseId"], reverse=True)
            if not matches or matches[0]["status"] != "completed" or matches[0]["conclusion"] != "success":
                raise DeployError("MAIN_CHECKS_NOT_SUCCESSFUL")
        print("MAIN_EXACT_SHA_VERIFIED; IP_VALIDATED; no SSH attempted")
        return 0
    except Exception as error:
        print("FAILED: " + (str(error) if isinstance(error, DeployError) else "MAIN_CHECKS_UNAVAILABLE"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
