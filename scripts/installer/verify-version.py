"""Restore can choose only an immutable, CI-verified ancestor of main."""
import json
import os
import re
import subprocess

def main():
    version = os.environ.get("STUDIO_SELECTED_VERSION", "")
    try:
        if os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("STUDIO_RESTORE_CONFIRMATION") != "RESTORE STUDIO 19.25":
            raise ValueError()
        if not re.fullmatch(r"[a-f0-9]{40}", version):
            raise ValueError()
        result = subprocess.run(["git", "merge-base", "--is-ancestor", version, "origin/main"], capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError()
        result = subprocess.run(["gh", "run", "list", "--repo", os.environ["GITHUB_REPOSITORY"], "--commit", version, "--event", "push",
                                 "--limit", "100", "--json", "name,status,conclusion,databaseId"], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError()
        runs = json.loads(result.stdout)
        for name in ("Check backend foundation", "Check read-only VPS audit tool", "Check universal installer"):
            matches = sorted([r for r in runs if r["name"] == name], key=lambda r:r["databaseId"], reverse=True)
            if not matches or matches[0]["conclusion"] != "success" or matches[0]["status"] != "completed":
                raise ValueError()
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write("version=" + version + "\n")
        print("RESTORE_VERSION_AND_CONFIRMATION_VERIFIED")
        return 0
    except Exception:
        print("FAILED: RESTORE_REQUIRES_CONFIRMATION_AND_VERIFIED_MAIN_VERSION")
        return 1

if __name__ == "__main__": raise SystemExit(main())
