#!/usr/bin/env python3
"""Create an allowlisted, relocatable Ubuntu 24.04 SERVER root filesystem."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

NODE_VERSION = "v24.12.0"


def sha(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_tree(source, destination):
    def ignore(_directory, names):
        return [name for name in names if name.startswith(".env") or name in
                (".git", "cache", "__pycache__", "test-results", "playwright-report") or
                any(marker in name for marker in ("linuxmusl", "-musl", "win32", "darwin", "-arm64" if platform.machine() == "x86_64" else "-x64")) or
                name.endswith((".test.ts", ".sqlite", ".sqlite-wal", ".sqlite-shm", ".pem", ".key"))]
    # Dereference only links staying inside the source tree. No escaping tar links.
    for entry in source.rglob("*"):
        if entry.is_symlink() and not entry.resolve().is_relative_to(source.resolve()):
            raise RuntimeError("SOURCE_SYMLINK_ESCAPE")
    shutil.copytree(source, destination, symlinks=False, ignore=ignore)


def build(destination, version):
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise RuntimeError("INVALID_VERSION")
    release = Path("/etc/os-release").read_text()
    if 'ID=ubuntu' not in release or 'VERSION_ID="24.04"' not in release:
        raise RuntimeError("BUILD_REQUIRES_UBUNTU_24_04")
    node = Path(shutil.which("node")).resolve()
    if subprocess.check_output([node, "--version"], text=True).strip() != NODE_VERSION:
        raise RuntimeError("BUILD_NODE_VERSION_MISMATCH")
    arch = {"x86_64": "x64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise RuntimeError("BUILD_ARCH_UNSUPPORTED")
    with tempfile.TemporaryDirectory(prefix="studio-package-") as temporary:
        staging = Path(temporary)
        root = staging / "root"
        app = root / "app"
        app.mkdir(parents=True)
        for name in (".next-server", "node_modules", "public", "src"):
            copy_tree(Path(name), app / name)
        for name in ("package.json", "package-lock.json", "next.config.ts"):
            shutil.copyfile(name, app / name)
        (app / "scripts/installer").mkdir(parents=True)
        shutil.copyfile("scripts/database.mjs", app / "scripts/database.mjs")
        shutil.copyfile("scripts/installer/schema.mjs", app / "scripts/installer/schema.mjs")
        copy_tree(Path("migrations/sqlite"), app / "migrations/sqlite")
        for name in ("usr/bin", "etc", "dev", "proc", "sys", "tmp", "data", "backups", "app/.next-server/cache", "licenses"):
            (root / name).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(node, root / "usr/bin/node")
        os.chmod(root / "usr/bin/node", 0o755)
        # Resolve every native dependency on the matching Ubuntu/architecture.
        binaries = [node, *sorted((app / "node_modules").rglob("*.node"))]
        for binary in binaries:
            result = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, check=False)
            if result.returncode or "not found" in result.stdout:
                raise RuntimeError("NATIVE_DEPENDENCY_UNRESOLVED")
            for library in re.findall(r"(?:=>\s+|^\s*)(/[^\s()]+)", result.stdout, re.M):
                source = Path(library)
                if source.is_relative_to(root):
                    continue  # e.g. sharp's packaged libvips with an $ORIGIN rpath
                if not str(source).startswith(("/lib/", "/lib64/", "/usr/lib/")):
                    raise RuntimeError("UNEXPECTED_NATIVE_LIBRARY")
                target = root / source.relative_to("/")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source.resolve(), target)
        for package in ("libc6", "libgcc-s1", "libstdc++6", "zlib1g"):
            license_file = Path("/usr/share/doc") / package / "copyright"
            if license_file.exists():
                shutil.copyfile(license_file, root / "licenses" / package)
        node_license = node.parent.parent / "LICENSE"
        if not node_license.is_file():
            raise RuntimeError("NODE_LICENSE_MISSING")
        shutil.copyfile(node_license, root / "licenses/Node-LICENSE")
        migrations = {p.name: sha(p) for p in sorted((app / "migrations/sqlite").glob("*.sql"))}
        manifest = {"format": 1, "version": version, "os": "ubuntu", "os_version": "24.04", "arch": arch,
                    "node": NODE_VERSION, "node_abi": "137", "mode": "server", "migrations": migrations,
                    "unpacked_bytes": sum(p.stat().st_size for p in root.rglob("*") if p.is_file())}
        (staging / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
        with tarfile.open(destination, "w:gz", dereference=True) as archive:
            archive.add(staging / "manifest.json", arcname="manifest.json")
            archive.add(root, arcname="root")
    Path(str(destination) + ".sha256").write_text(sha(destination) + "\n")
    print("SERVER_PACKAGE_READY")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    build(args.output, args.version)
