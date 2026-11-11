"""Transfer the pinned native Caddy archive through LOCAL bootstrap pipes.

No SSH, host admission, Caddy execution, VPS or production apply is performed.
The native installer CI has already downloaded this checksummed public file.
"""
import argparse
import hashlib
from pathlib import Path
import platform

from test_session_transport import transfer_full_archive, workflow


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--archive',type=Path,required=True)
    args=parser.parse_args()
    arch={'x86_64':'x64','aarch64':'arm64'}.get(platform.machine())
    if arch not in workflow.RELEASE['archives']:raise RuntimeError('TRANSPORT_TEST_ARCH_UNSUPPORTED')
    with args.archive.open('rb') as source:archive=source.read(64*1024**2)
    if not 0<len(archive)<64*1024**2 or hashlib.sha256(archive).hexdigest()!=workflow.RELEASE['archives'][arch]['sha256']:
        raise RuntimeError('TRANSPORT_TEST_CHECKSUM_FAILED')
    size=transfer_full_archive(archive)
    print(f'PINNED_CADDY_ARCHIVE_PIPE_OK: arch={arch}; bytes={size}; original bootstrap; SHA256 matched; no VPS access')


if __name__=='__main__':main()
