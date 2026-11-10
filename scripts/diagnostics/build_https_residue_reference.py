#!/usr/bin/env python3
"""Rebuild a public evidence profile. Runner/local only, never executed on VPS.

Only this reviewed failed run is supported; not an arbitrary installer version.
Archive checksums come from its immutable source commit, not from the VPS.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

SOURCE = 'd46d2a067c60560a66176f742f0a094c34871579'
DEST = Path(__file__).with_name('https-residue-reference.json')


def build():
    with tempfile.TemporaryDirectory(prefix='studio-reference-') as tmp:
        root = Path(tmp)
        archive = subprocess.run(['git', 'archive', SOURCE, 'scripts'], check=True, capture_output=True).stdout
        import io
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            source.extractall(root, filter='data')
        code = "import sys,json,hashlib;sys.path.insert(0,'scripts/https');import workflow;print(json.dumps({'control':hashlib.sha256(workflow.source()).hexdigest(),'config':__import__('configuration').caddy_config('reference.example.org',3000)}))"
        value = json.loads(subprocess.run([sys.executable, '-B', '-c', code], cwd=root, check=True,
            capture_output=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'}).stdout)
        release = json.loads((root/'scripts/https/caddy-release.json').read_text())
        result = {'format':1, 'run_id':42645562662, 'source_sha':SOURCE,
            'window':[1794238303,1794238361], 'release':release, 'control_sha256':value['control'],
            # Owner-provided target for this specific failed attempt; no hostname/IP in source or logs.
            'hostname_sha256':'8eb29f5f13d86babe90c7cf7792eb99b392e90722dc1d17cf493b76be6c3dec9',
            'config_template':value['config'], 'files':{}}
        for arch, item in release['archives'].items():
            path = root/(arch+'.tar.gz')
            url = 'https://github.com/caddyserver/caddy/releases/download/v'+release['version']+'/'+item['asset']
            with urllib.request.urlopen(url, timeout=40) as response, path.open('xb') as output:
                total=0
                while chunk := response.read(1024*1024):
                    total+=len(chunk)
                    if total>64*1024**2: raise ValueError('ARCHIVE_LIMIT')
                    output.write(chunk)
            if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']: raise ValueError('CHECKSUM')
            with tarfile.open(path) as source:
                result['files'][arch]={name:hashlib.sha256(source.extractfile(name).read()).hexdigest() for name in ('caddy','LICENSE')}
        return result


if __name__=='__main__':
    value=build()
    if sys.argv[1:]==['--verify']:
        if value!=json.loads(DEST.read_text()): raise SystemExit('REFERENCE_MISMATCH')
        print('PINNED_FAILED_PREPARE_REFERENCE_VERIFIED')
    elif not sys.argv[1:]: DEST.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    else: raise SystemExit('INVALID_ARGUMENT')
