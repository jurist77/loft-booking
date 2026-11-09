#!/usr/bin/env python3
"""Pinned Caddy + unmodified production JSON; disposable CI /tmp files only.

No server, ACME issuance, user creation or systemd operations. Existing nobody
identity stands in for the isolated TLS user. Raw validation stderr is not logged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import sys
import tarfile
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/https'),str(ROOT/'scripts/installer'),str(ROOT/'scripts/diagnostics'),str(ROOT/'scripts/firewall')]
import remote
sys.modules['studio_installer']=remote
import configuration as cfg
import host
from artifacts import RELEASE


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--archive',type=Path,required=True);args=parser.parse_args()
    if not (os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('STUDIO_CADDY_VALIDATE_CI')=='1'):
        raise SystemExit('DISPOSABLE_ROOT_CI_REQUIRED')
    arch={'x86_64':'x64','aarch64':'arm64'}[platform.machine()]
    archive=args.archive.read_bytes()
    assert hashlib.sha256(archive).hexdigest()==RELEASE['archives'][arch]['sha256'],'CADDY_CHECKSUM_MISMATCH'
    account=pwd.getpwnam('nobody');assert account.pw_uid!=0
    with tempfile.TemporaryDirectory(prefix='studio-prod-caddy-') as tmp:
        root=Path(tmp);root.chmod(0o755)
        binary=root/'caddy'
        with tarfile.open(args.archive) as source:binary.write_bytes(source.extractfile('caddy').read())
        binary.chmod(0o755)
        config=cfg.caddy_config('fixture.dynv6.net',3000)
        file=root/'production.json';file.write_text(json.dumps(config));file.chmod(0o644)
        xdg=root/'xdg';xdg.mkdir(mode=0o700);os.chown(xdg,account.pw_uid,account.pw_gid)
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','XDG_DATA_HOME':str(xdg),'XDG_CONFIG_HOME':str(xdg/'config')}
        run=lambda argv:subprocess.run(argv,capture_output=True,text=True,env=env,timeout=30)
        result=run(['runuser','-u','nobody','--',str(binary),'validate','--config',str(file)])
        assert result.returncode==0,'PRODUCTION_JSON_VALIDATE_FAILED'
        print('PRODUCTION_JSON_VALIDATE_OK: official pinned Caddy, unmodified issuer/admin/storage/listeners/headers',flush=True)
        # Exercise actual prepare under the entry's umask. Only host paths,
        # account creation and systemd calls are isolated; runuser/validate and
        # every mkdir/chown/chmod/atomic write are real.
        base=root/'base';etc=root/'etc';data=root/'data';units=root/'units';units.mkdir()
        actual_run=subprocess.run
        def observed_run(argv,**kwargs):
            if argv[:3]==['runuser','-u','nobody'] and 'validate' in argv:
                kwargs.update(stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                result=actual_run(argv,**kwargs)
                if result.returncode:
                    marker='VALIDATE_EXEC_PERMISSION_DENIED' if 'Permission denied' in result.stderr else 'VALIDATE_OTHER_FAILURE'
                    print(marker,flush=True)
                return result
            return actual_run(argv,**kwargs)
        def commands(argv,*a,**kw):
            assert argv[0] in ('useradd','systemctl'),'UNEXPECTED_HOST_COMMAND'
            return ''
        original_service=cfg.service
        with patch.object(host,'BASE',base),patch.object(host,'ETC',etc),patch.object(host,'DATA',data),patch.object(host,'OWNER',base/'managed.json'),patch.object(host,'UNIT_DIR',units),patch.object(host,'USER','nobody'),patch.object(host,'RELEASE',RELEASE),patch.object(remote,'host_facts',return_value={'arch':arch}),patch.object(remote,'run',side_effect=commands),patch.object(remote.subprocess,'run',side_effect=observed_run),patch.object(host,'service',side_effect=lambda path:original_service(cfg.BASE/'releases'/RELEASE['archives'][arch]['sha256']/'caddy')):
            previous=os.umask(0o077)
            try:
                try:host.Operations('synthetic reviewed control source').prepare({'port':3000},archive,{'hostname':'fixture.dynv6.net'},None)
                except Exception:
                    print('PREPARE_MODES base='+oct(base.stat().st_mode&0o777)+' etc='+oct(etc.stat().st_mode&0o777)+' releases='+oct((base/'releases').stat().st_mode&0o777),flush=True)
                    raise
            finally:os.umask(previous)
        assert json.loads((etc/'caddy.json').read_text())==config,'PRODUCTION_JSON_WAS_CHANGED'
        print('PRODUCTION_PREPARE_VALIDATE_OK: umask077; separate TLS uid; exact generated JSON',flush=True)


if __name__=='__main__':main()
