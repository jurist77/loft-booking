"""One transient OS-authorized CLI in the installed release; no service edits."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

LIMIT=8192
class Rejected(Exception):pass

def require(value,code):
    if not value:raise Rejected(code)

def command(args,input=None):
    try:
        p=subprocess.run(args,input=input,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=75,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        require(len(p.stdout)<=LIMIT,'MANAGEMENT_RESPONSE_LIMIT')
        if input is None:
            require(p.returncode==0,'STUDIO_PREFLIGHT_FAILED');return p.stdout.decode()
        result=json.loads(p.stdout)
        if p.returncode or result.get('status')!='OK':
            safe={'AUTH_INVALID','CONCURRENT_POLLING','BOT_CHANGED_RELINK_REQUIRED','CONFIGURATION_PLAN_CHANGED',
                  'BOOTSTRAP_CONFIRMATION_INVALID','OWNER_ALREADY_BOOTSTRAPPED','INSTANCE_MISMATCH','WEBHOOK_CONFIGURED',
                  'WEBHOOK_STATE_UNCONFIRMED','NETWORK_UNCERTAIN','RATE_LIMITED','TEMPORARY_FAILURE'}
            raise Rejected(result.get('code') if result.get('code') in safe else 'MANAGEMENT_OPERATION_REJECTED')
        return result
    except (OSError,ValueError,subprocess.SubprocessError):raise Rejected('MANAGEMENT_RESULT_UNKNOWN') from None

def private(path,owner,mode,folder=False):
    p=Path(path);s=p.lstat()
    require((stat.S_ISDIR(s.st_mode) if folder else stat.S_ISREG(s.st_mode)) and not p.is_symlink() and
            s.st_uid==owner and stat.S_IMODE(s.st_mode)==mode and (folder or s.st_nlink==1),'STUDIO_PATH_UNSAFE')
    return p

@contextlib.contextmanager
def lock():
    path=private('/run/lock/studio1925-install.lock',0,0o600)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);require(s.st_ino==path.lstat().st_ino,'STUDIO_PATH_CHANGED')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)

def run(payload):
    require(os.geteuid()==0,'ROOT_REQUIRED')
    operation=payload.get('operation')
    require(operation in ('plan','configure','bootstrap','diagnose') and set(payload)<={'operation','token','confirmation','expected'},'INVALID_OPERATION')
    with lock():
        private('/etc/studio1925',0,0o700,True)
        state=json.loads(private('/etc/studio1925/state.json',0,0o600).read_text())
        release=state.get('current','');require(re.fullmatch(r'[a-f0-9]{40}-[a-f0-9]{16}-[a-f0-9]{8}',release),'STUDIO_STATE_INVALID')
        root=Path('/opt/studio1925/releases')/release/'root'
        for p in (Path('/opt/studio1925'),Path('/opt/studio1925/releases'),root.parent,root):
            info=p.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and not p.is_symlink(),'STUDIO_PATH_UNSAFE')
        require((root/'app/src/server/telegram/management.ts').is_file(),'STUDIO_UPGRADE_REQUIRED')
        user=pwd.getpwnam('studio1925');require(user.pw_uid>0 and user.pw_gid>0,'STUDIO_ACCOUNT_INVALID')
        private('/var/lib/studio1925',user.pw_uid,0o700,True)
        props=('LoadState','ActiveState','SubState','User','RootDirectory','FragmentPath','DropInPaths')
        def service():
            raw=command(['systemctl','show','studio1925.service',*('--property='+p for p in props)])
            return dict(line.split('=',1) for line in raw.splitlines() if '='in line)
        before=service()
        require(before.get('LoadState')=='loaded' and before.get('ActiveState')=='active' and before.get('SubState')=='running' and
            before.get('User')=='studio1925' and before.get('RootDirectory')==str(root) and
            before.get('FragmentPath')=='/etc/systemd/system/studio1925.service' and not before.get('DropInPaths'),'STUDIO_PREFLIGHT_FAILED')
        argv=['systemd-run','--quiet','--wait','--pipe','--collect','--property=User=studio1925','--property=Group=studio1925',
            '--property=RootDirectory='+str(root),'--property=WorkingDirectory=/app','--property=BindPaths=/var/lib/studio1925:/data',
            '--property=BindReadOnlyPaths=-/etc/resolv.conf:/etc/resolv.conf','--property=UMask=0077','--property=NoNewPrivileges=true',
            '--property=ProtectSystem=strict','--property=PrivateTmp=true','--property=RuntimeMaxSec=60',
            '--setenv=APP_MODE=server','--setenv=SQLITE_PATH=/data/studio.sqlite',
            '/usr/bin/node','--conditions=react-server','scripts/telegram.mjs','manage','--local-operator']
        result=command(argv,json.dumps(payload).encode())
        require(service()==before,'STUDIO_CHANGED_DURING_OPERATION')
        return result

if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(LIMIT+1);require(len(raw)<=LIMIT,'INPUT_LIMIT')
        print(json.dumps(run(json.loads(raw))))
    except BaseException as error:
        print(json.dumps({'status':'FAILED','code':str(error) if isinstance(error,Rejected) else 'MANAGEMENT_RESULT_UNKNOWN'}));sys.exit(1)
