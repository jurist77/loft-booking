"""Temporary-tree fixtures. real_identity=True is restricted to disposable CI."""
import copy
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/https_quarantine'),str(ROOT/'scripts/diagnostics')]
import quarantine_host as host


class FixtureOps(host.QuarantineOps):
    def __init__(self,root,real_identity=False):
        reference=json.loads((ROOT/'scripts/diagnostics/https-residue-reference.json').read_text())
        reference=copy.deepcopy(reference);reference['window']=[int(time.time())-30,int(time.time())+30]
        reference['hostname_sha256']=hashlib.sha256(b'reference.example.org').hexdigest()
        super().__init__(reference,root);self.root_uid=os.getuid();self.real_identity=real_identity
        self.user={'uid':888,'gid':889,'home':'/nonexistent','shell':'/usr/sbin/nologin'} if not real_identity else super().identity(host.TLS_USER)
        self.users={host.TLS_USER:dict(self.user)};self.groups={host.TLS_USER:self.user['gid']}
        self.fault=None;self.moves=0;self.proofs=0;self.commands=[];self.health_ok=True
        arch={'x86_64':'x64','aarch64':'arm64'}[platform.machine()]
        self.base,self.etc,self.data=(self.path(name) for name in host.TLS_ROOTS)
        self.release=self.base/'releases'/reference['release']['archives'][arch]['sha256']
        for path in (self.release,self.etc,self.data,self.path('/proc/self'),self.path('/run/lock')):path.mkdir(parents=True,exist_ok=True)
        for path in (self.base,self.etc,self.data,self.base/'releases',self.release):path.chmod(0o700)
        if real_identity:
            os.chown(self.data,self.user['uid'],self.user['gid']);os.chown(self.etc,0,self.user['gid'])
        (self.path('/proc/self/mountinfo')).write_text('1 0 8:1 / / rw - ext4 /dev/fixture rw\n')
        lock=self.path(host.LOCK);lock.touch();lock.chmod(0o600)
        self.canary=self.root/'studio.sqlite-canary';self.canary.write_bytes(b'SYNTHETIC ONLY; NEVER READ A VPS DB')
        for path,value,mode in ((self.base/'control.py',b'synthetic pinned control',0o644),
                (self.release/'caddy',b'synthetic caddy ELF',0o755),(self.release/'LICENSE',b'synthetic license',0o644),
                (self.etc/'caddy.json',json.dumps(reference['config_template']).encode(),0o640)):
            path.write_bytes(value);path.chmod(mode)
            if path.name=='caddy.json' and real_identity:os.chown(path,0,self.user['gid'])
            if path.name=='control.py':reference['control_sha256']=hashlib.sha256(value).hexdigest()
            elif path.name!='caddy.json':reference['files'][arch][path.name]=hashlib.sha256(value).hexdigest()

    def baseline(self):return {'canary':host.q_stat(self.canary)}

    def prove(self):
        self.proofs+=1
        if self.fault=='proof:'+str(self.proofs):raise host.QuarantineError('PREFLIGHT_FAILED')
        account=SimpleNamespace(pw_name=host.TLS_USER,pw_uid=self.user['uid'],pw_gid=self.user['gid'],pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        groups=lambda:[SimpleNamespace(gr_name=host.TLS_USER,gr_gid=self.user['gid'],gr_mem=[])]
        inspector=host.TlsResidueInspector(self.reference,root=self.root,account=lambda _:account,groups=groups)
        inspector.root_uid=self.root_uid
        if not self.real_identity:
            original=inspector.info
            def info(name):
                st=original(name)
                value={k:getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                if name==host.TLS_ROOTS[2]:value.update(st_uid=self.user['uid'],st_gid=self.user['gid'])
                if name in (host.TLS_ROOTS[1],host.TLS_ROOTS[1]+'/caddy.json'):value['st_gid']=self.user['gid']
                return SimpleNamespace(**value)
            inspector.info=info
        result=inspector.audit()
        host.q_require(result['status']=='MATCHED_FAILED_PREPARE','PREFLIGHT_FAILED')
        return inspector

    def identity(self,name):
        return super().identity(name) if self.real_identity else dict(self.users[name])

    def other_identities(self):return super().other_identities() if self.real_identity else 'synthetic-other-identities'

    def no_held_identity(self):
        if self.real_identity:return super().no_held_identity()
        host.q_require(host.HOLD not in self.users and host.HOLD not in self.groups,'IDENTITY_COLLISION')

    def move(self,source,target):
        self.moves+=1
        if self.fault=='move:'+str(self.moves)+':before':raise OSError('SYNTHETIC_SECRET')
        super().move(source,target)
        if self.fault=='move:'+str(self.moves)+':after':raise OSError('SYNTHETIC_SECRET')

    def dependencies(self,identity):
        if self.fault=='dependencies':raise host.QuarantineError('DEPENDENCY_FOUND')
        def read(name):return ('ok','Id=studio1925.service\n') if name=='tls_dependencies' else ('ok','/etc/systemd/system')
        with patch.object(host,'read_https',side_effect=read):super().dependencies(identity)

    def rename_identity(self,kind):
        self.commands.append(kind)
        if self.fault==kind+':before':raise OSError('SYNTHETIC_SECRET')
        if self.real_identity:super().rename_identity(kind)
        else:
            table=self.users if kind=='user' else self.groups
            table[host.HOLD]=table.pop(host.TLS_USER)
        if self.fault==kind+':after':raise OSError('SYNTHETIC_SECRET')

    def final_identity(self,identity):
        if self.real_identity:return super().final_identity(identity)
        host.q_require(self.users=={host.HOLD:identity} and self.groups=={host.HOLD:identity['gid']},'POSTCHECK_FAILED')

    def healthy(self):host.q_require(self.health_ok,'POSTCHECK_FAILED')
