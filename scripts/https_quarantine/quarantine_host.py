"""One failed-prepare quarantine, not a cleanup manager. No delete/restart/apply.

Only stdin-delivered reviewed code runs. A private write-ahead journal survives
partial moves/identity renames. No automatic rollback/resume on ambiguous errors.
"""
import contextlib
import ctypes
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import time

if 'TlsResidueInspector' not in globals():
    from probe_tls_residue import TlsResidueInspector, TLS_ROOTS, TLS_USER, TLS_CHECKS, TLS_UNIT_ROOTS, deadline, audit_tls_residue
    from probe_https_readiness import collect, read_https
    from probe_studio_network import read_health

CASE=42645562662
CONFIRM='QUARANTINE FAILED STUDIO HTTPS PREPARE'
HOLD='studio1925tls-hold'
QROOTS=('/opt/.studio1925-https-quarantine-42645562662',
        '/etc/.studio1925-https-quarantine-42645562662',
        '/var/lib/.studio1925-https-quarantine-42645562662')
TARGETS=tuple(p+'/residue' for p in QROOTS)
LOCK='/run/lock/studio1925-install.lock'
JOURNAL=QROOTS[0]+'/journal.json'
Q_CODES=('READY','DONE','CONFIRMATION_REQUIRED','INVALID_MODE','LOCK_UNAVAILABLE','PREFLIGHT_FAILED',
    'QUARANTINE_COLLISION','IDENTITY_COLLISION','SNAPSHOT_CHANGED','DEPENDENCY_FOUND',
    'MOVE_FAILED','IDENTITY_RENAME_FAILED','POSTCHECK_FAILED','OPERATION_FAILED')
Q_PHASES=('VALIDATE','LOCK','PROVE','PREPARE','MOVE_BASE','MOVE_CONFIG','MOVE_DATA',
    'VERIFY_MOVES','VERIFY_DEPENDENCIES','RENAME_USER','RENAME_GROUP','VERIFY_FINAL','COMPLETE')


class QuarantineError(Exception):pass


def q_require(value,code):
    if not value:raise QuarantineError(code)


def q_hash(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def q_stat(path):
    st=path.lstat()
    return [st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns]


def q_baseline():
    result={}
    for name in ('service','units','sockets4','sockets6','web4','web6'):
        state,value=read_https(name);q_require(state=='ok','PREFLIGHT_FAILED');result[name]=q_hash(value)
    for name in ('/etc/studio1925/server.env','/etc/systemd/system/studio1925.service','/var/lib/studio1925'):
        value=q_stat(Path(name))
        # Live DB work may change directory timestamps; never read/hash DB data.
        result[name]=value[:6] if name=='/var/lib/studio1925' else value
    return result


def q_safe_studio(report):
    s=report['studio'];h=report['host'];r=report['tls_residue']
    return (h['root'] and h['ubuntu24'] and h['arch'] in ('x64','arm64') and
        s['service']=={'read':'ok','LoadState':'loaded','ActiveState':'active','SubState':'running'} and
        s['listener_owned'] and s['snapshot_stable'] and s['local_health']=={'http':200,'ok':True,'error':'none'} and
        s['permissions_compatible'] and s['isolated_user'] and s['managed_rootfs'] and
        s['private_network']=='no' and not s['network_namespace'] and not s['drop_ins'] and
        all(p['read']=='ok' and not p['limited'] and not p['listeners'] for p in report['ports'].values()) and
        r['status']=='MATCHED_FAILED_PREPARE' and r['reason']=='MATCHED_PINNED_PREPARE' and
        not r['preservation_required'] and r['account']=='expected' and all(r['checks'][k]=='MATCH' for k in TLS_CHECKS))


class QuarantineOps:
    def __init__(self,reference,root=Path('/')):
        self.reference,self.root=reference,root
        self.root_uid=0

    def path(self,name):return self.root/name.lstrip('/')

    @contextlib.contextmanager
    def lock(self):
        st=self.path(LOCK).lstat()
        q_require(stat.S_ISREG(st.st_mode) and st.st_uid==self.root_uid and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,'LOCK_UNAVAILABLE')
        fd=os.open(self.path(LOCK),os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            q_require(os.fstat(fd).st_ino==st.st_ino and os.fstat(fd).st_dev==st.st_dev,'LOCK_UNAVAILABLE')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
        finally:os.close(fd)

    def baseline(self):return q_baseline()

    def prove(self):
        captured=[]
        report=collect(residue=lambda:audit_tls_residue(self.reference,read_https,capture=captured))
        q_require(q_safe_studio(report) and len(captured)==1,'PREFLIGHT_FAILED')
        return captured[0]

    def identity(self,name):
        value=pwd.getpwnam(name)
        return {'uid':value.pw_uid,'gid':value.pw_gid,'home':value.pw_dir,'shell':value.pw_shell}

    def other_identities(self):
        users=[(p.pw_name,p.pw_uid,p.pw_gid,p.pw_gecos,p.pw_dir,p.pw_shell) for p in pwd.getpwall() if p.pw_name not in (TLS_USER,HOLD)]
        groups=[(g.gr_name,g.gr_gid,g.gr_mem) for g in grp.getgrall() if g.gr_name not in (TLS_USER,HOLD)]
        return q_hash([sorted(users),sorted(groups)])

    def no_held_identity(self):
        for get in (pwd.getpwnam,grp.getgrnam):
            try:get(HOLD)
            except KeyError:continue
            raise QuarantineError('IDENTITY_COLLISION')
        for name in ('/etc/subuid','/etc/subgid'):
            path=self.path(name)
            if not path.exists():continue
            st=path.lstat()
            q_require(stat.S_ISREG(st.st_mode) and st.st_uid==self.root_uid and stat.S_IMODE(st.st_mode)==0o644 and st.st_nlink==1 and st.st_size<=2*1024**2,'PREFLIGHT_FAILED')
            fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME)
            try:
                data=os.read(fd,2*1024**2+1);q_require(len(data)<=2*1024**2,'PREFLIGHT_FAILED')
            finally:os.close(fd)
            q_require(not any(line.split(b':',1)[0] in (TLS_USER.encode(),HOLD.encode()) for line in data.splitlines()),'DEPENDENCY_FOUND')

    def destinations(self):
        for source,target,container in zip(TLS_ROOTS,TARGETS,QROOTS):
            path=self.path(container)
            q_require(not path.exists() and not path.is_symlink(),'QUARANTINE_COLLISION')
            parent=path.parent;st=parent.lstat()
            q_require(parent.resolve()==parent and stat.S_ISDIR(st.st_mode) and st.st_uid==self.root_uid and not st.st_mode&0o022,'PREFLIGHT_FAILED')
            q_require(st.st_dev==self.path(source).lstat().st_dev,'PREFLIGHT_FAILED')
        # No shell/mv/copy fallback. Ubuntu 24.04 glibc/kernel support renameat2.
        q_require(hasattr(ctypes.CDLL(None),'renameat2'),'PREFLIGHT_FAILED')
        for tool in ('/usr/sbin/usermod','/usr/sbin/groupmod'):
            q_require(os.access(tool,os.X_OK),'PREFLIGHT_FAILED')

    def make_containers(self):
        for name in QROOTS:
            os.mkdir(self.path(name),0o700)
            self.sync(self.path(name).parent)
            st=self.path(name).lstat()
            q_require(stat.S_ISDIR(st.st_mode) and st.st_uid==self.root_uid and stat.S_IMODE(st.st_mode)==0o700,'POSTCHECK_FAILED')

    def sync(self,path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    def journal(self,value):
        # Atomic replace only of our new private journal, never application files.
        path=self.path(JOURNAL);tmp=path.with_name('journal.next')
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'w') as output:
                json.dump(value,output,sort_keys=True);output.flush();os.fsync(output.fileno())
            os.replace(tmp,path);self.sync(path.parent)
        except BaseException:raise

    def move(self,source,target):
        source,target=self.path(source),self.path(target)
        q_require(source.lstat().st_dev==target.parent.lstat().st_dev,'MOVE_FAILED')
        libc=ctypes.CDLL(None,use_errno=True)
        fn=libc.renameat2;fn.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint);fn.restype=ctypes.c_int
        if fn(-100,os.fsencode(source),-100,os.fsencode(target),1)!=0:raise QuarantineError('MOVE_FAILED')
        self.sync(source.parent);self.sync(target.parent)

    def mapped(self,name):
        for source,target in zip(TLS_ROOTS,TARGETS):
            if name==source or name.startswith(source+'/'):return target+name[len(source):]
        raise QuarantineError('POSTCHECK_FAILED')

    def verify_moves(self,manifest):
        for name in QROOTS:
            path=self.path(name);st=path.lstat()
            q_require(path.resolve()==path and stat.S_ISDIR(st.st_mode) and st.st_uid==self.root_uid and stat.S_IMODE(st.st_mode)==0o700,'POSTCHECK_FAILED')
        for source in TLS_ROOTS:q_require(not self.path(source).exists() and not self.path(source).is_symlink(),'POSTCHECK_FAILED')
        for name,value in manifest.items():
            path=self.path(self.mapped(name));after=q_stat(path);before=value['stat']
            q_require(after[:8]==before[:8] and (name in TLS_ROOTS or after[8]==before[8]),'POSTCHECK_FAILED')
            if value['sha256'] is not None:
                reader=TlsResidueInspector(self.reference,root=self.root)
                q_require(reader.read(self.mapped(name),100*1024**2,hash_only=True)==value['sha256'],'POSTCHECK_FAILED')
        q_require(not list(self.path(TARGETS[2]).iterdir()),'POSTCHECK_FAILED')

    def dependencies(self,identity):
        # Only the already-verified three moved trees may retain this UID/GID.
        state,loaded=read_https('tls_dependencies');q_require(state=='ok','DEPENDENCY_FOUND')
        paths_state,paths=read_https('tls_unit_paths')
        q_require(paths_state=='ok' and paths.split() and all(any(p.startswith(r+'/') for r in TLS_UNIT_ROOTS) for p in paths.split()),'DEPENDENCY_FOUND')
        class HeldInspector(TlsResidueInspector):
            def related(self,name):return super().related(name) or any(name==p or name.startswith(p+'/') for p in TARGETS)
        inspector=HeldInspector(self.reference,root=self.root,loaded=loaded,dependency_roots=TARGETS,identity_names=(TLS_USER,HOLD))
        inspector.uid,inspector.gid=identity['uid'],identity['gid']
        with deadline(45):inspector.dependencies()
        q_require(read_https('tls_dependencies')==(state,loaded),'SNAPSHOT_CHANGED')
        q_require(read_https('tls_unit_paths')==(paths_state,paths),'SNAPSHOT_CHANGED')

    def rename_identity(self,kind):
        argv=['/usr/sbin/usermod','--login',HOLD,TLS_USER] if kind=='user' else ['/usr/sbin/groupmod','--new-name',HOLD,TLS_USER]
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        q_require(result.returncode==0,'IDENTITY_RENAME_FAILED')

    def final_identity(self,identity):
        q_require(self.identity(HOLD)==identity,'POSTCHECK_FAILED')
        for get in (pwd.getpwnam,grp.getgrnam):
            try:get(TLS_USER)
            except KeyError:continue
            raise QuarantineError('POSTCHECK_FAILED')
        group=grp.getgrnam(HOLD)
        q_require(group.gr_gid==identity['gid'] and not group.gr_mem,'POSTCHECK_FAILED')

    def healthy(self):
        q_require(read_health('127.0.0.1',3000)=={'http':200,'ok':True,'error':'none'},'POSTCHECK_FAILED')


def quarantine_once(mode,confirmation,ops):
    result={'status':'BLOCKED','code':'PREFLIGHT_FAILED','phase':'VALIDATE','moved':0,'identity_steps':0,'health':False,'changed':False}
    journal=None
    end=time.monotonic()+240
    def phase(name):
        q_require(time.monotonic()<end,'OPERATION_FAILED')
        result['phase']=name
        if journal is not None:
            journal.update(phase=name,moved=result['moved'],identity_steps=result['identity_steps']);ops.journal(journal)
    try:
        q_require(mode in ('check','quarantine'),'INVALID_MODE')
        q_require(mode!='quarantine' or confirmation==CONFIRM,'CONFIRMATION_REQUIRED')
        q_require(ops.reference.get('run_id')==CASE,'PREFLIGHT_FAILED')
        phase('LOCK')
        with ops.lock():
            phase('PROVE');baseline=ops.baseline();first=ops.prove()
            ops.no_held_identity();ops.destinations()
            identity=ops.identity(TLS_USER);others=ops.other_identities()
            second=ops.prove()
            keys=lambda i:{k:v for k,v in i.seen.items() if k in TLS_ROOTS or any(k.startswith(p+'/') for p in TLS_ROOTS)}
            q_require(keys(first)==keys(second) and ops.baseline()==baseline,'SNAPSHOT_CHANGED')
            q_require(identity==ops.identity(TLS_USER) and others==ops.other_identities(),'SNAPSHOT_CHANGED')
            manifest={name:{'stat':list(value),'sha256':second.read(name,100*1024**2,hash_only=True) if stat.S_ISREG(value[2]) else None} for name,value in keys(second).items()}
            q_require(len(manifest)==9,'PREFLIGHT_FAILED')
            q_require(keys(first)==keys(second) and ops.baseline()==baseline,'SNAPSHOT_CHANGED')
            ops.healthy();result['health']=True
            if mode=='check':result.update(status='READY',code='READY');return result
            ops.no_held_identity();ops.destinations()
            phase('PREPARE');result['changed']=True;ops.make_containers()
            journal={'format':1,'case':CASE,'reference_sha256':q_hash(ops.reference),'identity':identity,'manifest':manifest,'others_sha256':others}
            phase('PREPARE')
            for source,target,name in zip(TLS_ROOTS,TARGETS,('MOVE_BASE','MOVE_CONFIG','MOVE_DATA')):
                phase(name);ops.move(source,target);result['moved']+=1;phase(name)
            phase('VERIFY_MOVES');ops.verify_moves(manifest)
            phase('VERIFY_DEPENDENCIES');ops.dependencies(identity)
            q_require(ops.baseline()==baseline and ops.other_identities()==others,'SNAPSHOT_CHANGED');ops.healthy()
            phase('RENAME_USER');ops.no_held_identity();ops.rename_identity('user');result['identity_steps']=1;phase('RENAME_USER')
            phase('RENAME_GROUP');ops.rename_identity('group');result['identity_steps']=2;phase('RENAME_GROUP')
            phase('VERIFY_FINAL');ops.verify_moves(manifest);ops.final_identity(identity);ops.dependencies(identity)
            q_require(ops.other_identities()==others and ops.baseline()==baseline,'POSTCHECK_FAILED');ops.healthy()
            phase('COMPLETE');result.update(status='SUCCESS',code='DONE',health=True)
    except BaseException as error:
        code=str(error) if isinstance(error,QuarantineError) and str(error) in Q_CODES else 'OPERATION_FAILED'
        result.update(status='MANUAL_REVIEW_REQUIRED' if result['changed'] else 'BLOCKED',code=code,health=False)
        # Never overwrite the last durable intent during an ambiguous failure.
    return result
