"""Fixed, bounded, fail-closed attribution of ONE failed prepare. No writes.

Never execute installed code or read application/SQLite/VPN data. Only public
TLS staging files are read; unknown DATA children (including keys) block without
being opened. Output is fixed labels/booleans/mode bits, never paths or digests.
"""
import hashlib
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat

if 'deadline' not in globals():
    from probe_studio_network import deadline

TLS_ROOTS = ('/opt/studio1925-https','/etc/studio1925-https','/var/lib/studio1925-tls')
TLS_USER = 'studio1925tls'
TLS_UNIT_ROOTS = ('/etc/systemd','/run/systemd','/usr/lib/systemd','/usr/local/lib/systemd','/lib/systemd')
TLS_UNIT_NAMES = ('studio1925-tls.service','studio1925-https-recover.service','studio1925-https-recover.timer',
    'studio1925-https-monitor.service','studio1925-https-monitor.timer')
TLS_CHECKS = ('metadata','fingerprints','identity','empty_data','no_state','dependencies','stable')
TLS_REASONS = ('NOT_CHECKED','READ_OR_LIMIT_FAILED','REFERENCE_INVALID','METADATA_MISMATCH',
    'UNEXPECTED_OBJECT','STATE_REQUIRES_PRESERVATION','FINGERPRINT_MISMATCH','IDENTITY_MISMATCH',
    'DEPENDENCY_FOUND','DEPENDENCY_REVIEW_REQUIRED','SNAPSHOT_CHANGED','STUDIO_NOT_HEALTHY','MATCHED_PINNED_PREPARE')


class TlsBlocked(Exception):
    pass


def tls_empty_report():
    return {'status':'BLOCKED','reason':'NOT_CHECKED','checks':{key:'NOT_CHECKED' for key in TLS_CHECKS},
        'objects':{key:{'kind':'unknown','owner':'unknown','group':'unknown','mode':0} for key in ('base','config','data')},
        'account':'unknown','preservation_required':True}


class TlsResidueInspector:
    """root is only for isolated fixtures; production always uses / and /proc."""
    def __init__(self, reference, root=Path('/'), account=pwd.getpwnam, groups=grp.getgrall, loaded='', machine=platform.machine,
                 dependency_roots=TLS_ROOTS, identity_names=(TLS_USER,)):
        self.reference,self.root,self.account,self.groups=reference,root,account,groups
        self.seen={}; self.report=tls_empty_report(); self.uid=self.gid=None
        self.root_uid=0
        self.loaded=loaded
        self.machine=machine
        self.dependency_roots=dependency_roots
        self.identity_names=identity_names

    def block(self, code): raise TlsBlocked(code)

    def path(self, name): return self.root/name.lstrip('/')

    def info(self, name):
        if self.related(name):
            # NOFOLLOW on the final open does not protect symlinked parents.
            # The original prepare also requires canonical root-owned paths.
            for parent in self.path(name).parents:
                if parent==self.root:break
                st=parent.lstat()
                if not stat.S_ISDIR(st.st_mode) or st.st_uid!=self.root_uid or st.st_mode&0o022:
                    self.block('METADATA_MISMATCH')
        value=self.path(name).lstat()
        if not name.startswith('/proc/') and os.listxattr(self.path(name),follow_symlinks=False):
            self.block('METADATA_MISMATCH')
        self.seen[name]=(value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
            value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        return value

    def opened(self, name, directory=False):
        # NOATIME avoids changing filesystem timestamps. No fallback on denial.
        flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NOATIME
        if directory:flags|=os.O_DIRECTORY
        return os.open(self.path(name),flags)

    def names(self, name):
        fd=self.opened(name,True)
        try:
            with os.scandir(fd) as entries:
                values=[]
                for entry in entries:
                    values.append(entry.name)
                    if len(values)>10000:self.block('READ_OR_LIMIT_FAILED')
                return values
        finally:os.close(fd)

    def read(self, name, limit, hash_only=False):
        before=self.info(name)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:
            self.block('METADATA_MISMATCH')
        fd=self.opened(name)
        try:
            opened=os.fstat(fd)
            if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):self.block('SNAPSHOT_CHANGED')
            data=bytearray();digest=hashlib.sha256();total=0
            while chunk:=os.read(fd,min(1024*1024,limit+1-total)):
                total+=len(chunk)
                if total>limit:self.block('READ_OR_LIMIT_FAILED')
                if hash_only:digest.update(chunk)
                else:data.extend(chunk)
        finally:os.close(fd)
        return digest.hexdigest() if hash_only else bytes(data)

    def absent(self,name):
        try:self.path(name).lstat()
        except FileNotFoundError:return
        self.block('STATE_REQUIRES_PRESERVATION')

    def metadata(self):
        try:account=self.account(TLS_USER)
        except KeyError:
            self.report['account']='missing';self.block('IDENTITY_MISMATCH')
        self.uid,self.gid=account.pw_uid,account.pw_gid
        all_groups=self.groups()
        if not (0<self.uid<1000 and 0<self.gid<1000 and self.uid!=self.root_uid and
                account.pw_name==TLS_USER and account.pw_dir=='/nonexistent' and account.pw_shell=='/usr/sbin/nologin' and
                [g.gr_name for g in all_groups if g.gr_gid==self.gid]==[TLS_USER] and
                all(not g.gr_mem for g in all_groups if g.gr_gid==self.gid) and
                not any(TLS_USER in g.gr_mem for g in all_groups)):
            self.report['account']='unsafe';self.block('IDENTITY_MISMATCH')
        # No second passwd identity may alias the dedicated uid or primary gid.
        if self.root==Path('/') and any(p.pw_name!=TLS_USER and (p.pw_uid==self.uid or p.pw_gid==self.gid) for p in pwd.getpwall()):
            self.block('IDENTITY_MISMATCH')
        self.report['account']='expected'
        self.report['checks']['identity']='MATCH'
        expected=((self.root_uid,self.root_uid),(self.root_uid,self.gid),(self.uid,self.gid))
        for key,name,(uid,gid) in zip(('base','config','data'),TLS_ROOTS,expected):
            value=self.info(name)
            self.report['objects'][key]={'kind':'directory' if stat.S_ISDIR(value.st_mode) else 'other',
                'owner':'root' if value.st_uid==self.root_uid else 'tls' if value.st_uid==self.uid else 'other',
                'group':'root' if value.st_gid==self.root_uid else 'tls' if value.st_gid==self.gid else 'other',
                'mode':stat.S_IMODE(value.st_mode)}
            if not (stat.S_ISDIR(value.st_mode) and value.st_uid==uid and value.st_gid==gid and stat.S_IMODE(value.st_mode)==0o700):
                self.block('METADATA_MISMATCH')
        self.report['checks']['metadata']='MATCH'

    def files(self):
        ref=self.reference
        for name in ('managed.json','transaction.json'):self.absent(TLS_ROOTS[0]+'/'+name)
        self.absent('/run/studio1925-tls')
        self.report['checks']['no_state']='MATCH'
        if self.names(TLS_ROOTS[2]):self.block('STATE_REQUIRES_PRESERVATION')
        self.report['checks']['empty_data']='MATCH'
        base,config,_=TLS_ROOTS
        if set(self.names(base))!={'control.py','releases'} or set(self.names(config))!={'caddy.json'}:
            self.block('UNEXPECTED_OBJECT')
        choices=set(self.names(base+'/releases'))
        arch=next((a for a,v in ref['release']['archives'].items() if choices=={v['sha256']}),None)
        if arch is None or arch!={'x86_64':'x64','aarch64':'arm64'}.get(self.machine()):self.block('FINGERPRINT_MISMATCH')
        release=base+'/releases/'+ref['release']['archives'][arch]['sha256']
        if set(self.names(release))!={'caddy','LICENSE'}:self.block('UNEXPECTED_OBJECT')
        for name in (base+'/releases',release):
            st=self.info(name)
            if not stat.S_ISDIR(st.st_mode) or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(self.root_uid,self.root_uid,0o700):
                self.block('METADATA_MISMATCH')
        items=((base+'/control.py',0o644,self.root_uid,ref['control_sha256'],500000),
            (release+'/caddy',0o755,self.root_uid,ref['files'][arch]['caddy'],100*1024**2),
            (release+'/LICENSE',0o644,self.root_uid,ref['files'][arch]['LICENSE'],100000),
            (config+'/caddy.json',0o640,self.gid,None,32000))
        for name,mode,gid,digest,limit in items:
            st=self.info(name)
            if not stat.S_ISREG(st.st_mode) or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)!=(self.root_uid,gid,mode,1):
                self.block('METADATA_MISMATCH')
            data=self.read(name,limit,hash_only=bool(digest))
            if digest and data!=digest:self.block('FINGERPRINT_MISMATCH')
            if digest is None:
                def unique(pairs):
                    result={}
                    for k,v in pairs:
                        if k in result:raise ValueError()
                        result[k]=v
                    return result
                try:
                    actual=json.loads(data,object_pairs_hook=unique)
                    host=actual['apps']['tls']['automation']['policies'][0]['subjects'][0]
                except (ValueError,KeyError,IndexError,TypeError):self.block('FINGERPRINT_MISMATCH')
                if not isinstance(host,str) or len(host)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',host):
                    self.block('FINGERPRINT_MISMATCH')
                if hashlib.sha256(host.encode()).hexdigest()!=ref['hostname_sha256']:self.block('FINGERPRINT_MISMATCH')
                expected=json.loads(json.dumps(ref['config_template']).replace('reference.example.org',host))
                # Python equality equates True/1/1.0. Canonical JSON preserves
                # their types, rejects non-standard NaN/Infinity, and still
                # permits harmless whitespace/key ordering differences.
                try:
                    canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)
                    if canonical(actual)!=canonical(expected):self.block('FINGERPRINT_MISMATCH')
                except ValueError:self.block('FINGERPRINT_MISMATCH')
        # Timestamps corroborate exact fingerprints; never establish identity alone.
        start,end=ref['window']
        for name,value in self.seen.items():
            if not self.related(name):continue
            if not all(start-120<=t/1e9<=end+120 for t in value[-2:]):self.block('METADATA_MISMATCH')
        self.report['checks']['fingerprints']='MATCH'

    def related(self, name):
        return any(name==p or name.startswith(p+'/') for p in TLS_ROOTS) or name=='/run/studio1925-tls' or name.startswith('/run/studio1925-tls/')

    def mounts(self, name):
        # mountinfo is kernel metadata, never configuration or process arguments.
        text=self.read(name,2*1024**2).decode()
        if not text.strip():self.block('READ_OR_LIMIT_FAILED')
        for line in text.splitlines():
            fields=line.split()
            if len(fields)<10 or ' - ' not in line:self.block('READ_OR_LIMIT_FAILED')
            def unescape(v):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),v)
            if any(self.related(unescape(v)) for v in (fields[3],fields[4])):self.block('DEPENDENCY_FOUND')
            mountpoint=unescape(fields[4])
            if name=='/proc/self/mountinfo' and not any(mountpoint==p or mountpoint.startswith(p+'/') for p in ('/proc','/sys','/dev')):
                # Never trigger autofs/FUSE/network I/O by traversing another
                # application's mount. Review before touching any staging path.
                fstype=fields[fields.index('-')+1]
                if fstype not in ('ext2','ext3','ext4','xfs','btrfs','overlay','tmpfs','ramfs','squashfs','vfat'):
                    self.block('DEPENDENCY_REVIEW_REQUIRED')
        return hashlib.sha256(text.encode()).hexdigest()

    def dependencies(self):
        def has_reference(raw):
            if any(v in raw for v in (*TLS_ROOTS,*self.identity_names,'/run/studio1925-tls',*TLS_UNIT_NAMES)):return True
            for key,value in re.findall(r'(?m)^\s*(User|Group|SupplementaryGroups)[ \t]*=[ \t]*([^\n]*)$',raw):
                if str(self.uid if key=='User' else self.gid) in value.split():return True
            return False
        if has_reference(self.loaded):self.block('DEPENDENCY_FOUND')
        pids={p for p in self.names('/proc') if p.isdecimal()}
        # Every process namespace is checked; disappearing /proc entries are the
        # only tolerated race. Permission denials and output limits block.
        for pid in pids:
            try:
                raw=self.read('/proc/'+pid+'/status',64000).decode()
                ids=[re.findall(r'^'+field+r':\s+([0-9 \t]+)\s*$',raw,re.M) for field in ('Uid','Gid')]
                if any(len(v)!=1 for v in ids):self.block('READ_OR_LIMIT_FAILED')
                if self.uid in map(int,ids[0][0].split()) or self.gid in map(int,ids[1][0].split()):self.block('DEPENDENCY_FOUND')
                supplementary=re.findall(r'^Groups:[ \t]*([0-9 \t]*)$',raw,re.M)
                if len(supplementary)!=1:self.block('READ_OR_LIMIT_FAILED')
                if self.gid in map(int,supplementary[0].split()):self.block('DEPENDENCY_FOUND')
                self.mounts('/proc/'+pid+'/mountinfo')
                for line in self.read('/proc/'+pid+'/maps',2*1024**2).decode().splitlines():
                    fields=line.split(None,5)
                    if len(fields)<5:self.block('READ_OR_LIMIT_FAILED')
                    if len(fields)==6 and self.related(fields[5].removesuffix(' (deleted)')):self.block('DEPENDENCY_FOUND')
                for name in ('cwd','root','exe'):
                    try:target=os.readlink(self.path('/proc/'+pid+'/'+name))
                    except FileNotFoundError:
                        # Kernel threads have no exe; require the PID itself to
                        # be alive before treating that field as absent.
                        if not self.path('/proc/'+pid).exists():raise
                        continue
                    if self.related(target.removesuffix(' (deleted)')):self.block('DEPENDENCY_FOUND')
                for fd in self.names('/proc/'+pid+'/fd'):
                    try:target=os.readlink(self.path('/proc/'+pid+'/fd/'+fd))
                    except FileNotFoundError:
                        # This single-threaded reader closes its own scandir
                        # descriptors before inspection. No other fd race is OK.
                        if int(pid)==os.getpid():continue
                        self.block('SNAPSHOT_CHANGED')
                    if self.related(target.removesuffix(' (deleted)')):self.block('DEPENDENCY_FOUND')
            except FileNotFoundError:self.block('SNAPSHOT_CHANGED')
        self.mounts('/proc/self/mountinfo')
        # Metadata-only filesystem walk catches foreign uid/gid ownership,
        # symlink references and mount aliases. No application file is opened.
        todo=['/'];count=0;visited=set()
        while todo:
            parent=todo.pop()
            directory=self.path(parent).lstat();identity=(directory.st_dev,directory.st_ino)
            if identity in visited:self.block('DEPENDENCY_REVIEW_REQUIRED')
            visited.add(identity)
            for leaf in self.names(parent):
                name=parent.rstrip('/')+'/'+leaf
                if name in ('/proc','/sys','/dev') or name in self.dependency_roots:continue
                count+=1
                if count>2000000:self.block('READ_OR_LIMIT_FAILED')
                st=self.path(name).lstat()
                if st.st_uid==self.uid or st.st_gid==self.gid:self.block('DEPENDENCY_FOUND')
                if leaf in TLS_UNIT_NAMES:self.block('DEPENDENCY_FOUND')
                if stat.S_ISLNK(st.st_mode):
                    target=os.path.normpath(os.path.join(parent,os.readlink(self.path(name))))
                    if self.related(target):self.block('DEPENDENCY_FOUND')
                    if (Path(name).suffix in ('.service','.socket','.timer','.path','.target','.mount','.automount','.slice','.scope','.conf') and
                            any(name.startswith(r+'/') for r in TLS_UNIT_ROOTS) and target!='/dev/null' and
                            not any(target.startswith(r+'/') for r in TLS_UNIT_ROOTS)):
                        self.block('DEPENDENCY_REVIEW_REQUIRED')
                elif stat.S_ISDIR(st.st_mode):todo.append(name)
                elif (stat.S_ISREG(st.st_mode) and Path(name).suffix in
                        ('.service','.socket','.timer','.path','.target','.mount','.automount','.slice','.scope','.conf') and
                        any(name==r or name.startswith(r+'/') for r in TLS_UNIT_ROOTS)):
                    raw=self.read(name,512000).decode()
                    if has_reference(raw):self.block('DEPENDENCY_FOUND')
        if pids!={p for p in self.names('/proc') if p.isdecimal()}:self.block('SNAPSHOT_CHANGED')
        self.report['checks']['dependencies']='MATCH'

    def audit(self):
        self.report=tls_empty_report();self.seen={}
        try:
            if self.reference.get('format')!=1:self.block('REFERENCE_INVALID')
            mounts=self.mounts('/proc/self/mountinfo')
            self.metadata();self.files();self.dependencies()
            if self.mounts('/proc/self/mountinfo')!=mounts:self.block('SNAPSHOT_CHANGED')
            for name,before in list(self.seen.items()):
                # /proc values change normally; their identifiers are never evidence files.
                if name.startswith('/proc/'):continue
                self.info(name)
                if self.seen[name]!=before:self.block('SNAPSHOT_CHANGED')
            self.report['checks']['stable']='MATCH'
            self.report.update(status='MATCHED_FAILED_PREPARE',reason='MATCHED_PINNED_PREPARE',preservation_required=False)
        except KeyError:self.report.update(status='BLOCKED',reason='IDENTITY_MISMATCH',preservation_required=True)
        except TlsBlocked as error:self.report.update(status='BLOCKED',reason=str(error),preservation_required=True)
        except (OSError,ValueError,TypeError,IndexError,RecursionError):self.report.update(status='BLOCKED',reason='READ_OR_LIMIT_FAILED',preservation_required=True)
        return self.report


def audit_tls_residue(reference, run, capture=None):
    try:
        with deadline(45):
            state,loaded=run('tls_dependencies')
            if state!='ok' or not re.search(r'^Id=studio1925\.service$',loaded,re.M):raise OSError()
            state,paths=run('tls_unit_paths')
            if state!='ok' or not paths.split() or any(not any(p.startswith(r+'/') for r in TLS_UNIT_ROOTS) for p in paths.split()):raise OSError()
            inspector=TlsResidueInspector(reference,loaded=loaded)
            result=inspector.audit()
            state,after=run('tls_dependencies')
            if result['status']=='MATCHED_FAILED_PREPARE' and (state!='ok' or after!=loaded):
                result.update(status='BLOCKED',reason='SNAPSHOT_CHANGED',preservation_required=True)
            state,after_paths=run('tls_unit_paths')
            if result['status']=='MATCHED_FAILED_PREPARE' and (state!='ok' or after_paths!=paths):
                result.update(status='BLOCKED',reason='SNAPSHOT_CHANGED',preservation_required=True)
            if result['status']=='MATCHED_FAILED_PREPARE' and capture is not None:capture.append(inspector)
            return result
    except (TimeoutError,OSError):
        result=tls_empty_report();result['reason']='READ_OR_LIMIT_FAILED';return result
