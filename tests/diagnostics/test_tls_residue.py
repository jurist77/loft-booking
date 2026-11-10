"""Real temporary filesystem fixtures only. No host scan, SSH or real users."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/diagnostics'))
import probe_tls_residue as probe
import https_readiness as runner
from test_https_readiness import fixture, EXTERNAL, IP, CANARY


class ResidueTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.ref=json.loads((ROOT/'scripts/diagnostics/https-residue-reference.json').read_text())
        self.ref['window']=[int(time.time())-20,int(time.time())+20]
        self.base,self.etc,self.data=(self.root/p.lstrip('/') for p in probe.TLS_ROOTS)
        self.release=self.base/'releases'/self.ref['release']['archives']['x64']['sha256']
        for path in (self.release,self.etc,self.data,self.root/'proc/self'):
            path.mkdir(parents=True,exist_ok=True)
        for path in (self.base,self.etc,self.data,self.base/'releases',self.release):path.chmod(0o700)
        for path,value,mode in ((self.base/'control.py',b'fixture reviewed controller',0o644),
                (self.release/'caddy',b'fixture ELF binary',0o755),(self.release/'LICENSE',b'fixture license',0o644),
                (self.etc/'caddy.json',json.dumps(self.ref['config_template']).encode(),0o640)):
            path.write_bytes(value);path.chmod(mode)
            if path.name=='control.py':self.ref['control_sha256']=hashlib.sha256(value).hexdigest()
            elif path.name!='caddy.json':self.ref['files']['x64'][path.name]=hashlib.sha256(value).hexdigest()
        (self.root/'proc/self/mountinfo').write_text('1 0 8:1 / / rw - ext4 /dev/synthetic rw\n')
        account=SimpleNamespace(pw_name=probe.TLS_USER,pw_uid=888,pw_gid=889,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
        group=SimpleNamespace(gr_name=probe.TLS_USER,gr_gid=889,gr_mem=[])
        self.audit=probe.TlsResidueInspector(self.ref,self.root,lambda _:account,lambda:[group])
        self.audit.root_uid=os.getuid()
        original=self.audit.info
        def info(name):
            st=original(name)
            attrs={k:getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
            if name==probe.TLS_ROOTS[2]:attrs.update(st_uid=888,st_gid=889)
            elif name==probe.TLS_ROOTS[1] or name==probe.TLS_ROOTS[1]+'/caddy.json':attrs['st_gid']=889
            return SimpleNamespace(**attrs)
        self.audit.info=info

    def assertBlocked(self,reason=None):
        value=self.audit.audit()
        self.assertEqual(value['status'],'BLOCKED',value)
        self.assertTrue(value['preservation_required'])
        if reason:self.assertEqual(value['reason'],reason,value)
        raw=json.dumps(value)
        for secret in (CANARY,str(self.root),'control.py','caddy.json','888','889'):
            self.assertNotIn(secret,raw)
        return value

    def test_exact_fixture_requires_all_independent_evidence_and_is_read_only(self):
        before={str(p):(p.lstat().st_mode,p.lstat().st_mtime_ns,p.lstat().st_ctime_ns,p.lstat().st_atime_ns)
            for p in (self.base,self.data,self.etc,self.base/'control.py',self.etc/'caddy.json')}
        value=self.audit.audit()
        self.assertEqual(value['status'],'MATCHED_FAILED_PREPARE',value)
        self.assertTrue(all(v=='MATCH' for v in value['checks'].values()))
        self.assertEqual(value['objects']['data']['owner'],'tls')
        after={str(p):(p.lstat().st_mode,p.lstat().st_mtime_ns,p.lstat().st_ctime_ns,p.lstat().st_atime_ns)
            for p in (self.base,self.data,self.etc,self.base/'control.py',self.etc/'caddy.json')}
        self.assertEqual(before,after)
        response=fixture(residue=lambda:value);runner.validate(response)

    def test_unknown_file_does_not_get_opened_or_logged(self):
        path=self.base/CANARY;path.write_text(CANARY)
        with patch.object(self.audit,'read',wraps=self.audit.read) as opened:
            self.assertBlocked('UNEXPECTED_OBJECT')
            self.assertNotIn(str(path),str(opened.call_args_list))

    def test_keys_certificates_or_any_data_are_preserved_without_reading(self):
        (self.data/'private-key.pem').write_text(CANARY)
        with patch.object(self.audit,'read',side_effect=AssertionError('must not read any file yet')):
            self.assertBlocked('STATE_REQUIRES_PRESERVATION')

    def test_managed_or_pending_checkpoint_blocks_even_if_empty(self):
        for name in ('managed.json','transaction.json'):
            with self.subTest(name=name):
                p=self.base/name;p.write_text(CANARY)
                self.assertBlocked('STATE_REQUIRES_PRESERVATION');p.unlink()

    def test_symlink_hardlink_wrong_permissions_and_owner_are_blocked(self):
        file=self.base/'control.py';original=file.read_bytes()
        file.unlink();file.symlink_to(self.root/'outside')
        self.assertBlocked('METADATA_MISMATCH');file.unlink();file.write_bytes(original);file.chmod(0o644)
        os.link(file,self.root/'foreign-hardlink');self.assertBlocked('METADATA_MISMATCH')
        (self.root/'foreign-hardlink').unlink();file.chmod(0o666);self.assertBlocked('METADATA_MISMATCH')
        file.chmod(0o644);self.base.chmod(0o755);self.assertBlocked('METADATA_MISMATCH')

    def test_modified_binary_license_control_and_json_block(self):
        for path in (self.release/'caddy',self.release/'LICENSE',self.base/'control.py',self.etc/'caddy.json'):
            with self.subTest(file=path.name):
                prior=path.read_bytes();path.write_bytes(b'{}' if path.name=='caddy.json' else CANARY.encode())
                self.assertBlocked();path.write_bytes(prior)

    def test_duplicate_json_keys_are_not_normalized_into_a_match(self):
        path=self.etc/'caddy.json'
        data=path.read_text();path.write_text('{"admin":{},'+data[1:])
        self.assertBlocked('FINGERPRINT_MISMATCH')

    def test_identity_missing_root_alias_login_home_extra_group_blocks(self):
        account=self.audit.account('ignored')
        for field,value in (('pw_uid',0),('pw_shell','/bin/bash'),('pw_dir','/home/user')):
            previous=getattr(account,field);setattr(account,field,value)
            self.assertBlocked('IDENTITY_MISMATCH');setattr(account,field,previous)
        group=self.audit.groups()[0];group.gr_mem.append(CANARY)
        self.assertBlocked('IDENTITY_MISMATCH');group.gr_mem.clear()
        self.audit.account=lambda _:(_ for _ in ()).throw(KeyError())
        self.assertBlocked('IDENTITY_MISMATCH')

    def test_external_symlink_and_unit_reference_block_without_output(self):
        link=self.root/'foreign-link';link.symlink_to(probe.TLS_ROOTS[0]+'/control.py')
        self.assertBlocked('DEPENDENCY_FOUND');link.unlink()
        unit=self.root/'etc/systemd/system/foreign.service';unit.parent.mkdir(parents=True)
        for reference in (probe.TLS_USER,probe.TLS_ROOTS[0], 'User=888'):
            unit.write_text('[Service]\n'+reference+'\n'+CANARY)
            self.assertBlocked('DEPENDENCY_FOUND')

    def test_in_memory_unit_and_inactive_alias_are_dependencies(self):
        self.audit.loaded='User='+probe.TLS_USER+'\n'+CANARY
        self.assertBlocked('DEPENDENCY_FOUND');self.audit.loaded=''
        unit=self.root/'run/systemd/system'/probe.TLS_UNIT_NAMES[0];unit.parent.mkdir(parents=True)
        unit.symlink_to('/dev/null');self.assertBlocked('DEPENDENCY_FOUND')

    def test_mountpoint_or_bind_alias_blocks_without_reading_tls_data(self):
        for field in (3,4):
            fields='1 0 8:1 / / rw - ext4 /dev/synthetic rw'.split();fields[field]=probe.TLS_ROOTS[0]
            (self.root/'proc/self/mountinfo').write_text(' '.join(fields)+'\n')
            self.assertBlocked('DEPENDENCY_FOUND')

    def test_process_uid_or_open_reference_blocks(self):
        proc=self.root/'proc/123';proc.mkdir()
        (proc/'status').write_text('Uid:\t888\t888\t888\t888\nGid:\t889\t889\t889\t889\nGroups:\t889\n')
        self.assertBlocked('DEPENDENCY_FOUND')
        (proc/'status').write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\n')
        (proc/'mountinfo').write_text((self.root/'proc/self/mountinfo').read_text())
        (proc/'maps').write_text('')
        (proc/'fd').mkdir();(proc/'fd/5').symlink_to(probe.TLS_ROOTS[0]+'/control.py')
        self.assertBlocked('DEPENDENCY_FOUND')

    def test_supplementary_group_foreign_ownership_and_xattrs_block(self):
        proc=self.root/'proc/234';proc.mkdir()
        (proc/'status').write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0 889\n')
        self.assertBlocked('DEPENDENCY_FOUND')
        (proc/'status').unlink();proc.rmdir()
        foreign=self.root/'foreign';foreign.touch()
        original=Path.lstat
        def metadata(path,*a,**kw):
            st=original(path,*a,**kw)
            if path==foreign:return SimpleNamespace(st_uid=888,st_gid=0)
            return st
        with patch.object(Path,'lstat',metadata):self.assertBlocked('DEPENDENCY_FOUND')
        with patch.object(probe.os,'listxattr',return_value=['system.posix_acl_access']):self.assertBlocked('METADATA_MISMATCH')

    def test_failed_dependency_query_and_timeout_block_without_raw_error(self):
        result=probe.audit_tls_residue(self.ref,lambda name:('error',CANARY))
        self.assertEqual(result['status'],'BLOCKED')
        self.assertNotIn(CANARY,json.dumps(result))
        with patch.object(probe,'deadline',side_effect=TimeoutError(CANARY)):
            self.assertEqual(probe.audit_tls_residue(self.ref,lambda name:('ok',''))['status'],'BLOCKED')

    def test_dependency_snapshot_changes_and_healthy_studio_gate(self):
        matched=self.audit.audit();self.assertEqual(matched['status'],'MATCHED_FAILED_PREPARE')
        from unittest.mock import Mock
        with patch.object(probe,'TlsResidueInspector') as inspector:
            inspector.return_value.audit.return_value=copy.deepcopy(matched)
            run=Mock(side_effect=[('ok','Id=studio1925.service\n'),('ok','Id=studio1925.service\nchanged')])
            result=probe.audit_tls_residue(self.ref,run)
            self.assertEqual(result['reason'],'SNAPSHOT_CHANGED')
        response=fixture(residue=lambda:matched)
        response['studio']['local_health'].update(http=503,ok=False,error='unexpected_response')
        ssh=Mock();ssh.execute.return_value=response
        result=runner.diagnose(IP,CANARY,lambda *a:ssh,lambda *a:EXTERNAL)
        self.assertEqual(result['remote']['tls_residue']['reason'],'STUDIO_NOT_HEALTHY')

    def test_permission_denial_timeout_incomplete_scan_and_races_are_not_matches(self):
        with patch.object(self.audit,'dependencies',side_effect=PermissionError(CANARY)):
            self.assertBlocked('READ_OR_LIMIT_FAILED')
        previous=self.audit.dependencies
        def mutate():
            previous();(self.base/'control.py').write_text(CANARY)
        self.audit.dependencies=mutate
        self.assertBlocked('SNAPSHOT_CHANGED')

    def test_timestamp_outside_recorded_apply_window_blocks(self):
        self.ref['window']=[1,2];self.assertBlocked('METADATA_MISMATCH')

    def test_false_positive_remote_status_and_error_text_are_rejected(self):
        data=fixture();data['tls_residue'].update(status='MATCHED_FAILED_PREPARE',reason='MATCHED_PINNED_PREPARE',preservation_required=False)
        from unittest.mock import Mock
        ssh=Mock();ssh.execute.return_value=data
        result=runner.diagnose(IP,CANARY,lambda *a:ssh,lambda *a:EXTERNAL)
        self.assertEqual(result['ssh'],'REMOTE_PROTOCOL_FAILED')
        data=fixture();data['tls_residue']['reason']=CANARY
        ssh.execute.return_value=data
        self.assertEqual(runner.diagnose(IP,CANARY,lambda *a:ssh,lambda *a:EXTERNAL)['ssh'],'REMOTE_PROTOCOL_FAILED')


if __name__=='__main__':unittest.main()
