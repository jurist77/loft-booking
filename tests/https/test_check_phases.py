"""Exact bootstrap/PIPE and full admission logic; injected read primitives only.

No SSH, public HTTP, database, services or firewall changes. Synthetic fixtures.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_https as f
from phase_report import REMOTE_PHASES, ERROR_KINDS, report

CANARY = 'SYNTHETIC_PASSWORD_PRIVATE_KEY_PERSONAL_DATA_NEVER_LOG'
# This source is inserted in a disposable child immediately before entry, after
# all real bundled modules load. No change to framing/bootstrap/entry/parsers.
FIXTURE = r'''
import contextlib,types,tempfile
from unittest.mock import patch,Mock
from pathlib import Path
import host,inventory
I=host.I
_stack=contextlib.ExitStack()
_tmp=_stack.enter_context(tempfile.TemporaryDirectory(prefix="studio-readonly-check-"))
def p(target,name,value):_stack.enter_context(patch.object(target,name,value))
p(host,'TRANSACTION',Path(_tmp)/'transaction.json')
state={'current':'a'*40+'-'+'b'*16+'-'+'c'*8,'phase':'ready','port':3000,'origin':'http://192.0.2.10:3000'}
unit='LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nFragmentPath='+str(I.UNIT)+'\nDropInPaths=\n'
row='LISTEN 0 511 [::]:3000 [::]:* users:(("node",pid=123,fd=20)) ino:456 sk:abc v6only:0\n'
data={'service':unit,'sockets4':'','sockets6':row,'web4':'','web6':'','interfaces':'[{"addr_info":[{"local":"8.8.8.8"}]}]',
      'ufw':'Status: inactive\n','nft':'{"nftables":[]}', 'ip4':'', 'ip6':'', 'legacy4':'', 'legacy6':''}
def fail(*args,**kwargs):raise TypeError('SYNTHETIC_PASSWORD_PRIVATE_KEY_PERSONAL_DATA_NEVER_LOG')
def forbidden(*args,**kwargs):raise AssertionError('UNEXPECTED_MUTATION')
def read(name,port):
    if fault=='READ_'+name.upper():fail()
    return 'ok',data[name]
def acme():
    if fault=='CHECK_ACME':fail()
p(I,'load_state',fail if fault=='CHECK_STATE' else lambda:state)
p(host,'owned',fail if fault=='CHECK_TLS_OWNER' else lambda:None)
p(I,'host_facts',lambda:{'arch':'x64'})
p(I,'managed_account',lambda value:types.SimpleNamespace(pw_uid=1001,pw_gid=1001))
p(I,'owned_directory',lambda *a,**kw:None)
p(I.shutil,'which',lambda *a,**kw:'/usr/bin/fixture')
p(I.shutil,'disk_usage',lambda *a:types.SimpleNamespace(free=1024**3))
p(I,'private_environment',lambda:I.environment_text(3000,state['origin']))
p(I,'health',fail if fault=='CHECK_HEALTH' else lambda *a,**kw:None)
p(I,'api_health',fail if fault=='CHECK_API' else lambda *a,**kw:None)
p(I,'Path',lambda path:types.SimpleNamespace(read_text=lambda:'MemAvailable: 1048576 kB\n') if str(path)=='/proc/meminfo' else Path(path))
p(host.os,'geteuid',lambda:0)
p(host.os,'umask',lambda value:0)
p(host.signal,'signal',lambda *a:None)
p(inventory.own_listeners,'__defaults__',(lambda path:'socket:[456]',))
_original=inventory.snapshot
p(host,'snapshot',lambda *a,**kw:_original(*a,**kw,run=read,outbound=acme))
for name in ('atomic_write','store_state','run','install_lock'):p(I,name,forbidden)
if fault=='CHECK_LISTENER':data['sockets6']='LISTEN 0 511 [::]:3000 [::]:* users:(("node",pid=123,fd=20))\n'
if fault=='CHECK_FIREWALL':data['nft']='{"nftables":[{"rule":{}}]}'
'''


def options():
    return {'server_ip':'8.8.8.8','additional_ip':'','hostname':'fixture.dynv6.net','mode':'check','confirmation':'','nonce':'f'*64}


class FullCheckTests(unittest.TestCase):
    def bootstrap(self, fault='', code=None):
        source = f.workflow.source() if code is None else code
        fixture = 'fault='+repr(fault)+'\n'+FIXTURE+'\n'
        source = source.replace(b'from host import entry\n',fixture.encode()+b'from host import entry\n')
        packet = json.dumps({'code_size':len(source),'archive_size':0,'options':options()}).encode()+b'\n'+source
        result = subprocess.run([sys.executable,'-I','-B','-S','-c',f.workflow.BOOTSTRAP],input=packet,capture_output=True,timeout=10)
        self.assertEqual(result.stderr,b'')
        self.assertNotIn(CANARY.encode(),result.stdout)
        events=[json.loads(line) for line in result.stdout.splitlines()]
        for event in events:
            if event['event']=='phase':self.assertIn(event['phase'],REMOTE_PHASES)
        return result,events

    def test_exact_bootstrap_and_unmocked_full_admission_passes_without_mutations(self):
        result,events=self.bootstrap()
        self.assertEqual(result.returncode,0)
        self.assertEqual(events[-1]['status'],'CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED')
        phases=[e['phase'] for e in events if e['event']=='phase']
        self.assertIn('CHECK_FIREWALL',phases);self.assertIn('CHECK_LISTENER',phases)
        self.assertIn('CHECK_API',phases);self.assertEqual(phases[-1],'CHECK_COMPLETE')

    def test_unhandled_exceptions_identify_exact_phase_and_kind_without_raw_message(self):
        for phase in ('CHECK_STATE','CHECK_TLS_OWNER','READ_SERVICE','READ_UFW','READ_NFT','READ_INTERFACES','CHECK_HEALTH','CHECK_API','CHECK_ACME'):
            with self.subTest(phase=phase):
                result,events=self.bootstrap(phase)
                self.assertEqual(result.returncode,1)
                self.assertEqual(events[-1],{'event':'result','status':'FAILED','code':'HTTPS_OPERATION_FAILED','phase':phase,'error_kind':'TYPE_ERROR'})
                self.assertNotIn('CHECK_COMPLETE',[e.get('phase') for e in events])

    def test_listener_parser_rejection_is_named_and_does_not_skip_safety_checks(self):
        result,events=self.bootstrap('CHECK_LISTENER')
        self.assertEqual(result.returncode,1)
        self.assertEqual(events[-1]['code'],'LISTENER_METADATA_UNCONFIRMED')
        self.assertEqual(events[-1]['phase'],'CHECK_LISTENER')
        self.assertEqual(events[-1]['error_kind'],'EXPECTED')
        self.assertNotIn('CHECK_HEALTH',[e.get('phase') for e in events])

    def test_firewall_rejection_remains_a_failure(self):
        result,events=self.bootstrap('CHECK_FIREWALL')
        self.assertEqual(result.returncode,1);self.assertEqual(events[-1]['code'],'ADDITIONAL_FIREWALL_RULES')
        self.assertEqual(events[-1]['phase'],'CHECK_FIREWALL')

    def test_bootstrap_failure_is_named_without_stderr_or_exception_message(self):
        result,events=self.bootstrap(code=b"raise RuntimeError('SYNTHETIC_PASSWORD_PRIVATE_KEY_PERSONAL_DATA_NEVER_LOG')")
        self.assertEqual(result.returncode,1)
        self.assertEqual(events[-1],{'event':'result','status':'FAILED','code':'HTTPS_BOOTSTRAP_FAILED','phase':'BOOTSTRAP_EXEC','error_kind':'OTHER'})
        self.assertIn(events[-1]['code'],f.workflow.SAFE_REMOTE_CODES)

    def test_real_session_pipe_preserves_failure_phase_and_reaps_child(self):
        original=f.workflow.source()
        class SSH:
            password=CANARY
            def arguments(self,command):return [sys.executable,'-I','-B','-S','-c',f.workflow.BOOTSTRAP]
        source=original.replace(b'from host import entry\n',('fault="CHECK_API"\n'+FIXTURE+'\n').encode()+b'from host import entry\n')
        rows=[];session=f.workflow.Session(SSH(),diagnostics=rows)
        with patch.object(f.workflow,'source',return_value=source),contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(f.checks.HttpsError) as captured:session.run(options())
        self.assertEqual(captured.exception.phase,'CHECK_API');self.assertEqual(captured.exception.error_kind,'TYPE_ERROR')
        self.assertEqual(rows[-1],('REMOTE','CHECK_API'))
        self.assertNotIn(CANARY,output.getvalue()+report(rows))
        self.assertIsNotNone(session.child.poll());self.assertTrue(session.child.stdin.closed);self.assertTrue(session.child.stdout.closed)

    def test_summary_reports_only_fixed_phase_kind_and_known_error_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            event=Path(tmp)/'event.json';summary=Path(tmp)/'summary.md'
            event.write_text(json.dumps({'inputs':options()}))
            for phase,kind,code in [('CHECK_API','TYPE_ERROR','HTTPS_OPERATION_FAILED'),('CHECK_LISTENER','EXPECTED','LISTENER_METADATA_UNCONFIRMED')]:
                error=f.checks.HttpsError(code);error.phase=phase;error.error_kind=kind
                with patch.dict(os.environ,{'GITHUB_EVENT_PATH':str(event),'GITHUB_STEP_SUMMARY':str(summary),'STUDIO_SSH_PASSWORD':CANARY}), \
                        patch.object(f.workflow,'verified_main'),patch.object(f.workflow,'dns_records'),patch.object(f.workflow.Session,'run',side_effect=error),contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(f.workflow.main(),1)
                text=summary.read_text()+output.getvalue()
                self.assertIn(phase,text);self.assertIn(kind,text);self.assertNotIn(CANARY,text)
                self.assertNotIn('8.8.8.8',summary.read_text());self.assertNotIn('fixture.dynv6.net',summary.read_text())
            self.assertEqual(f.workflow.safe_code(CANARY),'HTTPS_WORKFLOW_FAILED')
            self.assertEqual(f.workflow.safe_code('DNS_GOOGLE_HOST_CAA_SERVFAIL'),'DNS_GOOGLE_HOST_CAA_SERVFAIL')
            self.assertEqual(f.workflow.safe_code('DNS_GOOGLE_HOST_CAA_'+CANARY),'HTTPS_WORKFLOW_FAILED')

    def test_malicious_phase_and_error_kind_are_rejected(self):
        for event in ({'event':'phase','phase':CANARY},
                      {'event':'result','status':'FAILED','code':'HTTPS_OPERATION_FAILED','phase':'CHECK_API','error_kind':CANARY},
                      {'event':'phase','phase':'CHECK_COMPLETE','raw':CANARY}):
            body='import sys,json;h=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read(h["code_size"]);print('+repr(json.dumps(event))+',flush=True)'
            class SSH:
                password=CANARY
                def arguments(self,command):return [sys.executable,'-c',body]
            with contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaisesRegex(f.checks.HttpsError,'INVALID_REMOTE_PROTOCOL'):
                f.workflow.Session(SSH()).run(options())
            self.assertNotIn(CANARY,output.getvalue())


    def test_diagnostic_phase_cannot_authorize_apply_or_flood_protocol(self):
        for count,mode,tail,expected in (
            (81,'check',[], 'INVALID_REMOTE_PROTOCOL'),
            (1,'apply',[{'event':'result','status':'SUCCESS','operation':'https-enabled','changes':'studio-tls-only'}], 'EXTERNAL_PROOF_SEQUENCE_REQUIRED')):
            events=[{'event':'phase','phase':'BOOTSTRAP_EXEC'}]*count+tail
            body='import sys,json;h=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read(h["code_size"]);' + ''.join('print('+repr(json.dumps(event))+',flush=True);' for event in events)
            class SSH:
                password=CANARY
                def arguments(self,command):return [sys.executable,'-c',body]
            with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(f.checks.HttpsError,expected):
                f.workflow.Session(SSH()).run({**options(),'mode':mode})


if __name__=='__main__':unittest.main()
