"""Real local pipes only: no SSH, VPS, DNS, services or database operations."""
import contextlib
import fcntl
import hashlib
import io
import json
import os
import select
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_https as f

workflow=f.workflow
NONCE='f'*64
CANARY='SYNTHETIC_PASSWORD_PRIVATE_KEY_PERSONAL_DATA_NEVER_LOG'


class LocalPeer:
    password=CANARY
    def __init__(self,program):self.program=program
    def arguments(self,_command):return [sys.executable,'-I','-B','-S','-c',self.program]


@contextlib.contextmanager
def small_pipes():
    # Force the circular wait independently of the runner kernel's pipe sizes.
    original=subprocess.Popen
    def start(*args,**kwargs):
        child=original(*args,**kwargs)
        for pipe in (child.stdin,child.stdout):fcntl.fcntl(pipe,fcntl.F_SETPIPE_SZ,4096)
        return child
    with patch.object(workflow.subprocess,'Popen',side_effect=start):yield


def receiver(archive,before='',chunk=32768,delay=0,apply=False,after=''):
    code_digest=hashlib.sha256(workflow.source()).hexdigest()
    archive_digest=hashlib.sha256(archive).hexdigest()
    return f'''
import sys,json,time,hashlib
h=json.loads(sys.stdin.buffer.readline())
{before}
def exact(n):
    data=bytearray()
    while len(data)<n:
        block=sys.stdin.buffer.read(min({chunk},n-len(data)))
        if not block:raise SystemExit(12)
        data.extend(block)
        time.sleep({delay})
    return bytes(data)
assert hashlib.sha256(exact(h['code_size'])).hexdigest()=={code_digest!r}
assert hashlib.sha256(exact(h['archive_size'])).hexdigest()=={archive_digest!r}
if {apply!r}:
    for phase in ('ports-probe','certificate-ready','cutover-ready'):
        event={{'event':phase}}
        if phase!='ports-probe':event.update(fingerprint='b'*64,port=3000)
        print(json.dumps(event),flush=True)
        ack=json.loads(sys.stdin.buffer.readline())
        assert ack=={{'phase':phase,'nonce':{NONCE!r},'ok':True}}
    result={{'event':'result','status':'SUCCESS','operation':'https-enabled','changes':'studio-tls-only'}}
else:result={{'event':'result','status':'CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED','arch':'x64','changes':'none','firewall_plan':[]}}
print(json.dumps(result),flush=True)
{after}
'''


def assert_reaped(test,session):
    test.assertIsNotNone(session.child.poll())
    test.assertTrue(session.child.stdin.closed);test.assertTrue(session.child.stdout.closed)


def transfer_full_archive(archive):
    """Use the exact framing bootstrap and full real archive, but dummy control.

    It verifies every archive byte and the unchanged proof/ACK state machine,
    without executing installed code, Caddy, host admission or HTTPS apply.
    """
    digest=hashlib.sha256(archive).hexdigest();verified=[]
    dummy=f'''
import hashlib,json,sys
assert hashlib.sha256(archive).hexdigest()=={digest!r}
for phase in ('ports-probe','certificate-ready','cutover-ready'):
    event={{'event':phase}}
    if phase!='ports-probe':event.update(fingerprint='b'*64,port=3000)
    print(json.dumps(event),flush=True)
    ack=json.loads(sys.stdin.buffer.readline())
    assert ack=={{'phase':phase,'nonce':{NONCE!r},'ok':True}}
print(json.dumps({{'event':'result','status':'SUCCESS','operation':'https-enabled','changes':'studio-tls-only'}}),flush=True)
return 0
'''
    code=workflow.source()
    marker=b'from host import entry\n'
    if code.count(marker)!=1:raise AssertionError('LOCAL_ARCHIVE_CONTROL_MARKER_CHANGED')
    # Load the real bundled modules too, replacing only the host mutation entry.
    code=code.replace(marker,('def entry(options, archive, source):\n'+textwrap.indent(dummy,'    ')+'\n').encode())
    session=workflow.Session(LocalPeer(workflow.BOOTSTRAP),limit=10)
    with patch.object(workflow,'source',return_value=code),small_pipes(),contextlib.redirect_stdout(io.StringIO()):
        result=session.run({'mode':'apply','nonce':NONCE},archive,lambda phase,event:verified.append(phase))
    if result['status']!='SUCCESS' or verified!=['ports-probe','certificate-ready','cutover-ready'] or session.child.returncode!=0:
        raise AssertionError('LOCAL_ARCHIVE_TRANSFER_FAILED')
    return len(archive)


class TransportTests(unittest.TestCase):
    def test_old_write_reproduces_circular_wait_and_duplex_write_completes_same_peer(self):
        archive=b'public synthetic archive'*65536
        event=json.dumps({'event':'phase','phase':'MODULE_PROBE_STUDIO_NETWORK'})+'\n'
        self.assertGreater(len(event.encode())*75,4096)
        self.assertLess(len(event.encode())*75,8192)
        program=receiver(archive,before='sys.stdout.write('+repr(event*75)+');sys.stdout.flush()')
        class OldWrite(workflow.Session):
            def write(self,data,timeout=120):
                end=time.monotonic()+0.15;view=memoryview(data)
                while view:
                    f.checks.require(time.monotonic()<end,'SSH_INPUT_TIMEOUT')
                    if select.select([],[self.child.stdin],[],0.01)[1]:
                        try:view=view[os.write(self.child.stdin.fileno(),view[:65536]):]
                        except BlockingIOError:continue
        old=OldWrite(LocalPeer(program))
        with small_pipes(),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(f.checks.HttpsError,'SSH_INPUT_TIMEOUT'):
            old.run({'mode':'check','nonce':NONCE},archive)
        assert_reaped(self,old)
        phases=[];session=workflow.Session(LocalPeer(program),limit=10,diagnostics=phases)
        with small_pipes(),contextlib.redirect_stdout(io.StringIO()):result=session.run({'mode':'check','nonce':NONCE},archive)
        self.assertEqual(result['status'],'CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED');self.assertEqual(len(phases),75)
        assert_reaped(self,session)

    def test_large_payload_and_slow_channel_keep_fifo_integrity_and_all_proofs(self):
        archive=b'public bytes'*131072
        session=workflow.Session(LocalPeer(receiver(archive,chunk=8192,delay=0.0005,apply=True)),limit=10)
        verified=[]
        with small_pipes(),contextlib.redirect_stdout(io.StringIO()):
            result=session.run({'mode':'apply','nonce':NONCE},archive,lambda phase,event:verified.append(phase))
        self.assertEqual(result['status'],'SUCCESS');self.assertEqual(verified,['ports-probe','certificate-ready','cutover-ready'])
        assert_reaped(self,session)

    def test_partial_os_writes_do_not_truncate_code_archive_or_ack(self):
        archive=b'synthetic data'*4096;original=os.write
        session=workflow.Session(LocalPeer(receiver(archive,apply=True)),limit=10)
        with small_pipes(),patch.object(workflow.os,'write',side_effect=lambda fd,data:original(fd,data[:97])),contextlib.redirect_stdout(io.StringIO()):
            result=session.run({'mode':'apply','nonce':NONCE},archive,lambda *args:None)
        self.assertEqual(result['status'],'SUCCESS');assert_reaped(self,session)

    def test_absolute_upload_deadline_still_fails_and_reports_only_local_progress(self):
        class ShortDeadline(workflow.Session):
            def write(self,data,timeout=120):return super().write(data,timeout=0.1)
        session=ShortDeadline(LocalPeer('import sys,time;sys.stdin.buffer.readline();time.sleep(0.3);sys.stdin.buffer.read()'))
        with small_pipes(),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(f.checks.HttpsError,'SSH_INPUT_TIMEOUT') as error:
            session.run({'mode':'check','nonce':NONCE},b'x'*1024**2)
        sent,total,elapsed,buffered=error.exception.upload
        self.assertGreater(sent,0);self.assertLess(sent,total);self.assertGreaterEqual(elapsed,0);self.assertEqual(buffered,0)
        assert_reaped(self,session)

    def test_premature_close_never_announces_success_or_repeats_apply(self):
        for code,expected in ((0,'SSH_CLOSED_OUTCOME_UNKNOWN'),(5,'SSH_AUTH_FAILED'),(255,'SSH_CONNECTION_FAILED')):
            session=workflow.Session(LocalPeer(f'import sys;sys.stdin.buffer.readline();sys.stdin.buffer.read(8);sys.exit({code})'))
            verified=[]
            with small_pipes(),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(f.checks.HttpsError,expected):
                session.run({'mode':'apply','nonce':NONCE},b'x'*1024**2,lambda *args:verified.append(args))
            self.assertEqual(verified,[]);assert_reaped(self,session)

    def test_disconnect_after_proof_before_result_keeps_unknown_outcome(self):
        program="import sys,json;h=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read(h['code_size']+h['archive_size']);print(json.dumps({'event':'ports-probe'}),flush=True)"
        session=workflow.Session(LocalPeer(program));verified=[]
        with small_pipes(),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(f.checks.HttpsError,'SSH_CLOSED_OUTCOME_UNKNOWN'):
            session.run({'mode':'apply','nonce':NONCE},b'public artifact',lambda phase,event:verified.append(phase))
        self.assertEqual(verified,['ports-probe']);assert_reaped(self,session)

    def test_oversized_early_stdout_is_rejected_and_cleanup_drains_without_leaks(self):
        # More than a pipe can hold, then exit; don't strand the peer during EOF.
        program='import sys;sys.stdin.buffer.readline();sys.stdout.write('+repr(CANARY)+'*4096);sys.stdout.flush()'
        session=workflow.Session(LocalPeer(program))
        with small_pipes(),contextlib.redirect_stdout(io.StringIO()) as log,self.assertRaisesRegex(f.checks.HttpsError,'INVALID_REMOTE_PROTOCOL'):
            session.run({'mode':'apply','nonce':NONCE},b'x'*1024**2)
        self.assertNotIn(CANARY,log.getvalue());assert_reaped(self,session)

    def test_cleanup_after_final_result_does_not_wait_on_full_stdout_pipe(self):
        archive=b'x'*32768
        session=workflow.Session(LocalPeer(receiver(archive,after='sys.stdout.write("x"*131072);sys.stdout.flush()')))
        started=time.monotonic()
        with small_pipes(),contextlib.redirect_stdout(io.StringIO()):result=session.run({'mode':'check','nonce':NONCE},archive)
        self.assertEqual(result['status'],'CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED');self.assertLess(time.monotonic()-started,10)
        assert_reaped(self,session)

    def test_exact_bootstrap_accepts_large_archive_with_original_time_limits(self):
        self.assertEqual(transfer_full_archive(b'public artifact'*524288),len(b'public artifact'*524288))

    def test_native_archive_transfer_is_mandatory_before_package_publication(self):
        text=(f.ROOT/'.github/workflows/installer-package.yml').read_text()
        start=text.index('- name: Require pinned Caddy validation')
        end=text.index('- name: Browser CA tooling')
        self.assertIn('python3 -B tests/https/full_archive_transport.py --archive',text[start:end])
        self.assertNotIn('continue-on-error',text[start:end]);self.assertNotIn('if:',text[start:end])
        self.assertLess(end,text.index('- name: Publish only the verified immutable package'))

    def test_timeout_summary_contains_only_bounded_local_progress_not_remote_contents(self):
        from test_check_phases import options
        with tempfile.TemporaryDirectory() as folder:
            event=Path(folder)/'event.json';summary=Path(folder)/'summary'
            event.write_text(json.dumps({'inputs':options()}))
            error=f.checks.HttpsError('SSH_INPUT_TIMEOUT');error.upload=(4096,18000000,120,97)
            with patch.dict(os.environ,{'GITHUB_EVENT_PATH':str(event),'GITHUB_STEP_SUMMARY':str(summary),'STUDIO_SSH_PASSWORD':CANARY}),patch.object(workflow,'verified_main'),patch.object(workflow,'dns_records'),patch.object(workflow.Session,'run',side_effect=error),contextlib.redirect_stdout(io.StringIO()) as log:
                self.assertEqual(workflow.main(),1)
            text=summary.read_text()
            self.assertIn('4096/18000000',text);self.assertIn('elapsed_seconds=120',text)
            self.assertIn('buffered_stdout_bytes=97',text);self.assertIn('does not prove remote receipt',text)
            self.assertNotIn(CANARY,text+log.getvalue());self.assertNotIn(f.IP,text);self.assertNotIn(f.DOMAIN,text)


if __name__=='__main__':unittest.main()
