"""No real SSH, Telegram, GitHub deployment or VPS calls. Isolated operator fixtures."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[2]
FOLDER=ROOT/'scripts/telegram-management'
spec=importlib.util.spec_from_file_location('telegram_technical_workflow',FOLDER/'workflow.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
hspec=importlib.util.spec_from_file_location('telegram_technical_host',FOLDER/'host.py')
h=importlib.util.module_from_spec(hspec);hspec.loader.exec_module(h)
SECRET='SYNTHETIC_SECRET_TOKEN_AND_PERSONAL_DATA_NEVER_PRINT'
FP={'bot':'a'*64,'instance':'b'*64,'token':'c'*64}
def status(fp=FP):
    return {'status':'OK',**fp,'configured':True,'instanceBound':True,'botRegistered':True,'ownerReady':False,
        'workerLive':True,'workerState':'RUNNING','enabled':False,'subscribers':0,'pendingRequests':0,'queued':0,'failed':0}

class Registry:
    def __init__(self,record=None):self.record=record;self.reserved=0;self.completed=[]
    def latest(self):return self.record
    def reserve(self,sha,fp):
        self.reserved+=1;self.record={'id':self.reserved,'fingerprints':fp,'active':False};return self.reserved
    def success(self,id):self.completed.append(id);self.record['active']=True
class Peer:
    def __init__(self,planned=FP,live=True):self.planned=planned;self.live=live;self.calls=[];self.after_write_failure=False
    def call(self,payload):
        self.calls.append(payload['operation'])
        if payload['operation']=='plan':return {**status(self.planned),'planned':self.planned,'configured':False,'workerLive':False}
        if payload['operation']=='configure' and self.after_write_failure:raise w.Failure('SSH_RESULT_UNKNOWN')
        return {**status(self.planned),'workerLive':self.live,'ownerReady':payload['operation']=='bootstrap'}

class ManagementTests(unittest.TestCase):
    def test_first_config_then_repeat_keeps_registration_and_has_no_reset_or_install(self):
        peer=Peer();r=Registry();result=w.operate(peer,r,'a'*40,'configure',SECRET)
        self.assertTrue(result['workerLive']);self.assertEqual(r.completed,[1]);self.assertEqual(peer.calls,['plan','configure','diagnose'])
        peer.call=lambda payload:{**status(),'planned':FP} if payload['operation']=='plan' else status()
        w.operate(peer,r,'a'*40,'configure',SECRET);self.assertEqual(r.reserved,1)
    def test_other_bot_other_host_same_token_and_unconfirmed_write_block(self):
        r={'id':1,'fingerprints':FP,'active':True}
        for fp,operation in (({**FP,'bot':'d'*64},'rotate-token'),({**FP,'instance':'d'*64},'configure'),
            ({**FP,'instance':'d'*64},'rotate-token'),({**FP,'token':'d'*64},'configure')):
            with self.assertRaises(w.Failure):w.permitted(r,fp,operation)
        with self.assertRaisesRegex(w.Failure,'PREVIOUS_CONFIGURATION_OUTCOME_UNKNOWN'):
            w.permitted({**r,'active':False},{**FP,'instance':'d'*64,'token':'e'*64},'rotate-token')
        w.permitted(r,{**FP,'instance':'d'*64,'token':'e'*64},'rotate-token')
    def test_failed_token_plan_leaves_old_registration_and_never_writes_config(self):
        peer=Peer();peer.call=Mock(side_effect=w.Failure('AUTH_INVALID'));r=Registry({'id':1,'fingerprints':FP,'active':True})
        with self.assertRaisesRegex(w.Failure,'AUTH_INVALID'):w.operate(peer,r,'a'*40,'rotate-token',SECRET)
        self.assertEqual(r.reserved,0);self.assertEqual(peer.call.call_args.args[0]['operation'],'plan')
    def test_ssh_loss_after_write_is_unknown_and_same_target_diagnose_can_complete_registry(self):
        peer=Peer();peer.after_write_failure=True;r=Registry()
        with self.assertRaisesRegex(w.Failure,'SSH_RESULT_UNKNOWN'):w.operate(peer,r,'a'*40,'configure',SECRET)
        self.assertFalse(r.record['active']);self.assertEqual(r.completed,[])
        peer.after_write_failure=False
        observed=w.operate(peer,r,'a'*40,'diagnose');self.assertTrue(observed['registryAligned']);self.assertEqual(r.completed,[1])
    def test_unhealthy_worker_or_wrong_actual_state_never_reports_config_success(self):
        peer=Peer(live=False);r=Registry();ticks=iter((0,0,2))
        with self.assertRaisesRegex(w.Failure,'WORKER_NOT_READY_CONFIGURATION_PRESERVED'):
            w.operate(peer,r,'a'*40,'configure',SECRET,clock=lambda:next(ticks)*120,pause=lambda _:None)
        self.assertFalse(r.record['active'])
        r=Registry({'id':1,'fingerprints':FP,'active':True})
        observed=w.operate(Peer({**FP,'instance':'d'*64}),r,'a'*40,'diagnose')
        self.assertFalse(observed['registryAligned'])
    def test_bootstrap_requires_active_matching_instance_and_uses_secret_only_in_payload(self):
        for record in (None,{'id':1,'fingerprints':FP,'active':False},{'id':1,'fingerprints':{**FP,'token':'d'*64},'active':True}):
            with self.assertRaisesRegex(w.Failure,'TELEGRAM_NOT_READY'):w.operate(Peer(),Registry(record),'a'*40,'bootstrap-owner',confirmation=SECRET)
        peer=Peer();r=Registry({'id':1,'fingerprints':FP,'active':True})
        self.assertTrue(w.operate(peer,r,'a'*40,'bootstrap-owner',confirmation=SECRET)['ownerReady'])
    def test_registry_failure_never_claims_success_or_resets_recipients(self):
        for stage in ('latest','reserve','success'):
            r=Registry();setattr(r,stage,Mock(side_effect=w.Failure('GITHUB_STATE_UNAVAILABLE')));peer=Peer()
            with self.assertRaisesRegex(w.Failure,'GITHUB_STATE_UNAVAILABLE'):w.operate(peer,r,'a'*40,'configure',SECRET)
            if stage in ('latest','reserve'):self.assertNotIn('configure',peer.calls)
    def test_private_pipe_transport_keeps_tokens_out_of_argv_env_and_reaps_failures(self):
        child=Mock();child.communicate.return_value=(json.dumps(status()).encode(),None);child.returncode=0;child.poll.return_value=0
        with patch.object(w.subprocess,'Popen',return_value=child) as popen:
            result=w.Peer('192.0.2.10','fake-password').call({'operation':'configure','token':SECRET,'expected':FP})
            self.assertTrue(result['workerLive']);self.assertNotIn(SECRET,str(popen.call_args))
            packet=child.communicate.call_args.args[0];self.assertIn(SECRET.encode(),packet)
            args=popen.call_args.args[0];self.assertIn('StrictHostKeyChecking=no',args)
            self.assertIn('root@192.0.2.10',args);self.assertIn('22',args)
            child.communicate.side_effect=subprocess.TimeoutExpired('synthetic',100);child.poll.return_value=None
            with patch.object(w.os,'killpg') as kill:
                with self.assertRaisesRegex(w.Failure,'SSH_RESULT_UNKNOWN'):w.Peer('192.0.2.10','fake-password').call({'operation':'diagnose'})
                kill.assert_called_once();child.wait.assert_called()
            child.stdout.close.assert_called();child.stdin.close.assert_called()
    def test_unknown_response_fields_digests_and_status_never_escape_schema(self):
        for change in (lambda v:v.update(token=SECRET),lambda v:v.update(name=SECRET),lambda v:v.update(workerState=SECRET),lambda v:v.update(subscribers=-1)):
            value=status();change(value)
            with self.assertRaises(w.Failure):w.validate(value)
    def test_safe_actions_summary_contains_no_token_claim_personal_data_or_fingerprints(self):
        with tempfile.TemporaryDirectory() as folder:
            event=Path(folder)/'event';summary=Path(folder)/'summary'
            event.write_text(json.dumps({'inputs':{'server_ip':'192.0.2.10','operation':'configure','confirmation':w.CONFIRM['configure']}}))
            env={'GITHUB_REF':'refs/heads/main','GITHUB_SHA':'a'*40,'GITHUB_REPOSITORY':'owner/repo','GITHUB_EVENT_PATH':str(event),
                'GITHUB_STEP_SUMMARY':str(summary),'STUDIO_SSH_PASSWORD':'fake','STUDIO_TELEGRAM_BOT_TOKEN':SECRET,'GH_TOKEN':'fake'}
            with patch.dict(os.environ,env),patch.object(w,'GitHub'),patch.object(w,'Peer'),patch.object(w,'operate',return_value=status()),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(w.main(),0)
            text=summary.read_text();self.assertNotIn(SECRET,text)
            for value in FP.values():self.assertNotIn(value,text)
            self.assertNotIn('192.0.2.10',text)
    def test_host_bridge_uses_existing_private_release_user_and_stdin_without_restarting_services(self):
        release='a'*40+'-'+'b'*16+'-'+'c'*8
        root='/opt/studio1925/releases/'+release+'/root'
        props={'LoadState':'loaded','ActiveState':'active','SubState':'running','User':'studio1925','RootDirectory':root,
            'FragmentPath':'/etc/systemd/system/studio1925.service','DropInPaths':''}
        calls=[]
        def command(args,input=None):
            calls.append((args,input))
            return status() if input else '\n'.join(k+'='+v for k,v in props.items())
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder)/'state';state.write_text(json.dumps({'current':release}))
            with patch.object(h.os,'geteuid',return_value=0),patch.object(h,'lock',return_value=contextlib.nullcontext()),\
                patch.object(h,'private',return_value=state),patch.object(h.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1001,pw_gid=1001)),\
                patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=0o40755,st_uid=0)),patch.object(Path,'is_symlink',return_value=False),\
                patch.object(Path,'is_file',return_value=True),patch.object(h,'command',side_effect=command):
                self.assertEqual(h.run({'operation':'configure','token':SECRET,'expected':FP}),status())
        self.assertEqual(len(calls),3)
        args,packet=calls[1];self.assertEqual(args[0],'systemd-run');self.assertIn(SECRET.encode(),packet)
        self.assertNotIn(SECRET,str(args));self.assertIn('--property=RootDirectory='+root,args)
        self.assertIn('--property=User=studio1925',args);self.assertIn('--property=UMask=0077',args)
        self.assertIn('--property=BindPaths=/var/lib/studio1925:/data',args)
        self.assertTrue(all(args[0]=='systemctl' and args[1]=='show' for args,_ in (calls[0],calls[2])))
    def test_host_cli_failure_or_ssh_authorization_never_exposes_raw_stderr(self):
        result=SimpleNamespace(stdout=json.dumps({'status':'FAILED','code':'AUTH_INVALID'}).encode(),returncode=1)
        with patch.object(h.subprocess,'run',return_value=result) as process:
            with self.assertRaisesRegex(h.Rejected,'AUTH_INVALID'):h.command(['systemd-run'],SECRET.encode())
            self.assertIs(process.call_args.kwargs['stderr'],subprocess.DEVNULL)
            self.assertNotIn(SECRET,str(process.call_args.kwargs['env']))
        for code,expected in ((5,'SSH_AUTH_FAILED'),(255,'SSH_CONNECTION_FAILED')):
            child=Mock();child.communicate.return_value=(b'',None);child.returncode=code;child.poll.return_value=code
            with patch.object(w.subprocess,'Popen',return_value=child):
                with self.assertRaisesRegex(w.Failure,expected):w.Peer('192.0.2.10','fake').call({'operation':'diagnose'})
    def test_workflow_manual_main_and_global_registry_serialization_without_new_daemon(self):
        text=(ROOT/'.github/workflows/manage-studio-telegram.yml').read_text()
        for term in ('workflow_dispatch:',"github.ref == 'refs/heads/main'",'deployments: write','group: studio-telegram-management','cancel-in-progress: false','secrets.STUDIO_TELEGRAM_BOT_TOKEN','secrets.STUDIO_TELEGRAM_OWNER_CONFIRMATION'):self.assertIn(term,text)
        for term in ('  push:', '  schedule:', '${{ inputs.', 'STUDIO_SSH_KNOWN_HOSTS','token:\n        description:'):self.assertNotIn(term,text)
        host=(FOLDER/'host.py').read_text()
        for term in ('systemctl restart','systemctl stop','systemctl enable','ufw allow','nft add','iptables -A','mount --bind','apt-get','docker','sqlite3.connect','shell=True'):self.assertNotIn(term,host)
        self.assertIn('systemd-run',host);self.assertIn('--property=RuntimeMaxSec=60',host)

if __name__=='__main__':unittest.main()
