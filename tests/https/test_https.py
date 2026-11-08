"""No VPS, public DNS, ACME issuance or real systemd. Isolated files/TCP/FDs."""
import ast
import contextlib
import copy
import datetime as dt
import email.utils
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/https'), str(ROOT / 'scripts/installer'), str(ROOT / 'scripts/diagnostics'), str(ROOT / 'scripts/firewall')]
import remote
sys.modules['studio_installer'] = remote
import configuration as cfg
import checks
import inventory
import host
import workflow
import monitor
from transport_settings import https_settings, https_origin, hostname

DOMAIN = 'fixture.duckdns.org'
IP = '192.0.2.10'
NONCE = 'f' * 64
CANARY = 'SYNTHETIC_PASSWORD_PII_PRIVATE_KEY_NEVER_LOG'
TLS = {'format': 1, 'hostname': DOMAIN}


class FakeInstaller:
    def __init__(self, root):
        self.CONFIG=root/'appconfig';self.CONFIG.mkdir()
        self.BASE=root/'app';self.UNIT=root/'studio1925.service';self.SERVICE='studio1925.service'
        self.Path=Path;self.commands=[];self.state={'format':1,'phase':'ready','current':'a'*40+'-'+'b'*16+'-'+'c'*8,'port':3000,'origin':'http://192.0.2.10:3000'}
        self.UNIT.write_text('old-unit')
        (self.CONFIG/'server.env').write_text('old-env')
        self.fail=None
    def install_lock(self):return contextlib.nullcontext()
    def load_state(self,**kwargs):return copy.deepcopy(self.state)
    def store_state(self,state):self.state=copy.deepcopy(state)
    def private_environment(self):return (self.CONFIG/'server.env').read_text()
    def atomic_write(self,path,text,mode=0o600):Path(path).write_text(text);os.chmod(path,mode)
    def https_settings(self,state):return https_settings(state)
    def environment_text(self,*args,**kwargs):return remote.environment_text(*args,**kwargs)
    def service_text(self,*args,**kwargs):return remote.service_text(*args,**kwargs)
    def digest(self,path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    def run(self,argv,*args,**kwargs):
        self.commands.append(argv)
        if self.fail and self.fail(argv):raise checks.HttpsError('SYNTHETIC_FAILURE')
        return 0 if argv[:2]==['systemctl','is-enabled'] else ''
    def health(self,*a,**k):pass
    def api_health(self,*a,**k):pass


class FakeOperations(host.Operations):
    def __init__(self):
        super().__init__('synthetic source', inspector=self.inspect, verifier=lambda *a,**k:{'fingerprint':'b'*64,'lifetime_ok':True})
        self.calls=[];self.fault=None;self.stopped=False;self.rollbacks=0
    def inspect(self,*a,**kw):
        self.calls.append('inspect')
        if self.fault=='inspect':raise checks.HttpsError('PREFLIGHT_READ_INCOMPLETE')
        return {'arch':'x64','firewall':'c'*64,'port':3000,'public':[IP],'tls_stopped':self.stopped}
    def prepare(self,*args):
        self.calls.append('prepare')
        if self.fault=='prepare':raise checks.HttpsError('CADDY_CONFIG_INVALID')
        return {'committed':False,'hostname':DOMAIN}
    def start_tls(self):
        self.calls.append('start')
        if self.fault=='start':raise checks.HttpsError('TLS_START_FAILED')
        return super().start_tls()
    def certificate(self,*args):
        self.calls.append('certificate')
        if self.fault=='certificate':raise checks.HttpsError('TRUSTED_CERTIFICATE_NOT_READY')
        return super().certificate(*args)
    def cutover(self,*args):
        self.calls.append('cutover');value=super().cutover(*args)
        if self.fault=='cutover':raise checks.HttpsError('TLS_STUDIO_RESTART_FAILED')
        return value
    def rollback(self,*args):self.rollbacks+=1;return super().rollback(*args)


class Fixture:
    def __init__(self, root, owner=None):
        self.root=root;self.installer=FakeInstaller(root);self.ops=FakeOperations();self.owner=owner;self.events=[];self.phases=[]
        self.db=root/'data.sqlite';db=sqlite3.connect(self.db);db.execute('create table bookings(id text)');db.execute("insert into bookings values('before')");db.commit();db.close()
    def patches(self):
        stack=contextlib.ExitStack()
        for name,value in {'I':self.installer,'BASE':self.root,'OWNER':self.root/'managed.json','TRANSACTION':self.root/'transaction.json'}.items():stack.enter_context(patch.object(host,name,value))
        stack.enter_context(patch.object(host,'owned',side_effect=lambda:self.owner if not (self.root/'managed.json').exists() else json.loads((self.root/'managed.json').read_text())))
        return stack
    def emit(self,kind,**fields):self.events.append({'event':kind,**fields})
    def ack(self,phase,nonce):self.phases.append(phase)
    def run(self,ack=None,emit=None):
        return host.apply({'hostname':DOMAIN,'addresses':[IP],'nonce':NONCE},b'archive','source',ops=self.ops,emit=emit or self.emit,ack=ack or self.ack,probe=lambda *a:contextlib.nullcontext())


class HttpsTests(unittest.TestCase):
    def test_input_validation_exact_confirmation_and_dual_stack(self):
        self.assertEqual(cfg.inputs({'server_ip':IP,'hostname':DOMAIN,'mode':'apply','confirmation':cfg.CONFIRMATION},fixture=True)['addresses'],[IP])
        for change in ({'confirmation':''},{'confirmation':cfg.CONFIRMATION+' '},{'hostname':'$(bad).duckdns.org'},{'server_ip':'127.0.0.1'},{'server_ip':'https://192.0.2.10'},{'additional_ip':'192.0.2.11'},{'hostname':'example.com'}):
            with self.assertRaises(ValueError):cfg.inputs({'server_ip':IP,'hostname':DOMAIN,'mode':'apply','confirmation':cfg.CONFIRMATION,**change},fixture=True)
        self.assertEqual(len(cfg.inputs({'server_ip':IP,'additional_ip':'2001:db8::1','hostname':DOMAIN},fixture=True)['addresses']),2)
        with self.assertRaises(ValueError):cfg.inputs({'server_ip':IP,'hostname':DOMAIN})

    def test_managed_settings_preserve_https_env_loopback_and_reject_downgrade_result(self):
        import deploy
        env=remote.environment_text(3100,'http://192.0.2.2:3100',TLS)
        self.assertIn('API_PUBLIC_ORIGIN=https://'+DOMAIN,env);self.assertIn('API_TRUST_PROXY=true',env);self.assertIn('API_ALLOW_INSECURE_TEST_HTTP=false',env)
        self.assertIn('--hostname 127.0.0.1',remote.service_text(Path('/opt/studio1925/releases/fixture'),3100,TLS))
        for bad in ({'format':True,'hostname':DOMAIN},{'format':1,'hostname':'evil.com'},{'format':1,'hostname':DOMAIN,'extra':'bad'}):
            with self.assertRaises(ValueError):https_settings({'https':bad})
        value={'status':'SUCCESS','version':'a'*40,'port':3100,'url':'https://'+DOMAIN,'https':TLS,'health':200,'technical_acceptance':'passed','operation':'update','migrations':'verified','service':'active-enabled'}
        self.assertEqual(deploy.safe_result(value,'a'*40,IP,TLS)['https'],TLS)
        with self.assertRaises(deploy.DeployError):deploy.safe_result({**value,'url':'http://'+IP+':3100'},'a'*40,IP,TLS)

    def test_config_is_letsencrypt_http01_only_no_token_h3_or_public_admin(self):
        value=cfg.caddy_config(DOMAIN,3000);blob=json.dumps(value)
        self.assertEqual(value['admin']['listen'],cfg.ADMIN)
        self.assertEqual(value['apps']['http']['servers']['studio_https']['protocols'],['h1','h2'])
        issuer=value['apps']['tls']['automation']['policies'][0]['issuers'][0]
        self.assertEqual(issuer['ca'],cfg.ACME);self.assertTrue(issuer['challenges']['tls-alpn']['disabled'])
        self.assertIn('127.0.0.1:3000',blob);self.assertIn('{http.request.remote.host}',blob)
        self.assertNotIn('DUCKDNS_TOKEN',blob);self.assertNotIn('2019',blob)
        self.assertNotIn('includeSubDomains',blob);self.assertNotIn('preload',blob)
        for bad in ('/bin/caddy','/opt/studio1925-https/releases/../other/caddy'):
            with self.assertRaises(ValueError):cfg.service(bad)

    def test_dns_exact_a_aaaa_caa_and_independent_resolver_agreement(self):
        import urllib.parse
        seen=[]
        def fetch(url,*args):
            seen.append(url);q=urllib.parse.parse_qs(urllib.parse.urlparse(url).query);name=q['name'][0];kind=int(q['type'][0])
            answers=[{'name':DOMAIN+'.','type':1,'data':IP}] if kind==1 else []
            return {'Status':0,'Answer':answers},{}
        self.assertTrue(checks.dns_records(DOMAIN,[IP],fetch))
        self.assertTrue(any('cloudflare' in u for u in seen));self.assertTrue(any('dns.google' in u for u in seen))
        def unexpected(url,*args):
            data,headers=fetch(url,*args)
            if 'type=28' in url:data['Answer']=[{'name':DOMAIN+'.','type':28,'data':'2001:db8::1'}]
            return data,headers
        with self.assertRaisesRegex(checks.HttpsError,'DNS_ADDRESS_MISMATCH'):checks.dns_records(DOMAIN,[IP],unexpected)
        def denied(url,*args):
            data,headers=fetch(url,*args)
            if 'type=257' in url:data['Answer']=[{'type':257,'data':'0 issue "other-ca.example"'}]
            return data,headers
        with self.assertRaisesRegex(checks.HttpsError,'CAA_DISALLOWS'):checks.dns_records(DOMAIN,[IP],denied)

    def test_acme_outbound_and_clock_date_are_verified_without_issuance(self):
        good={'newNonce':'https://ca/nonce','newAccount':'https://ca/account','newOrder':'https://ca/order'}
        date=email.utils.format_datetime(dt.datetime.now(dt.timezone.utc))
        checks.acme_ready(lambda u:(good,{'Date':date}))
        with self.assertRaises(checks.HttpsError):checks.acme_ready(lambda u:(good,{'Date':'invalid'}))

    def test_firewall_unknown_nat_rules_sets_and_active_ufw_refuse(self):
        data={name:'' for name in ('ip4','ip6','legacy4','legacy6')};data.update(ufw='Status: inactive\n',nft='{"nftables":[]}')
        self.assertRegex(inventory.empty_firewall(data),'^[a-f0-9]{64}$')
        for key,value in (('ufw','Status: active\nDefault: allow (incoming)'),('ip4','*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j REDIRECT\nCOMMIT\n'),('ip6','*filter\n:INPUT DROP [0:0]\nCOMMIT\n'),('nft','{"nftables":[{"set":{}}]}'),('legacy4','unexpected'),('nft','{"nftables":[{"chain":{"hook":"input","policy":"drop"}}]}')):
            with self.assertRaises(checks.HttpsError):inventory.empty_firewall({**data,key:value})
        for key in ('ip4','ip6','legacy4','legacy6'):self.assertEqual(inventory.COMMANDS[key][-2:],('-M','/bin/false'))

    def test_success_order_http_preserved_until_external_tls_and_sqlite_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));before=f.db.read_bytes()
            def ack(phase,nonce):
                f.ack(phase,nonce)
                if phase in ('ports-probe','certificate-ready'):
                    self.assertEqual(f.installer.private_environment(),'old-env');self.assertNotIn('https',f.installer.state)
                else:self.assertIn('API_TRUST_PROXY=true',f.installer.private_environment())
            with f.patches():f.run(ack)
            self.assertEqual(f.phases,['ports-probe','certificate-ready','cutover-ready'])
            self.assertEqual(f.installer.state['https'],TLS);self.assertNotIn('https_pending',f.installer.state)
            self.assertFalse((Path(tmp)/'transaction.json').exists());self.assertEqual(f.db.read_bytes(),before)
            self.assertEqual(f.events[-1]['status'],'SUCCESS')

    def test_failures_before_admission_or_certificate_never_replace_http(self):
        for fault in ('inspect','prepare','start','certificate'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                f=Fixture(Path(tmp));f.ops.fault=fault
                with f.patches(),self.assertRaises(Exception):f.run()
                self.assertEqual(f.installer.private_environment(),'old-env');self.assertEqual(f.installer.UNIT.read_text(),'old-unit');self.assertNotIn('https',f.installer.state)

    def test_lost_ssh_ack_at_each_phase_restores_only_uncommitted_configuration(self):
        for failed in ('ports-probe','certificate-ready','cutover-ready'):
            with self.subTest(phase=failed),tempfile.TemporaryDirectory() as tmp:
                f=Fixture(Path(tmp))
                def ack(phase,nonce):
                    if phase==failed:raise EOFError('synthetic transport loss')
                with f.patches(),self.assertRaises(Exception):f.run(ack)
                self.assertEqual(f.installer.private_environment(),'old-env');self.assertNotIn('https',f.installer.state)
                self.assertFalse((Path(tmp)/'transaction.json').exists())

    def test_partial_cutover_rolls_back_without_losing_new_bookings(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            def ack(phase,nonce):
                if phase=='cutover-ready':
                    db=sqlite3.connect(f.db);db.execute("insert into bookings values('during')");db.commit();db.close();raise EOFError()
            with f.patches(),self.assertRaisesRegex(checks.HttpsError,'PRIOR_CONFIGURATION_RESTORED'):f.run(ack)
            db=sqlite3.connect(f.db)
            self.assertEqual(db.execute('select id from bookings order by id').fetchall(),[('before',),('during',)]);db.close()
            self.assertEqual(f.installer.UNIT.read_text(),'old-unit')

    def test_hard_crash_checkpoint_recovery_and_unknown_files_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            with f.patches():
                checkpoint=f.ops.checkpoint(f.installer.state,None);checkpoint['hostname']=DOMAIN
                f.ops.cutover(checkpoint,{'committed':False})
                self.assertTrue(f.installer.state['https_pending'])
                f.ops.rollback(checkpoint)
                self.assertEqual(f.installer.UNIT.read_text(),'old-unit')
                checkpoint=f.ops.checkpoint(f.installer.state,None);checkpoint['hostname']=DOMAIN
                f.ops.cutover(checkpoint,{'committed':False});f.installer.UNIT.write_text('FOREIGN_ADMIN_EDIT')
                with self.assertRaisesRegex(checks.HttpsError,'RECOVERY_FILES_CHANGED'):f.ops.rollback(checkpoint)
                self.assertEqual(f.installer.UNIT.read_text(),'FOREIGN_ADMIN_EDIT')

    def test_lost_success_response_keeps_committed_https_and_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            def emit(phase,**fields):
                if phase=='result':raise BrokenPipeError()
            with f.patches(),self.assertRaisesRegex(checks.HttpsError,'HTTPS_COMMITTED_RESULT_UNCONFIRMED'):f.run(emit=emit)
            self.assertEqual(f.installer.state['https'],TLS);self.assertEqual(f.ops.rollbacks,0)
            before=(f.installer.UNIT.read_bytes(),f.installer.private_environment(),f.db.read_bytes())
            f.installer.commands.clear()
            with f.patches():f.run()
            self.assertEqual(before,(f.installer.UNIT.read_bytes(),f.installer.private_environment(),f.db.read_bytes()))
            self.assertNotIn(['systemctl','restart',f.installer.SERVICE],f.installer.commands)
            self.assertEqual(f.events[-1]['operation'],'already-https')

    def test_public_verified_crash_finalizes_https_instead_of_reopening_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            with f.patches():
                checkpoint=f.ops.checkpoint(f.installer.state,None);checkpoint['hostname']=DOMAIN
                f.ops.cutover(checkpoint,{})
                checkpoint['stage']='public-verified'
                (Path(tmp)/'managed.json').write_text('{"committed":false,"hostname":"'+DOMAIN+'"}')
                f.ops.rollback(checkpoint)
            self.assertEqual(f.installer.state['https'],TLS);self.assertIn('--hostname 127.0.0.1',f.installer.UNIT.read_text())
            self.assertNotIn('https_pending',f.installer.state)

    def test_commands_never_target_vpn_or_change_firewall_and_timers_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp))
            with f.patches():f.run()
            for argv in f.installer.commands:
                self.assertEqual(argv[0],'systemctl')
                for item in argv[2:]:self.assertIn(item,(cfg.SERVICE,cfg.MONITOR_TIMER,cfg.RECOVERY_TIMER,'studio1925.service'))
            source=(ROOT/'scripts/https/host.py').read_text()
            for bad in ('ufw allow','iptables -A','nft add','sysctl -w','reboot','sqlite3.connect'):self.assertNotIn(bad,source)
            for text in cfg.auxiliary_units().values():
                self.assertNotIn('PartOf=',text);self.assertNotIn('BindsTo=',text)

    def test_owned_managed_stopped_service_can_recover_without_http_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp),{'committed':True,'hostname':DOMAIN})
            f.installer.state['https']=TLS;f.installer.state['origin']=https_origin(TLS);f.ops.stopped=True
            with f.patches():f.run()
            self.assertNotIn('cutover',f.ops.calls);self.assertEqual(f.installer.state['https'],TLS)
            self.assertEqual(f.events[-1]['operation'],'https-service-recovered')

    def test_real_local_port_probe_has_one_time_body_and_closes_its_own_sockets(self):
        original=socket.socket
        class LocalSocket(original):
            def bind(self,address):
                if address[1]==0:return super().bind(('127.0.0.1',0))
                return super().bind(address)
        with patch.object(host.socket,'socket',LocalSocket):
            with host.PortProbe(NONCE,[],ports=(0,)) as probe:
                port=probe.servers[0].server_address[1]
                checks.port_challenge('127.0.0.1',port,NONCE)
                with self.assertRaises(checks.HttpsError):checks.port_challenge('127.0.0.1',port,'a'*64)
            self.assertTrue(checks.closed('127.0.0.1',port))

    def test_monitor_failure_and_notification_test_never_repairs_or_connects(self):
        with patch.dict(os.environ,{'GITHUB_REF':'refs/heads/main','STUDIO_TEST_NOTIFICATION':'true','GITHUB_STEP_SUMMARY':''}),patch.object(monitor,'check') as fn,contextlib.redirect_stdout(io.StringIO()) as log:
            self.assertEqual(monitor.main(),1);fn.assert_not_called();self.assertIn('NO_NETWORK',log.getvalue())

    def test_bundled_source_has_no_password_and_workflow_is_manual_main_only(self):
        source=workflow.source();compile(source,'fixture','exec')
        self.assertNotIn(CANARY.encode(),source)
        text=(ROOT/'.github/workflows/studio-https.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('  push:',text);self.assertNotIn('  schedule:',text)
        self.assertIn("github.ref == 'refs/heads/main'",text);self.assertIn('secrets.STUDIO_SSH_PASSWORD',text)
        self.assertNotIn('DUCKDNS_TOKEN',text);self.assertNotIn('STUDIO_SSH_KNOWN_HOSTS',text)


RECEIVER=r'''
import json,sys,hashlib
header=json.loads(sys.stdin.buffer.readline())
code=sys.stdin.buffer.read(header['code_size']);archive=sys.stdin.buffer.read(header['archive_size'])
assert b'SYNTHETIC_PASSWORD_PII_PRIVATE_KEY_NEVER_LOG' not in code
assert header['options']['nonce']=='f'*64
print(json.dumps({'event':'ports-probe'}),flush=True)
ack=json.loads(sys.stdin.buffer.readline());assert ack['phase']=='ports-probe' and ack['ok'] is True
print(json.dumps({'event':'result','status':'SUCCESS','operation':'https-enabled','changes':'studio-tls-only'}),flush=True)
'''


class SessionTests(unittest.TestCase):
    def test_first_ssh_command_uses_real_pipe_fds_and_password_only_in_environment(self):
        commands=[]
        class SSH:
            password=CANARY
            def arguments(self,command):commands.append(command);return [sys.executable,'-c',RECEIVER]
        events=[]
        with contextlib.redirect_stdout(io.StringIO()) as log:
            result=workflow.Session(SSH()).run({'nonce':NONCE},b'public-artifact',lambda phase,event:events.append(phase))
        self.assertEqual(result['status'],'SUCCESS');self.assertEqual(events,['ports-probe'])
        self.assertNotIn(CANARY,log.getvalue()+' '.join(commands))
    def test_auth_failure_malicious_protocol_and_transport_cleanup(self):
        for body,code in (("raise SystemExit(5)",'SSH_AUTH_FAILED'),("print('not json')",'INVALID_REMOTE_PROTOCOL'),("print('{\"event\":\"result\",\"status\":\"FAILED\",\"code\":\"SYNTHETIC_PASSWORD_PII_PRIVATE_KEY_NEVER_LOG\"}')",'REMOTE_HTTPS_FAILED')):
            class SSH:
                password=CANARY
                def arguments(self,command):return [sys.executable,'-c',"import sys,json;h=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read(h['code_size']+h['archive_size']);"+body]
            session=workflow.Session(SSH())
            with self.assertRaisesRegex(checks.HttpsError,code):session.run({'nonce':NONCE})
            self.assertIsNotNone(session.child.poll());self.assertTrue(session.child.stdin.closed);self.assertTrue(session.child.stdout.closed)


if __name__=='__main__':unittest.main()
