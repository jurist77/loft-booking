#!/usr/bin/env python3
"""Disposable GITHUB HOSTED RUNNER ONLY. No real SSH/DNS/ACME/backup repo.

Production logic is real. Only storage location, public-network admission and
issuer are CI fixtures. Browser SQL uses a /tmp/studio-server-ui-* database,
NEVER a literal production data path. No TLS verification bypass is used.
"""
import argparse
import contextlib
import io
from unittest.mock import patch
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/installer'),str(ROOT/'scripts/https'),str(ROOT/'scripts/diagnostics'),str(ROOT/'scripts/firewall'),str(Path(__file__).parent)]
spec=importlib.util.spec_from_file_location('base_systemd_ci',ROOT/'tests/installer/real_systemd.py');ci=importlib.util.module_from_spec(spec);spec.loader.exec_module(ci)
sys.modules['studio_installer']=ci.installer
import host
import inventory
import configuration as cfg
import checks
import workflow
from artifacts import RELEASE,download
from fixture_config import internal


def command(args,check=True):
    return ci.command(args,check)


def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--version',required=True);args=p.parse_args()
    if not (os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('STUDIO_INSTALLER_CI')=='1' and str(ROOT).startswith('/home/runner/work/')):
        raise SystemExit('CI_ONLY: no execution outside a disposable GitHub runner')
    if any(path.exists() for path in (*ci.SITE_PATHS,ci.installer.UNIT,host.BASE,host.DATA,host.ETC)):
        raise SystemExit('CI_FIXTURE_COLLISION')
    I=ci.installer;host.I=I;inventory.I=I
    data=Path('/tmp/studio-server-ui-'+uuid.uuid4().hex)
    I.DATA=data;ci.SITE_PATHS=(I.BASE,I.CONFIG,I.DATA,I.CACHE,I.BACKUPS)
    original_source=ci.transport.remote_source
    def private_source():
        code=original_source();target=b'DATA = Path("/var/lib/studio1925")'
        assert code.count(target)==1
        return code.replace(target,('DATA = Path('+repr(str(data))+')').encode())
    ci.transport.remote_source=private_source
    hostname='fixture.dynv6.net';nonce=secrets.token_hex(32);options={'hostname':hostname,'addresses':['127.0.0.1'],'nonce':nonce}
    host.RELEASE=RELEASE
    source=workflow.source().decode();fingerprints=None
    # CI fixture only: Caddy journals contain only our synthetic hostname and
    # ephemeral CA metadata. Production service output remains disabled.
    host.service=lambda binary:cfg.service(binary).replace('StandardOutput=null','StandardOutput=journal').replace('StandardError=null','StandardError=journal')
    ca=host.DATA/'storage/pki/authorities/local/root.crt'
    alias='studio-https-ci-'+uuid.uuid4().hex
    os_ca=Path('/usr/local/share/ca-certificates')/(alias+'.crt')
    stores=[Path.home()/'.pki/nssdb',Path.home()/'.local/share/pki/nssdb']
    hosts=Path('/etc/hosts');host_line='127.0.0.1 '+hostname+' # '+alias+'\n'
    assert hostname not in hosts.read_text()
    canary=Path('/etc/systemd/system/studio-ci-vpn.service');canary_directory=Path('/opt/studio-ci-vpn')
    assert not canary.exists() and not canary_directory.exists()
    ctx=None;last_verification=None
    def verify(name,address,**kwargs):
        nonlocal last_verification
        try:context=ssl.create_default_context(cafile=str(ca))
        except OSError:raise checks.HttpsError('TEST_CA_NOT_READY') from None
        try:return checks.https_health(name,address,minimum=30,context=context,**kwargs)
        except checks.HttpsError as error:
            if last_verification!=str(error):print('CI_ONLY_TLS_VERIFY_'+str(error),flush=True);last_verification=str(error)
            raise
    def inspect(state,addresses,managed=False,allow_stopped=False):
        I.host_facts()
        assert I.private_environment()==I.environment_text(state['port'],state.get('origin'),I.https_settings(state))
        selected={}
        for name in ('service','caddy','sockets4','sockets6','web4','web6'):
            status,raw=inventory.read(name,state['port']);assert status=='ok' or name=='caddy' and not managed
            selected[name]=raw
        _,pid=inventory.service_summary('ok',selected['service'])
        inventory.own_unit(selected['service'],I.UNIT)
        rows=inventory.own_listeners({k:selected[k] for k in ('sockets4','sockets6')},pid,state['port'])
        if state.get('https'):assert all(row['family']==4 and row['address']=='127.0.0.1' for row in rows)
        stopped=False
        if managed:
            inventory.own_unit(selected['caddy'],cfg.UNIT_DIR/cfg.SERVICE)
            svc,cpid=inventory.service_summary('ok',selected['caddy']);stopped=svc['ActiveState'] in ('failed','inactive')
            if not stopped:
                for port in (80,443):inventory.own_listeners({f'sockets{f}':inventory.select_port(selected[f'web{f}'],port) for f in (4,6)},cpid,port)
        I.health(state['port']);I.api_health(state['port'])
        return {'arch':I.host_facts()['arch'],'firewall':'f'*64,'port':state['port'],'public':[],'tls_stopped':stopped}
    def config(name,port):
        value=internal(cfg.caddy_config(name,port))
        value['apps']['http']['servers']['studio_https']['listen']=['127.0.0.1:443']
        value['apps']['http']['servers']['studio_http']['listen']=['127.0.0.1:80']
        return value
    def install_trust():
        os_ca.write_bytes(ca.read_bytes());command(['update-ca-certificates'])
        for nss in stores:
            nss.mkdir(parents=True,exist_ok=True)
            if not (nss/'cert9.db').exists():command(['certutil','-N','-d','sql:'+str(nss),'--empty-password'])
            command(['certutil','-D','-d','sql:'+str(nss),'-n',alias],False)
            command(['certutil','-A','-d','sql:'+str(nss),'-n',alias,'-t','C,,','-i',str(ca)])
    def ack(phase,value):
        assert value==nonce
        if phase=='ports-probe':
            for port in (80,443):checks.port_challenge('127.0.0.1',port,nonce)
            assert not I.load_state().get('https')
        else:
            cert=verify(hostname,'127.0.0.1');assert cert['fingerprint']
            if phase=='certificate-ready':
                install_trust();assert not I.load_state().get('https')
            if phase in ('cutover-ready','verify-existing'):
                s=json.loads((I.CONFIG/'state.json').read_text());assert s['https']['hostname']==hostname
                assert '--hostname 127.0.0.1' in I.UNIT.read_text()
    def emit(phase,**fields):print('CI_HTTPS_'+phase.replace('-','_').upper(),flush=True)
    try:
        ci.apply(args.archive,args.version)
        # Exercise the actual entry + full snapshot, unlike the TLS apply
        # adapter below. Only ambient CI firewall/address/ACME admission is a
        # fixture; systemd, ownership, sockets, health and API are real reads.
        def check_read(name,port):
            if name=='interfaces':return 'ok','[{"addr_info":[{"local":"8.8.8.8"}]}]'
            if name=='ufw':return 'ok','Status: inactive\n'
            if name=='nft':return 'ok','{"nftables":[]}'
            if name in ('ip4','ip6','legacy4','legacy6'):return 'ok',''
            return inventory.read(name,port)
        def check_snapshot(*a,**kw):return inventory.snapshot(*a,**kw,run=check_read,outbound=lambda:None)
        before_check=(I.UNIT.read_bytes(),(I.CONFIG/'state.json').read_bytes(),(I.CONFIG/'server.env').read_bytes())
        saved_umask=os.umask(0o077);os.umask(saved_umask)
        saved_signals={sig:signal.getsignal(sig) for sig in (signal.SIGHUP,signal.SIGTERM,signal.SIGINT)}
        try:
            with patch.object(host,'snapshot',side_effect=check_snapshot),contextlib.redirect_stdout(io.StringIO()) as check_log:
                code=host.entry({'server_ip':'8.8.8.8','additional_ip':'','hostname':hostname,'mode':'check','confirmation':'','nonce':nonce})
        finally:
            os.umask(saved_umask)
            for sig,handler in saved_signals.items():signal.signal(sig,handler)
        result=[json.loads(line) for line in check_log.getvalue().splitlines()]
        from phase_report import REMOTE_PHASES,ERROR_KINDS
        for event in result:
            if event.get('event')=='phase' and event.get('phase') in REMOTE_PHASES:
                print('CI_READONLY_PHASE_'+event['phase'],flush=True)
        if code!=0 or result[-1]['status']!='CHECK_CANDIDATE_ACTIVE_PROOF_REQUIRED':
            last=result[-1];phase=last.get('phase');kind=last.get('error_kind')
            print('CI_READONLY_FAILED code='+workflow.safe_code(last.get('code'))+' phase='+(phase if phase in REMOTE_PHASES else 'UNKNOWN')+' kind='+(kind if kind in ERROR_KINDS else 'OTHER'),flush=True)
            raise AssertionError('REAL_READONLY_ENTRY_FAILED')
        assert any(e.get('phase')=='CHECK_API' for e in result)
        assert before_check==(I.UNIT.read_bytes(),(I.CONFIG/'state.json').read_bytes(),(I.CONFIG/'server.env').read_bytes())
        assert not host.TRANSACTION.exists() and not host.OWNER.exists()
        print('REAL_READONLY_CHECK_OK: full entry/snapshot, real systemd/listener/health/API; managed files unchanged',flush=True)
        canary_directory.mkdir(mode=0o700);(canary_directory/'private.conf').write_text('synthetic VPN fixture, not a real configuration')
        os.chmod(canary_directory/'private.conf',0o600)
        canary.write_text('[Unit]\nDescription=CI UDP VPN neighbor\n[Service]\nExecStart=/usr/bin/python3 -c "import socket,time;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((\'127.0.0.1\',443));time.sleep(2400)"\n')
        command(['systemctl','daemon-reload']);command(['systemctl','start',canary.name])
        neighbor=command(['systemctl','show',canary.name,'-p','MainPID','--value']).stdout.strip()
        assert int(neighbor)>0
        fingerprints=ci.fingerprints()
        arch=I.host_facts()['arch']
        with tempfile.TemporaryDirectory(prefix='studio-caddy-ci-') as tmp:
            archive=download(arch,Path(tmp)/'caddy.tar.gz').read_bytes()
            ops=host.Operations(source,config=config,inspector=inspect,verifier=verify)
            # SIGKILL equivalent: no finally/rollback in the child. The durable
            # production recovery timer must restore the previous HTTP state.
            child=os.fork()
            if child==0:
                def crash_ack(phase,value):
                    ack(phase,value)
                    if phase=='cutover-ready':os._exit(77)
                host.apply(options,archive,source,ops=ops,emit=emit,ack=crash_ack)
                os._exit(99)
            _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==77
            end=time.monotonic()+65
            while time.monotonic()<end:
                state=json.loads((I.CONFIG/'state.json').read_text())
                if not state.get('https_pending') and not state.get('https') and not host.TRANSACTION.exists():break
                time.sleep(1)
            else:raise AssertionError('REAL_RECOVERY_TIMER_FAILED')
            I.health(state['port']);print('CI_REAL_REBOOT_STYLE_RECOVERY_OK',flush=True)
            host.apply(options,archive,source,ops=ops,emit=emit,ack=ack)
            before=command(['systemctl','show',I.SERVICE,'-p','MainPID','--value']).stdout
            host.apply(options,archive,source,ops=ops,emit=emit,ack=ack)
            assert command(['systemctl','show',I.SERVICE,'-p','MainPID','--value']).stdout==before
            # The real persisted watchdog must signal our deliberately short
            # fixture certificate, without an email service or public request.
            assert command(['systemctl','start',cfg.MONITOR_SERVICE],False).returncode!=0
            alert=command(['journalctl','-u',cfg.MONITOR_SERVICE,'-n','10','--no-pager','-o','cat']).stdout
            assert 'STUDIO_TLS_ATTENTION_CERTIFICATE_EXPIRING' in alert,'REAL_EXPIRY_SIGNAL_MISSING'
            print('CI_REAL_EXPIRY_SIGNAL_OK',flush=True)
        hosts.write_text(hosts.read_text()+host_line)
        state=I.load_state();runtime=I.BASE/'releases'/state['current']/'root/usr/bin/node'
        env={**os.environ,'STUDIO_E2E_DB':str(data/'studio.sqlite'),'NODE_EXTRA_CA_CERTS':str(ca)}
        result=subprocess.run([str(runtime),str(ROOT/'node_modules/@playwright/test/cli.js'),'test','--config=playwright.https.config.ts'],cwd=ROOT,env=env,timeout=400)
        assert result.returncode==0,'REAL_HTTPS_BROWSER_FAILED'
        with tempfile.TemporaryDirectory(prefix='studio-https-lifecycle-ci-') as tmp:
            directory=Path(tmp);upgraded=ci.variant(args.archive,directory,'b'*40)
            ci.apply(upgraded,'b'*40)
            assert I.load_state()['https']=={'format':1,'hostname':hostname}
            verify(hostname,'127.0.0.1')
            snapshot=directory/'snapshot.tar.gz'
            with snapshot.open('wb') as output:
                saved=subprocess.run(['python3','-','--action','snapshot','--purpose','daily'],input=private_source(),stdout=output,stderr=subprocess.DEVNULL,timeout=180)
            assert saved.returncode==0
            assert ci.lifecycle_backup.validate_bundle(snapshot)['https']['hostname']==hostname
            ci.apply(upgraded,'b'*40,restore_bundle=snapshot)
            assert I.load_state()['https']['hostname']==hostname
            verify(hostname,'127.0.0.1')
            assert 'API_ALLOW_INSECURE_TEST_HTTP=false' in I.private_environment()
            assert '--hostname 127.0.0.1' in I.UNIT.read_text()
        assert command(['systemctl','show',canary.name,'-p','MainPID','--value']).stdout.strip()==neighbor
        assert command(['systemctl','is-active',canary.name]).stdout.strip()=='active'
        ci.assert_unchanged(fingerprints)
        print('REAL_HTTPS_CI_OK: trusted browser/SQLite, response loss, spoof protection, crash recovery, repeat, update, restore, UDP neighbor preserved',flush=True)
    except BaseException:
        print('CI_ONLY_TLS_FAILURE_DIAGNOSTIC',flush=True)
        log=command(['journalctl','-u',cfg.SERVICE,'-n','25','--no-pager','-o','cat'],False).stdout
        print(log[-12000:],flush=True)
        raise
    finally:
        for unit in (cfg.MONITOR_TIMER,cfg.RECOVERY_TIMER,cfg.SERVICE):
            command(['systemctl','stop',unit],False);command(['systemctl','disable',unit],False)
        for unit in (cfg.MONITOR_SERVICE,cfg.RECOVERY_SERVICE):command(['systemctl','stop',unit],False)
        for unit in (cfg.SERVICE,*cfg.auxiliary_units()):(cfg.UNIT_DIR/unit).unlink(missing_ok=True)
        for path in (host.BASE,host.DATA,host.ETC):
            if path.exists():shutil.rmtree(path)
        command(['userdel',cfg.USER],False)
        ci.cleanup();command(['systemctl','stop',canary.name],False);canary.unlink(missing_ok=True)
        if canary_directory.exists():shutil.rmtree(canary_directory)
        command(['systemctl','daemon-reload'],False)
        hosts.write_text(hosts.read_text().replace(host_line,''))
        for nss in stores:command(['certutil','-D','-d','sql:'+str(nss),'-n',alias],False)
        os_ca.unlink(missing_ok=True);command(['update-ca-certificates'],False)


if __name__=='__main__':main()
