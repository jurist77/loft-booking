#!/usr/bin/env python3
"""Real stock UFW + kernel + packets; disposable GitHub runners ONLY.

A private mount/network namespace holds UFW configuration, lock and both packet
endpoints. Host firewall/routing/config stay outside it. No SSH/VPS/DNS/ACME.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts/https'),str(ROOT/'scripts/firewall'),str(ROOT/'scripts/diagnostics'),str(ROOT/'scripts/installer')]
import firewall as fw
from rules import nft_rule


def run(args, timeout=30):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout)
    if result.returncode:raise AssertionError('CI_NAMESPACE_COMMAND_FAILED')
    return result.stdout


def host_fingerprint():
    raw={name:fw.F.saved_tables(run([name,'-M','/bin/false']).decode()) for name in ('iptables-save','ip6tables-save','iptables-legacy-save','ip6tables-legacy-save')}
    raw['nft']=fw.F.clean_nft(json.loads(run(['nft','-j','list','ruleset'])))
    # Config is captured after installation of tooling, before entering namespace.
    for name in (*fw.F.PROTECTED,'/etc/ufw/user.rules','/etc/ufw/user6.rules'):
        path=Path(name)
        raw[name]=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return hashlib.sha256(json.dumps(raw,sort_keys=True).encode()).hexdigest()


def inside():
    # Namespace identity must actually differ; never fall back to host execution.
    assert os.readlink('/proc/self/ns/net')!=os.environ['STUDIO_CI_PARENT_NET']
    assert os.readlink('/proc/self/ns/mnt')!=os.environ['STUDIO_CI_PARENT_MNT']
    servers=[];peer=None
    with tempfile.TemporaryDirectory(prefix='studio-ufw-kernel-') as tmp:
        temp=Path(tmp);config=temp/'ufw';shutil.copytree('/etc/ufw',config)
        for name in ('before.rules','before6.rules','after.rules','after6.rules','user.rules','user6.rules'):
            shutil.copyfile('/usr/share/ufw/iptables/'+name,config/name)
        (config/'ufw.conf').write_text('ENABLED=no\nLOGLEVEL=low\n')
        shutil.rmtree(config/'applications.d');(config/'applications.d').mkdir()
        (config/'applications.d/ci-openssh').write_text('[OpenSSH]\ntitle=CI SSH\ndescription=Synthetic namespace only\nports=22/tcp\n')
        defaults=temp/'defaults';shutil.copyfile('/etc/default/ufw',defaults)
        private_run=temp/'run';private_run.mkdir();(private_run/'ufw.lock').touch(mode=0o600)
        for source,target in ((config,'/etc/ufw'),(defaults,'/etc/default/ufw'),(private_run,'/run')):
            run(['mount','--bind',str(source),target])
        print('CI_UFW_PHASE_STOCK_SETUP',flush=True)
        run(['ip','link','set','lo','up'])
        run(['ufw','allow','OpenSSH']);run(['ufw','allow','4444/tcp'])
        run(['ufw','allow','51820/udp']);run(['ufw','--force','enable'])
        fw.F.ufw_implementation()
        peer=subprocess.Popen(['unshare','--net','--','python3','-c','import time;time.sleep(600)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if peer.poll() is not None:raise AssertionError('CI_PEER_NAMESPACE_FAILED')
                if os.readlink(f'/proc/{peer.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
                time.sleep(.01)
            else:raise AssertionError('CI_PEER_NAMESPACE_FAILED')
            prefix=['nsenter','--target',str(peer.pid),'--net','--']
            run(['ip','link','add','studio-in','type','veth','peer','name','studio-client'])
            run(['ip','link','set','studio-client','netns',str(peer.pid)])
            for command in (['ip','link','set','lo','up'],['ip','link','set','studio-client','up']):run(prefix+command)
            run(['ip','link','set','studio-in','up'])
            for v,server,client in ((4,'192.0.2.1/24','192.0.2.2/24'),(6,'2001:db8::1/64','2001:db8::2/64')):
                extra=['nodad'] if v==6 else []
                run(['ip',f'-{v}','addr','add',server,'dev','studio-in',*extra])
                run(prefix+['ip',f'-{v}','addr','add',client,'dev','studio-client',*extra])
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self,*a):pass
                def do_GET(self):
                    self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
            class V6(http.server.ThreadingHTTPServer):
                address_family=socket.AF_INET6
                def server_bind(self):self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);super().server_bind()
            for cls,address in ((http.server.ThreadingHTTPServer,'0.0.0.0'),(V6,'::')):
                for port in (22,80,443,4444):
                    server=cls((address,port),Handler);server.daemon_threads=True;servers.append(server)
                    threading.Thread(target=server.serve_forever,daemon=True).start()
            def probe(v,port):
                code="import http.client,sys\nc=http.client.HTTPConnection(sys.argv[1],int(sys.argv[2]),timeout=2)\ntry:\n c.request('GET','/');r=c.getresponse();sys.exit(0 if r.status==200 and r.read()==b'ok' else 2)\nexcept Exception:sys.exit(1)\nfinally:c.close()"
                result=subprocess.run(prefix+['python3','-c',code,'192.0.2.1' if v==4 else '2001:db8::1',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
                return result.returncode==0
            for v in (4,6):
                assert probe(v,22) and probe(v,4444),'CI_BASELINE_NEIGHBOR_FAILED'
                assert not probe(v,80) and not probe(v,443),'CI_BASELINE_PORT_NOT_BLOCKED'
            print('CI_UFW_PHASE_READONLY_PROOF',flush=True)
            # Real parser/serializer and read-only admission against complete
            # stock Ubuntu chains. No mocked kernel or mocked UFW in this test.
            before=fw.take();fingerprint=fw.fingerprint(before)
            print('CI_REVIEWED_STOCK_PROFILE_LOW_'+json.dumps(fw.F.stock_shape(before),sort_keys=True),flush=True)
            run(['ufw','logging','off'])
            print('CI_REVIEWED_STOCK_PROFILE_OFF_'+json.dumps(fw.F.stock_shape(fw.take()),sort_keys=True),flush=True)
            run(['ufw','logging','low'])
            before=fw.take();fingerprint=fw.fingerprint(before)
            assert fw.inspect(['192.0.2.1'])['firewall_plan']==[80,443]
            assert fw.fingerprint(fw.take())==fingerprint,'CI_CHECK_MUTATED_FIREWALL'
            print('CI_UFW_PHASE_VERIFIED_APPEND',flush=True)
            after=fw.enable(fingerprint,[80,443],['192.0.2.1'])
            assert fw.inspect(['192.0.2.1'])=={'firewall':after,'firewall_plan':[]}
            assert fw.inspect(['2001:db8::1'])['firewall_plan']==[]
            print('CI_UFW_PHASE_PACKET_AND_REPEAT_PROOF',flush=True)
            for v in (4,6):
                assert all(probe(v,p) for p in (22,80,443,4444)),'CI_EXTERNAL_PACKET_PATH_FAILED'
            assert fw.fingerprint(fw.take())==after,'CI_REPEAT_CHANGED_FIREWALL'
            print('REAL_UFW_KERNEL_OK: stock OpenSSH/IPv4/IPv6, check read-only, 80/443 append, repeat no-op, SSH/neighbor preserved',flush=True)
        finally:
            for server in servers:server.shutdown();server.server_close()
            if peer:peer.terminate();peer.wait(timeout=10)


def main():
    if not (os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('STUDIO_UFW_KERNEL_CI')=='1' and str(ROOT).startswith('/home/runner/work/')):
        raise SystemExit('CI_ONLY: refusing non-disposable environment')
    if sys.argv[1:]==['--inside']:inside();return
    assert sys.argv[1:]==[]
    before=host_fingerprint()
    env={**os.environ,'STUDIO_CI_PARENT_NET':os.readlink('/proc/self/ns/net'),'STUDIO_CI_PARENT_MNT':os.readlink('/proc/self/ns/mnt')}
    process=subprocess.Popen(['unshare','--mount','--net','--fork','--propagation','private','--',sys.executable,str(Path(__file__).resolve()),'--inside'],env=env,start_new_session=True)
    try:result=process.wait(timeout=240)
    finally:
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
        assert host_fingerprint()==before,'CI_HOST_FIREWALL_OR_CONFIGURATION_CHANGED'
    assert result==0,'CI_ISOLATED_UFW_FAILED'


if __name__=='__main__':
    try:main()
    except fw.F.Unsafe as error:print('CI_UFW_BLOCKED_'+error.code,flush=True);raise SystemExit(1) from None
    except fw.HttpsError as error:print('CI_UFW_BLOCKED_'+str(error),flush=True);raise SystemExit(1) from None
    except Exception as error:
        # Only our own fixed assertion codes; never argv/raw rules/addresses.
        print(str(error) if isinstance(error,AssertionError) and str(error).startswith('CI_') else 'CI_UFW_KERNEL_FAILED',flush=True)
        raise SystemExit(1) from None
