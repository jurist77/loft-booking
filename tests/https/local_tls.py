#!/usr/bin/env python3
"""Non-root local Caddy/Next/SQLite acceptance + actual certificate rotation.

Only loopback, new private temp SQLite and an ephemeral internal test CA. No
public DNS/ACME/SSH/systemd. Production config always keeps Let's Encrypt.
"""
import datetime as dt
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/https'),str(Path(__file__).parent)]
from configuration import caddy_config
from checks import DirectHTTPS,https_health,HttpsError
from fixture_config import internal


def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]


def main():
    binary=Path(sys.argv[1]).resolve();children=[]
    with tempfile.TemporaryDirectory(prefix='studio-https-local-') as tmp:
        root=Path(tmp);port=next(p for p in range(3150,3200) if port_available(p));tls=free_port();plain=free_port()
        host='fixture.duckdns.org';origin=f'https://{host}:{tls}'
        env={**os.environ,'APP_MODE':'server','DEPLOY_TARGET':'node','NODE_ENV':'production','SQLITE_PATH':str(root/'test.sqlite'),
             'API_PUBLIC_ORIGIN':origin,'API_TRUST_PROXY':'true','API_ALLOW_INSECURE_TEST_HTTP':'false','NEXT_TELEMETRY_DISABLED':'1'}
        setup="import{initializeDatabase,openDatabase}from'./src/server/database.ts';import{migrate}from'./src/server/migrations.ts';const s={path:process.env.SQLITE_PATH,busyTimeout:1000};initializeDatabase(s);const d=openDatabase(s);try{await migrate(d,'migrations/sqlite')}finally{d.close()}"
        subprocess.run(['node','--conditions=react-server','--input-type=module','-e',setup],cwd=ROOT,env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        config=internal(caddy_config(host,port),'90s');config['storage']['root']=str(root/'storage');config['admin']['listen']='unix/'+str(root/'admin.sock')
        config['apps']['http']['servers']['studio_https']['listen']=[f'127.0.0.1:{tls}'];config['apps']['http']['servers']['studio_http']['listen']=[f'127.0.0.1:{plain}']
        cfg=root/'caddy.json';cfg.write_text(json.dumps(config))
        try:
            children.append(subprocess.Popen(['node','node_modules/next/dist/bin/next','start','--hostname','127.0.0.1','--port',str(port)],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True))
            children.append(subprocess.Popen([str(binary),'run','--config',str(cfg)],env={**os.environ,'XDG_DATA_HOME':str(root/'data'),'XDG_CONFIG_HOME':str(root/'config')},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True))
            ca=root/'storage/pki/authorities/local/root.crt';ctx=None;first=None;end=time.monotonic()+30
            while time.monotonic()<end:
                try:
                    ctx=ssl.create_default_context(cafile=str(ca));first=https_health(host,'127.0.0.1',minimum=20,context=ctx,port=tls);break
                except (OSError,HttpsError):time.sleep(.2)
            assert first,'LOCAL_HTTPS_NOT_READY'
            body={'requestId':str(uuid.uuid4()),'resourceId':'studio-19-25','date':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=2)).strftime('%Y-%m-%d'),
                  'start':'12:00','end':'13:00','firstName':'Тест','lastName':'Пример','phone':'+79000000000'}
            def send(value,origin_value=origin):
                c=DirectHTTPS(host,'127.0.0.1',port=tls,context=ctx)
                try:
                    c.request('POST','/api/bookings',body=json.dumps(value),headers={'Content-Type':'application/json','Origin':origin_value,'X-Studio-Client-IP':'198.51.100.77'})
                    r=c.getresponse();data=json.loads(r.read(4096));return r.status,data
                finally:c.close()
            result=send(body);assert result[0]==201 and result[1]['bookingId']==body['requestId']
            assert send(body)[0]==201
            assert send({**body,'requestId':str(uuid.uuid4())})[0]==409
            assert send(body,'https://untrusted.example')[0]==403
            # Source DB is private and separate from installed data. Real
            # restart/update/restore persistence is tested by real_systemd.py.
            print('LOCAL_TLS_API_OK: CA/SAN verified, real SQLite COMMIT/idempotency/overlap/origin',flush=True)
            end=time.monotonic()+120;rotated=False
            while time.monotonic()<end:
                time.sleep(2)
                current=https_health(host,'127.0.0.1',minimum=10,context=ctx,api=False,port=tls)
                if current['fingerprint']!=first['fingerprint']:rotated=True;break
            assert rotated,'AUTOMATIC_CERTIFICATE_ROTATION_NOT_OBSERVED'
            print('LOCAL_AUTO_RENEW_OK: pinned Caddy renewed a short-lived internal fixture certificate without service restart',flush=True)
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    os.killpg(child.pid,signal.SIGTERM)
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()


def port_available(port):
    try:
        with socket.socket() as s:s.bind(('127.0.0.1',port))
        return True
    except OSError:return False


if __name__=='__main__':main()
