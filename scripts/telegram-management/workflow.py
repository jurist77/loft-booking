#!/usr/bin/env python3
"""Manual technical setup only. No token/claim/profile output or VPS deploy."""
import ast
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'installer'))
from deploy import SSH,server_ip

class Failure(Exception):pass

def require(value,code):
    if not value:raise Failure(code)

DIGEST=re.compile(r'^[a-f0-9]{64}$')
OPERATIONS=('configure','rotate-token','bootstrap-owner','diagnose')
CONFIRM={'configure':'CONFIGURE STUDIO TELEGRAM','rotate-token':'ROTATE STUDIO TELEGRAM TOKEN','bootstrap-owner':'INITIALIZE STUDIO TELEGRAM OWNER'}
WORKER_STATES={'NOT_CONFIGURED','INSTANCE_MISMATCH','RUNNING','AUTH_INVALID','CONCURRENT_POLLING','WORKER_UNAVAILABLE','NETWORK_UNCERTAIN','STARTING_OR_STOPPED'}
FIELDS={'workerState','status','configured','instanceBound','bot','instance','token','botRegistered','ownerReady','workerLive','enabled','subscribers','pendingRequests','queued','failed'}
FINGERPRINTS={'bot','instance','token'}
BOOLS={'configured','instanceBound','botRegistered','ownerReady','workerLive','enabled'}
COUNTS={'subscribers','pendingRequests','queued','failed'}
SAFE_CODES={n.value for p in (HERE/'host.py',HERE.parent/'installer/deploy.py',Path(__file__)) for n in ast.walk(ast.parse(p.read_text())) if isinstance(n,ast.Constant) and type(n.value)is str and re.fullmatch('[A-Z_]{1,80}',n.value)}
SAFE_CODES|={'AUTH_INVALID','CONCURRENT_POLLING','BOT_CHANGED_RELINK_REQUIRED','CONFIGURATION_PLAN_CHANGED','BOOTSTRAP_CONFIRMATION_INVALID','OWNER_ALREADY_BOOTSTRAPPED','INSTANCE_MISMATCH','WEBHOOK_CONFIGURED','WEBHOOK_STATE_UNCONFIRMED','NETWORK_UNCERTAIN','RATE_LIMITED','TEMPORARY_FAILURE'}

BOOTSTRAP=r'''
import json,sys,signal
signal.alarm(90)
try:
 h=json.loads(sys.stdin.buffer.readline(8193));n=h['code_size'];p=h['payload_size']
 if type(n)is not int or type(p)is not int or not 0<n<50000 or not 0<p<=8192:raise ValueError()
 code=sys.stdin.buffer.read(n);data=sys.stdin.buffer.read(p)
 if len(code)!=n or len(data)!=p:raise ValueError()
 scope={'__name__':'studio_telegram_operator'};exec(compile(code,'studio-telegram-operator','exec'),scope)
 print(json.dumps(scope['run'](json.loads(data))),flush=True)
except BaseException as e:
 value=str(e);safe=scope.get('Rejected') if 'scope'in globals() else None
 code=value if safe and isinstance(e,safe) and value in _CODES else 'MANAGEMENT_RESULT_UNKNOWN'
 print(json.dumps({'status':'FAILED','code':code}),flush=True);sys.exit(1)
'''

def validate(value,plan=False):
    require(type(value)is dict and set(value)==FIELDS|({'planned'} if plan else set()) and value.get('status')=='OK','MANAGEMENT_PROTOCOL_INVALID')
    require(value['workerState'] in WORKER_STATES,'MANAGEMENT_PROTOCOL_INVALID')
    for k in BOOLS:require(type(value[k])is bool,'MANAGEMENT_PROTOCOL_INVALID')
    for k in COUNTS:require(type(value[k])is int and 0<=value[k]<=10**9,'MANAGEMENT_PROTOCOL_INVALID')
    for k in FINGERPRINTS:require(value[k]is None or type(value[k])is str and DIGEST.fullmatch(value[k]),'MANAGEMENT_PROTOCOL_INVALID')
    if plan:validate_fingerprints(value['planned'])
    return value

def validate_fingerprints(value):
    require(type(value)is dict and set(value)==FINGERPRINTS and all(type(v)is str and DIGEST.fullmatch(v) for v in value.values()),'REGISTRY_STATE_INVALID')
    return value

class Peer:
    def __init__(self,address,password):self.ssh=SSH(address,password)
    def call(self,payload):
        code=(HERE/'host.py').read_bytes();raw=json.dumps(payload).encode()
        require(len(raw)<=8192,'INPUT_LIMIT')
        packet=json.dumps({'code_size':len(code),'payload_size':len(raw)}).encode()+b'\n'+code+raw
        bootstrap='_CODES='+repr(sorted(SAFE_CODES))+'\n'+BOOTSTRAP
        child=None
        try:
            child=subprocess.Popen(self.ssh.arguments('python3 -I -B -S -c '+shlex.quote(bootstrap)),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,
                env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LC_ALL':'C','SSHPASS':self.ssh.password})
            output,_=child.communicate(packet,timeout=100)
            require(len(output)<=8192,'MANAGEMENT_RESPONSE_LIMIT')
            if child.returncode==5:raise Failure('SSH_AUTH_FAILED')
            if child.returncode==255:raise Failure('SSH_CONNECTION_FAILED')
            value=json.loads(output)
            if child.returncode or value.get('status')!='OK':raise Failure(value.get('code') if value.get('code') in SAFE_CODES else 'MANAGEMENT_RESULT_UNKNOWN')
            return validate(value,payload['operation']=='plan')
        except Failure:raise
        except (OSError,ValueError,subprocess.SubprocessError):raise Failure('SSH_RESULT_UNKNOWN') from None
        finally:
            if child:
                if child.poll()is None:
                    os.killpg(child.pid,signal.SIGTERM)
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
                for stream in (child.stdin,child.stdout):
                    if stream:stream.close()

class GitHub:
    def __init__(self,repo,token):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) and token,'GITHUB_CONFIGURATION_REQUIRED')
        self.repo,self.token=repo,token
    def call(self,path,data=None):
        req=urllib.request.Request('https://api.github.com/repos/'+self.repo+'/'+path,data=None if data is None else json.dumps(data).encode(),
            headers={'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28'})
        try:
            with urllib.request.urlopen(req,timeout=20) as r:
                raw=r.read(1024**2+1);require(len(raw)<=1024**2,'GITHUB_RESPONSE_LIMIT');return json.loads(raw)
        except (urllib.error.URLError,ValueError):raise Failure('GITHUB_STATE_UNAVAILABLE') from None
    def main_checked(self,sha):
        require(re.fullmatch('[a-f0-9]{40}',sha),'MAIN_REQUIRED')
        runs=self.call('actions/runs?head_sha='+sha+'&event=push&per_page=50')['workflow_runs']
        for name in ('Check backend foundation','Check universal installer','Check Studio HTTPS','Check read-only VPS audit tool'):
            selected=sorted((v for v in runs if v['name']==name),key=lambda r:r['id'],reverse=True)
            require(selected and selected[0]['status']=='completed' and selected[0]['conclusion']=='success','MAIN_CHECKS_NOT_SUCCESSFUL')
    def latest(self):
        values=self.call('deployments?environment=studio-telegram&per_page=100')
        if not values:return None
        value=max(values,key=lambda r:r['id'])
        require(value['task']=='studio-telegram','REGISTRY_STATE_INVALID')
        payload=value['payload'];require(type(payload)is dict and set(payload)=={'version','fingerprints'} and payload['version']==1,'REGISTRY_STATE_INVALID')
        validate_fingerprints(payload['fingerprints'])
        states=self.call('deployments/'+str(value['id'])+'/statuses')
        return {'id':value['id'],'fingerprints':payload['fingerprints'],'active':bool(states and max(states,key=lambda r:r['id'])['state']=='success')}
    def reserve(self,sha,fp):
        d=self.call('deployments',{'ref':sha,'task':'studio-telegram','environment':'studio-telegram','auto_merge':False,'required_contexts':[],
            'transient_environment':False,'production_environment':False,'payload':{'version':1,'fingerprints':fp}})
        require(type(d.get('id'))is int,'REGISTRY_STATE_INVALID')
        self.call('deployments/'+str(d['id'])+'/statuses',{'state':'in_progress','auto_inactive':False})
        return d['id']
    def success(self,id):self.call('deployments/'+str(id)+'/statuses',{'state':'success','auto_inactive':True,'description':'Verified private Studio Telegram configuration; no application deploy'})

def permitted(record,planned,operation):
    validate_fingerprints(planned)
    if not record:require(operation=='configure','INITIAL_CONFIGURATION_REQUIRED');return
    old=record['fingerprints'];validate_fingerprints(old)
    require(old['bot']==planned['bot'],'BOT_CHANGED_RELINK_REQUIRED')
    if not record['active']:require(old==planned,'PREVIOUS_CONFIGURATION_OUTCOME_UNKNOWN');return
    if old['instance']!=planned['instance']:
        require(operation=='rotate-token' and old['token']!=planned['token'],'BOT_ALREADY_BOUND_TO_OTHER_INSTANCE')
    elif old['token']!=planned['token']:require(operation=='rotate-token','TOKEN_ROTATION_ACTION_REQUIRED')

def matches(status,fp):
    return all(status[k]==fp[k] for k in FINGERPRINTS) and status['configured'] and status['instanceBound'] and status['botRegistered']

def operate(peer,github,sha,operation,token='',confirmation='',clock=time.monotonic,pause=time.sleep):
    record=github.latest()
    if operation in ('diagnose','bootstrap-owner'):
        status=peer.call({'operation':'diagnose'})
        if operation=='diagnose':
            # Diagnose may complete an interrupted registry write only after
            # observing matching host config, bot identity and live polling.
            if record and not record['active'] and matches(status,record['fingerprints']) and status['workerLive']:github.success(record['id'])
            return {**status,'registryAligned':bool(record and matches(status,record['fingerprints']) and (record['active'] or status['workerLive']))}
        require(record and record['active'] and matches(status,record['fingerprints']) and status['workerLive'],'TELEGRAM_NOT_READY')
        result=peer.call({'operation':'bootstrap','confirmation':confirmation})
        require(result['ownerReady'],'OWNER_CONFIRMATION_NOT_VERIFIED');return result
    plan=peer.call({'operation':'plan','token':token});fp=plan['planned'];permitted(record,fp,operation)
    if record and record['active'] and record['fingerprints']==fp and matches(plan,fp) and plan['workerLive']:return {k:v for k,v in plan.items() if k!='planned'}
    id=record['id'] if record and not record['active'] else github.reserve(sha,fp)
    peer.call({'operation':'configure','token':token,'expected':fp})
    end=clock()+120
    while clock()<end:
        status=peer.call({'operation':'diagnose'})
        require(matches(status,fp),'CONFIGURATION_RESULT_UNKNOWN')
        if status['workerLive']:
            github.success(id);return status
        pause(5)
    raise Failure('WORKER_NOT_READY_CONFIGURATION_PRESERVED')

def main():
    try:
        require(os.environ.get('GITHUB_REF')=='refs/heads/main','MAIN_REQUIRED')
        with open(os.environ['GITHUB_EVENT_PATH'])as f:inputs=json.load(f).get('inputs',{})
        address=server_ip(inputs.get('server_ip',''));print('::add-mask::'+address)
        operation=inputs.get('operation','diagnose');require(operation in OPERATIONS,'INVALID_OPERATION')
        if operation!='diagnose':require(inputs.get('confirmation')==CONFIRM[operation],'CONFIRMATION_REQUIRED')
        password=os.environ.get('STUDIO_SSH_PASSWORD','');require(bool(password),'STUDIO_SSH_PASSWORD_MISSING')
        token=os.environ.get('STUDIO_TELEGRAM_BOT_TOKEN','') if operation in ('configure','rotate-token') else ''
        if operation in ('configure','rotate-token'):require(bool(token),'TELEGRAM_TOKEN_SECRET_MISSING')
        claim=os.environ.get('STUDIO_TELEGRAM_OWNER_CONFIRMATION','') if operation=='bootstrap-owner' else ''
        if operation=='bootstrap-owner':require(bool(claim),'OWNER_CONFIRMATION_SECRET_MISSING')
        github=GitHub(os.environ['GITHUB_REPOSITORY'],os.environ.get('GH_TOKEN',''));github.main_checked(os.environ.get('GITHUB_SHA',''))
        result=operate(Peer(address,password),github,os.environ['GITHUB_SHA'],operation,token,claim)
        safe={k:result[k] for k in BOOLS|COUNTS};safe.update(status='SUCCESS',operation=operation,workerState=result['workerState'])
        if operation=='diagnose':safe['registryAligned']=result['registryAligned']
        text=json.dumps(safe,sort_keys=True);print(text)
    except BaseException as error:
        code=str(error) if isinstance(error,Failure) and str(error) in SAFE_CODES else 'TELEGRAM_OPERATION_FAILED'
        text=json.dumps({'status':'FAILED','code':code,'outcome':'check_actual_state_before_retry'});print(text)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a')as f:f.write('## Studio Telegram\n\n```json\n'+text+'\n```\nNo success claimed. Diagnose the same target after an SSH/registry interruption; recipients/queue are never reset.\n')
        return 1
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a')as f:f.write('## Studio Telegram\n\n```json\n'+text+'\n```\nNo bot token, confirmation code, Telegram user IDs, names or contact data are included. This is technical configuration, not a Studio application deployment.\n')
    return 0
if __name__=='__main__':raise SystemExit(main())
