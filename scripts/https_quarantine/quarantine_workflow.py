#!/usr/bin/env python3
"""Manual one-case workflow runner. Never dispatched automatically or by CI."""
import json
import os
from pathlib import Path
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent/'diagnostics'),str(HERE.parent/'installer')]
from deploy import SSH, DeployError, server_ip
from https_readiness import payload as readonly_payload
from probe_studio_network import read_health
from quarantine_host import CONFIRM, Q_CODES, Q_PHASES


def options(raw):
    if not isinstance(raw,dict) or set(raw)-{'server_ip','mode','confirmation'}:raise ValueError('INVALID_INPUT')
    address=server_ip(raw.get('server_ip',''))
    mode=raw.get('mode','check');confirmation=raw.get('confirmation','')
    if mode not in ('check','quarantine'):raise ValueError('INVALID_MODE')
    if mode=='quarantine' and confirmation!=CONFIRM:raise ValueError('CONFIRMATION_REQUIRED')
    if mode=='check' and confirmation!='':raise ValueError('CHECK_CONFIRMATION_MUST_BE_EMPTY')
    return address,mode,confirmation


def payload(mode,confirmation):
    # Existing reviewed diagnostic definitions only; do not run its final collect.
    source=readonly_payload().decode().rsplit('\ntry: print(json.dumps(collect()',1)[0]
    source+='\n'+(HERE/'quarantine_host.py').read_text()
    source+='\nos.umask(0o077)\n'
    source+='\ndef _q_timeout(*args): raise TimeoutError()\nsignal.signal(signal.SIGALRM,_q_timeout)\nsignal.alarm(360)\n'
    source+='\ntry:\n _qresult=quarantine_once('+repr(mode)+','+repr(confirmation)+',QuarantineOps(TLS_RESIDUE_REFERENCE))\nexcept BaseException:\n _qresult={"status":"MANUAL_REVIEW_REQUIRED","code":"OPERATION_FAILED","phase":"VALIDATE","moved":0,"identity_steps":0,"health":False,"changed":True}\n'
    source+='\nsignal.alarm(0)\nprint(json.dumps(_qresult,sort_keys=True))\n'
    return source.encode()


def validate(value):
    if not isinstance(value,dict) or set(value)!={'status','code','phase','moved','identity_steps','health','changed'}:raise ValueError()
    if value['status'] not in ('BLOCKED','READY','SUCCESS','MANUAL_REVIEW_REQUIRED'):raise ValueError()
    if value['code'] not in Q_CODES or value['phase'] not in Q_PHASES:raise ValueError()
    if type(value['moved']) is not int or not 0<=value['moved']<=3 or type(value['identity_steps']) is not int or not 0<=value['identity_steps']<=2:raise ValueError()
    if type(value['health']) is not bool or type(value['changed']) is not bool:raise ValueError()
    if value['status']=='SUCCESS' and not (value['code']=='DONE' and value['phase']=='COMPLETE' and value['moved']==3 and value['identity_steps']==2 and value['health'] and value['changed']):raise ValueError()
    if value['status']=='READY' and not (value['code']=='READY' and value['phase']=='PROVE' and value['health'] and not value['changed'] and value['moved']==value['identity_steps']==0):raise ValueError()
    if value['status']=='BLOCKED' and (value['changed'] or value['moved'] or value['identity_steps']):raise ValueError()
    if value['status']=='MANUAL_REVIEW_REQUIRED' and not value['changed']:raise ValueError()
    return value


def run(address,mode,confirmation,password,ssh_factory=SSH,health=read_health):
    # Public Studio health only; never create a booking or send contacts.
    before=health(address,3000)
    if before!={'http':200,'ok':True,'error':'none'}:
        return {'status':'BLOCKED','code':'EXTERNAL_HEALTH_FAILED','changes':'none','external_health':False}
    try:
        ssh=ssh_factory(address,password)
        with tempfile.TemporaryFile('w+b') as source:
            source.write(payload(mode,confirmation));source.seek(0)
            result=validate(ssh.execute('python3 -I -B -S -',source,timeout=420))
        if (mode=='check' and result['status']=='SUCCESS') or (mode=='quarantine' and result['status']=='READY'):raise ValueError()
        external=health(address,3000)=={'http':200,'ok':True,'error':'none'}
        if result['status']=='SUCCESS' and not external:result.update(status='MANUAL_REVIEW_REQUIRED',code='EXTERNAL_POSTCHECK_FAILED')
        return {**result,'external_health':external}
    except DeployError as error:
        if str(error) in ('SSH_AUTH_FAILED','SSH_TOOLS_MISSING','SSH_STREAM_UNSUPPORTED'):
            return {'status':'BLOCKED','code':str(error),'changes':'none','external_health':False}
        return {'status':'OUTCOME_UNKNOWN_MANUAL_REVIEW' if mode=='quarantine' else 'BLOCKED',
                'code':'SSH_OR_PROTOCOL_FAILED','changes':'unknown' if mode=='quarantine' else 'none','external_health':False}
    except Exception:
        # A lost response can follow a successful rename. No automatic retry.
        return {'status':'OUTCOME_UNKNOWN_MANUAL_REVIEW' if mode=='quarantine' else 'BLOCKED',
                'code':'SSH_OR_PROTOCOL_FAILED','changes':'unknown' if mode=='quarantine' else 'none','external_health':False}


def emit(value):
    text=json.dumps(value,sort_keys=True)
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as output:
            output.write('## One-time Studio TLS quarantine\n\n```json\n'+text+'\n```\n\nCounts are confirmed completions; a failed/unknown operation may have completed its last journal intent. Preserve all quarantine files and inspect privately. No automatic rollback, retry, apply or deletion.\n')


def main():
    try:
        if os.environ.get('GITHUB_REF')!='refs/heads/main':raise ValueError('MAIN_REQUIRED')
        with open(os.environ['GITHUB_EVENT_PATH'],'rb') as source:data=source.read(1024*1024+1)
        if len(data)>1024*1024:raise ValueError('INVALID_INPUT')
        address,mode,confirmation=options(json.loads(data).get('inputs',{}))
        password=os.environ.get('STUDIO_SSH_PASSWORD','')
        if not password:raise ValueError('PASSWORD_MISSING')
        result=run(address,mode,confirmation,password);emit(result)
        return 0 if result['status'] in ('READY','SUCCESS') else 1
    except Exception:
        emit({'status':'BLOCKED','code':'INVALID_INPUT_OR_ENVIRONMENT','changes':'none','external_health':False});return 1


if __name__=='__main__':raise SystemExit(main())
