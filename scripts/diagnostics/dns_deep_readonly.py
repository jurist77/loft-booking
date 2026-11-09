#!/usr/bin/env python3
"""Observational public DNS queries only. No SSH, Secrets, ACME or DNS UPDATE.
CD=1 observations are diagnostics, NEVER a readiness/security acceptance path.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'https'))
from configuration import inputs

TYPES={1:'A',2:'NS',5:'CNAME',6:'SOA',43:'DS',46:'RRSIG',47:'NSEC',48:'DNSKEY',50:'NSEC3',257:'CAA'}
EDE={0:'OTHER',1:'UNSUPPORTED_DNSKEY_ALGORITHM',2:'UNSUPPORTED_DS_DIGEST',3:'STALE_ANSWER',5:'DNSSEC_INDETERMINATE',6:'DNSSEC_BOGUS',7:'SIGNATURE_EXPIRED',8:'SIGNATURE_NOT_YET_VALID',9:'DNSKEY_MISSING',10:'RRSIG_MISSING',11:'NO_ZONE_KEY',12:'NSEC_MISSING',13:'CACHED_ERROR',14:'NOT_READY',15:'BLOCKED',16:'CENSORED',17:'FILTERED',18:'PROHIBITED',19:'STALE_NXDOMAIN',20:'NOT_AUTHORITATIVE',21:'NOT_SUPPORTED',22:'NO_REACHABLE_AUTHORITY',23:'NETWORK_ERROR',24:'INVALID_DATA'}
DOH={'GOOGLE':'https://dns.google/dns-query','CLOUDFLARE':'https://cloudflare-dns.com/dns-query','QUAD9':'https://dns.quad9.net/dns-query','OPENDNS':'https://doh.opendns.com/dns-query'}
RECURSIVE={'GOOGLE':'8.8.8.8','CLOUDFLARE':'1.1.1.1','QUAD9':'9.9.9.9','OPENDNS':'208.67.222.222'}
ROWS=[]


def safe_detail(text):
    value=text.lower()
    tokens=[label for word,label in (('dnssec','DNSSEC'),('notimp','NOTIMP'),('refused','REFUSED'),('timeout','TIMEOUT'),('timed out','TIMEOUT'),('no reachable','NO_REACHABLE_AUTHORITY'),('network error','NETWORK_ERROR'),('validation failure','VALIDATION_FAILURE'),('invalid data','INVALID_DATA'),('format error','FORMAT_ERROR')) if word in value]
    return {'classes':sorted(set(tokens)) or ['UNCLASSIFIED'],'text_sha256':hashlib.sha256(text.encode()).hexdigest()[:16]}


def packet(name,kind,cd=False,rd=True,edns=True):
    # DNS QUERY opcode 0 only. No AXFR/UPDATE/registration operations.
    assert kind in TYPES and kind not in (5,46,47,50)
    ident=secrets.randbelow(65536)
    q=struct.pack('!6H',ident,(0x100 if rd else 0)|(0x10 if cd else 0),1,0,0,int(edns))
    q+=b''.join(bytes([len(label)])+label.encode('ascii') for label in name.rstrip('.').split('.') if label)+b'\0'+struct.pack('!HH',kind,1)
    if edns:q+=b'\0'+struct.pack('!HHIH',41,1232,0x8000,0)
    return q


def parse(raw):
    if len(raw)<12:raise ValueError('SHORT_DNS')
    ident,flags,qd,an,ns,ar=struct.unpack_from('!6H',raw)
    def name(pos):
        parts=[];end=None;seen=set()
        for _ in range(80):
            if pos in seen or pos>=len(raw):raise ValueError('BAD_DNS_NAME')
            seen.add(pos);n=raw[pos];pos+=1
            if n&0xc0==0xc0:
                if pos>=len(raw):raise ValueError('BAD_DNS_POINTER')
                target=((n&63)<<8)|raw[pos]
                if end is None:end=pos+1
                pos=target;continue
            if n&0xc0 or n>63 or pos+n>len(raw):raise ValueError('BAD_DNS_LABEL')
            if n==0:return '.'.join(parts)+'.',end if end is not None else pos
            parts.append(raw[pos:pos+n].decode('ascii',errors='replace'));pos+=n
        raise ValueError('DNS_NAME_LIMIT')
    pos=12;questions=[]
    if qd>4 or an+ns+ar>256:raise ValueError('DNS_RECORD_LIMIT')
    for _ in range(qd):
        label,pos=name(pos);kind,cls=struct.unpack_from('!HH',raw,pos);pos+=4;questions.append((label.lower().rstrip('.'),kind))
    records=[];errors=[]
    for section,count in (('ANSWER',an),('AUTHORITY',ns),('ADDITIONAL',ar)):
        for _ in range(count):
            label,pos=name(pos);kind,cls,ttl,length=struct.unpack_from('!HHIH',raw,pos);pos+=10;end=pos+length
            if end>len(raw):raise ValueError('DNS_RDATA_TRUNCATED')
            data=raw[pos:end];item={'section':section,'type':TYPES.get(kind,str(kind))}
            if kind in (2,5):item['name']=name(pos)[0]
            elif kind==1 and length==4:item['_address']=socket.inet_ntop(socket.AF_INET,data)
            elif kind==43 and length>=4:item.update(key_tag=int.from_bytes(data[:2],'big'),algorithm=data[2],digest_type=data[3])
            elif kind==48 and length>=4:item.update(flags=int.from_bytes(data[:2],'big'),protocol=data[2],algorithm=data[3],key_hash=hashlib.sha256(data).hexdigest()[:16])
            elif kind==46 and length>=2:item['covers']=TYPES.get(int.from_bytes(data[:2],'big'),str(int.from_bytes(data[:2],'big')))
            elif kind==257 and length>=2 and data[1]+2<=length:
                tag=data[2:2+data[1]].decode('ascii',errors='replace');value=data[2+data[1]:].decode(errors='replace')
                item.update(flags=data[0],tag=tag if re.fullmatch('[A-Za-z0-9]{1,15}',tag) else 'INVALID',issuer_le=value.split(';')[0].strip()=='letsencrypt.org',parameters_present=';' in value)
            elif kind==41:
                at=0
                while at+4<=len(data):
                    option,size=struct.unpack_from('!HH',data,at);at+=4
                    if at+size>len(data):raise ValueError('BAD_EDNS_OPTION')
                    if option==15 and size>=2:
                        code=int.from_bytes(data[at:at+2],'big');errors.append({'code':code,'name':EDE.get(code,'OTHER_CODE'),**safe_detail(data[at+2:at+size].decode(errors='replace'))})
                    at+=size
            records.append(item);pos=end
    return {'id':ident,'rcode':flags&15,'ad':bool(flags&32),'cd':bool(flags&16),'aa':bool(flags&0x400),'tc':bool(flags&0x200),'ede':errors,'questions':questions,'records':records}


def http(url,accept):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):raise ValueError('REDIRECT_REFUSED')
    with urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(url,headers={'Accept':accept}),timeout=5) as r:
        data=r.read(65537)
        if r.status!=200 or len(data)>65536:raise ValueError('HTTP_RESPONSE_INVALID')
        return data


def ask(name,kind,provider,cd=False,transport='DOH',address=None,rd=True,edns=True):
    row={'provider':provider,'qname':name,'type':TYPES[kind],'cd_requested':int(cd),'purpose':'DIAGNOSTIC_ONLY','transport':transport,'edns_do':edns}
    try:
        q=packet(name,kind,cd,rd,edns)
        if transport=='DOH':
            url=DOH[provider]+'?dns='+base64.urlsafe_b64encode(q).rstrip(b'=').decode()
            raw=http(url,'application/dns-message')
        else:
            ip=ipaddress.ip_address(address)
            if not ip.is_global:raise ValueError('NONPUBLIC_DNS_TARGET')
            family=socket.AF_INET6 if ip.version==6 else socket.AF_INET
            with socket.socket(family,socket.SOCK_DGRAM if transport=='UDP' else socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                if transport=='UDP':
                    sock.connect((address,53));sock.send(q);raw=sock.recv(65536)
                else:
                    sock.connect((address,53));sock.sendall(struct.pack('!H',len(q))+q)
                    def exact(n):
                        data=b''
                        while len(data)<n:
                            more=sock.recv(n-len(data))
                            if not more:raise ValueError('DNS_TCP_EOF')
                            data+=more
                        return data
                    raw=exact(int.from_bytes(exact(2),'big'))
        result=parse(raw)
        if result['id']!=int.from_bytes(q[:2],'big') or result['questions']!=[(name.lower().rstrip('.'),kind)]:raise ValueError('DNS_RESPONSE_MISMATCH')
        row.update({k:result[k] for k in ('rcode','ad','cd','aa','tc','ede')});row['status']='RECEIVED'
        row['_records']=result['records']
        row['records']=[{k:v for k,v in item.items() if k!='_address'} for item in result['records']]
    except urllib.error.HTTPError as e:row['status']='HTTP_'+str(e.code)
    except (TimeoutError,socket.timeout):row['status']='TIMEOUT'
    except urllib.error.URLError:row['status']='HTTP_TRANSPORT_OR_TLS_ERROR'
    except OSError:row['status']='NETWORK_ERROR'
    except (ValueError,struct.error):row['status']='INVALID_RESPONSE'
    return row


def google_json(host,cd):
    row={'provider':'GOOGLE_JSON','qname':host,'type':'CAA','cd_requested':int(cd),'purpose':'DIAGNOSTIC_ONLY'}
    try:
        data=json.loads(http('https://dns.google/resolve?'+urllib.parse.urlencode({'name':host,'type':257,'do':1,'cd':int(cd)}),'application/dns-json'))
        row.update(status='RECEIVED',rcode=data.get('Status'),ad=data.get('AD'),cd=data.get('CD'),answer_count=len(data.get('Answer') or []))
        row['comment']=safe_detail(data['Comment']) if isinstance(data.get('Comment'),str) else {'classes':['NOT_PROVIDED']}
    except Exception:row['status']='FAILED'
    return row


def emit(row,expected):
    addresses=[x['_address'] for x in row.pop('_records',[]) if x.get('_address')]
    if row['type']=='A':row['expected_ipv4_match']=expected in addresses
    ROWS.append(row)
    print(json.dumps(row,sort_keys=True),flush=True)


def main():
    with open(os.environ['GITHUB_EVENT_PATH']) as stream:raw=json.load(stream)['inputs']
    options=inputs({**raw,'mode':'check','confirmation':''});host=options['hostname'];expected=options['addresses'][0]
    targets=[(host,257,cd) for cd in (False,True)]+[('duckdns.org',kind,False) for kind in (2,43,48)]+[(name,1,cd) for name in ('cloudflare.com','dnssec-failed.org') for cd in (False,True)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(ask,name,kind,provider,cd) for provider in DOH for name,kind,cd in targets]
        for future in futures:emit(future.result(),expected)
    for cd in (False,True):emit(google_json(host,cd),expected)
    # Public recursive UDP/TCP controls independently test validation and DoH availability.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(ask,name,kind,provider,cd,transport,ip) for provider,ip in RECURSIVE.items() for transport in ('UDP','TCP') for name,kind,cd in ((host,257,False),('dnssec-failed.org',1,False),(host,257,True))]
        for future in futures:emit(future.result(),expected)
    # Compare only public DNS records for a small fixed sample; never visit sites.
    samples=['test.duckdns.org','demo.duckdns.org','www.duckdns.org']
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(ask,name,kind,provider) for name in samples for provider in DOH for kind in (1,257)]
        for future in futures:emit(future.result(),expected)
    # Discover zone NS from the actual replies, not assumed provider hostnames.
    ns=sorted({item['name'].rstrip('.') for row in ROWS if row.get('qname')=='duckdns.org' and row.get('type')=='NS' and row.get('rcode')==0 for item in row.get('records',[]) if item['section']=='ANSWER' and item['type']=='NS'})
    print('AUTHORITATIVE_NS_COUNT='+str(len(ns)),flush=True)
    for server in ns[:12]:
        found=ask(server,1,'GOOGLE')
        if found.get('rcode')!=0:found=ask(server,1,'CLOUDFLARE')
        addresses=[r['_address'] for r in found.get('_records',[]) if r.get('_address')]
        for address in addresses[:1]:
            if address in options['addresses']:print('AUTHORITY_EQUALS_VPS_SKIPPED',flush=True);continue
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures=[pool.submit(ask,name,kind,'AUTH:'+server,False,transport,address,False,edns) for name,kind in ((host,257),('duckdns.org',48)) for transport,edns in (('UDP',True),('TCP',True),('UDP',False),('TCP',False))]
                for future in futures:emit(future.result(),expected)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:
            stream.write('## Read-only DNS investigation\n\nCD=1 is diagnostics only and NEVER grants readiness. No SSH/Secrets/VPS/ACME/DNS UPDATE/apply. No production security policy changed.\n\n```json\n'+json.dumps(ROWS,indent=2)+'\n```\n')


if __name__=='__main__':main()
