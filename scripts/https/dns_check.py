#!/usr/bin/env python3
"""Public DNS-only check: no SSH, Secrets, VPS connection or DNS writes."""
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
from configuration import inputs
from checks import dns_records, fetch_json

PROVIDERS=(('GOOGLE','https://dns.google/resolve'),('CLOUDFLARE','https://cloudflare-dns.com/dns-query'))


def error_code(error):
    if isinstance(error,urllib.error.HTTPError):return 'HTTP_'+str(error.code) if 100<=error.code<=599 else 'HTTP_ERROR'
    if isinstance(error,(TimeoutError,socket.timeout)):return 'TIMEOUT'
    if isinstance(error,urllib.error.URLError):
        if isinstance(error.reason,(TimeoutError,socket.timeout)):return 'TIMEOUT'
        if isinstance(error.reason,ssl.SSLError):return 'TLS_ERROR'
        return 'TRANSPORT_ERROR'
    if isinstance(error,json.JSONDecodeError):return 'INVALID_JSON'
    return 'UNEXPECTED_RESPONSE'


def run(host,addresses,fetch=fetch_json):
    cache={};rows=[]
    for provider,endpoint in PROVIDERS:
        queries=[('HOST','A',host,1),('HOST','AAAA',host,28),*((scope,'CAA',name,257) for scope,name in (('HOST',host),('PARENT','duckdns.org'),('TLD','org'),('ROOT','.')))]
        for scope,kind,name,number in queries:
            url=endpoint+'?'+urllib.parse.urlencode({'name':name,'type':number})
            row={'resolver':provider,'scope':scope,'type':kind}
            try:
                data,headers=fetch(url,'application/dns-json');cache[url]=(data,headers)
                row['http']='HTTP_200'
                if not isinstance(data,dict):row['result']='JSON_NOT_OBJECT'
                else:
                    status=data.get('Status');row['dns']=('STATUS_'+str(status)) if type(status) is int and 0<=status<=4095 else 'STATUS_INVALID'
                    answer=data.get('Answer',[])
                    row['answer']='MISSING' if 'Answer' not in data else 'EMPTY' if answer==[] else 'NULL' if answer is None else 'RECORDS' if isinstance(answer,list) else 'INVALID'
                    row['truncated']='YES' if data.get('TC') is True else 'NO' if data.get('TC',False) is False else 'INVALID'
                    row['result']='DNS_RESPONSE'
            except Exception as error:
                cache[url]=error;row['result']=error_code(error)
            rows.append(row)
    def cached(url,*args):
        value=cache[url]
        if isinstance(value,Exception):raise value
        return value
    try:dns_records(host,addresses,fetch=cached);outcome='DNS_CHECK_PASSED';success=True
    except Exception:outcome='DNS_CHECK_FAILED';success=False
    return rows,outcome,success


def render(rows,outcome):
    result='## Studio public DNS-only check\n\n| Resolver | Scope | Type | HTTP | DNS | Answer | Truncated | Result |\n|---|---|---|---|---|---|---|---|\n'
    for r in rows:result+='| '+' | '.join(r.get(k,'—') for k in ('resolver','scope','type','http','dns','answer','truncated','result'))+' |\n'
    return result+'\n'+outcome+'\n\nNo SSH, Secrets, VPS connection, ACME issuance, DNS/firewall writes or apply. Only public DNS was queried; names, addresses and raw responses are omitted.\n'


def main():
    try:
        with open(os.environ['GITHUB_EVENT_PATH']) as stream:raw=json.load(stream)['inputs']
        normalized=inputs({**raw,'mode':'check','confirmation':''})
        rows,outcome,success=run(normalized['hostname'],normalized['addresses'])
        report=render(rows,outcome);print(report)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:stream.write(report)
        return 0 if success else 1
    except Exception:
        print('DNS_CHECK_INPUT_OR_REPORT_FAILED');return 1


if __name__=='__main__':raise SystemExit(main())
