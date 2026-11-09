"""Actual failure replay and isolated DoH/summary safety, never real DNS/SSH."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/https'))
import checks
import dns_check

HOST='fixture.duckdns.org';IP='192.0.2.10';CANARY='SYNTHETIC_SECRET_AND_PRIVATE_ADDRESS_DO_NOT_LOG'


def query(url):
    parsed=urllib.parse.urlparse(url);q=urllib.parse.parse_qs(parsed.query)
    return ('GOOGLE' if parsed.netloc=='dns.google' else 'CLOUDFLARE',q['name'][0],int(q['type'][0]))


def response(url,*args):
    provider,name,kind=query(url)
    data={'Status':0,'Question':[{'name':name+'.' if name!='.' else '.','type':kind}]}
    if kind==1:data['Answer']=[{'name':name+'.','type':1,'data':IP}]
    return data,{}


class DnsTests(unittest.TestCase):
    def setUp(self):
        self.sleep=patch.object(checks.time,'sleep');self.sleep.start();self.addCleanup(self.sleep.stop)

    def test_provider_independent_hierarchy_includes_every_parent_and_root(self):
        for host,names in (
            ('fixture.dynv6.net',['fixture.dynv6.net','dynv6.net','net','.']),
            ('booking.space.example.co.uk',['booking.space.example.co.uk','space.example.co.uk','example.co.uk','co.uk','uk','.']),
            ('example.com',['example.com','com','.']),
            (HOST,[HOST,'duckdns.org','org','.'])):
            seen=[]
            def fetch(url,*args):seen.append(query(url));return response(url)
            self.assertTrue(checks.dns_records(host,[IP],fetch))
            self.assertEqual([n for _,n in checks.caa_hierarchy(host)],names)
            for provider in ('GOOGLE','CLOUDFLARE'):
                self.assertEqual([name for p,name,k in seen if p==provider and k==257],names)

    def test_intermediate_caa_cannot_be_skipped_or_overridden_by_ancestor(self):
        host='booking.space.example.co.uk'
        for level in [name for _,name in checks.caa_hierarchy(host)]:
            for provider in ('GOOGLE','CLOUDFLARE'):
                for fault in ('denied','servfail','irrelevant-a'):
                    seen=[]
                    def fetch(url,*args):
                        data,headers=response(url);key=query(url);seen.append(key)
                        if key==(provider,level,257):
                            if fault=='servfail':data['Status']=2
                            else:data['Answer']=[{'name':level,'type':1 if fault=='irrelevant-a' else 257,'data':IP if fault=='irrelevant-a' else '0 issue "other.example"'}]
                        return data,headers
                    with self.subTest(level=level,provider=provider,fault=fault),self.assertRaises(checks.HttpsError):
                        checks.dns_records(host,[IP],fetch)
                    self.assertTrue(any(p!=provider and k==257 for p,n,k in seen))

    def test_nearest_policy_stops_required_walk_but_diagnostics_still_use_real_ancestors(self):
        host='booking.space.example.co.uk';seen=[]
        def fetch(url,*args):
            data,headers=response(url);p,name,k=query(url);seen.append((p,name,k))
            if k==257:
                if name=='space.example.co.uk':data['Answer']=[{'name':name,'type':257,'data':'0 issue "letsencrypt.org"'}]
                elif name=='example.co.uk':data['Status']=2
            return data,headers
        rows,outcome,ok=dns_check.run(host,[IP],fetch)
        self.assertTrue(ok);self.assertEqual(outcome,'DNS_CHECK_PASSED')
        for provider in ('GOOGLE','CLOUDFLARE'):
            self.assertEqual([name for p,name,k in seen if p==provider and k==257],
                             [host,'space.example.co.uk','example.co.uk','example.co.uk','co.uk','uk','.'])
        self.assertTrue(all(r['use']=='DIAGNOSTIC' for r in rows if r.get('result')=='SERVFAIL'))

    def test_dnssec_is_explicitly_enabled_and_disabled_or_malformed_cd_is_rejected(self):
        seen=[]
        def fetch(url,*args):
            params=urllib.parse.parse_qs(urllib.parse.urlparse(url).query);seen.append(params)
            return response(url)
        self.assertTrue(checks.dns_records('fixture.dynv6.net',[IP],fetch))
        self.assertTrue(all(p['cd']==['false'] and p['do']==['true'] for p in seen))
        for cd in (True,'false',0,None):
            def invalid(url,*args):
                data,headers=response(url);data['CD']=cd;return data,headers
            with self.assertRaisesRegex(checks.HttpsError,'DNSSEC_CHECKING_DISABLED'):
                checks.dns_records('fixture.dynv6.net',[IP],invalid)

    def test_replay_google_host_caa_servfail_cloudflare_nodata_never_passes(self):
        seen=[];rows=[]
        def fetch(url,*args):
            key=query(url);seen.append(key);data,headers=response(url)
            if key==('GOOGLE',HOST,257):data['Status']=2
            return data,headers
        with self.assertRaisesRegex(checks.HttpsError,'^DNS_GOOGLE_HOST_CAA_SERVFAIL$'):
            checks.dns_records(HOST,[IP],fetch,rows)
        self.assertEqual(seen.count(('GOOGLE',HOST,257)),2)
        self.assertIn(('CLOUDFLARE','.',257),seen)
        self.assertEqual(len([r for r in rows if r.get('result')=='IP_MATCH']),2)
        failures=[r for r in rows if r.get('result')=='SERVFAIL']
        self.assertEqual([r['http'] for r in failures],['HTTP_200','HTTP_200'])
        self.assertEqual([r['dns'] for r in failures],['RCODE_2','RCODE_2'])
        self.assertNotIn(CANARY,checks.dns_report(rows))

    def test_absent_or_empty_aaaa_and_caa_are_valid_only_with_noerror(self):
        for empty in ('missing','empty'):
            def fetch(url,*args):
                data,headers=response(url)
                if query(url)[2]!=1 and empty=='empty':data['Answer']=[]
                return data,headers
            rows=[];self.assertTrue(checks.dns_records(HOST,[IP],fetch,rows))
            self.assertEqual(len([r for r in rows if r.get('result')=='CAA_ALLOWED']),2)
            self.assertTrue(any(r.get('result')=='NODATA' and r['type']=='AAAA' for r in rows))

    def test_both_resolvers_and_all_record_types_checked_after_address_failure(self):
        seen=[]
        def fetch(url,*args):
            key=query(url);seen.append(key)
            if key==('GOOGLE',HOST,1):raise urllib.error.HTTPError(url,403,CANARY,None,None)
            return response(url)
        with self.assertRaisesRegex(checks.HttpsError,'^DNS_GOOGLE_HOST_A_HTTP_403$'):checks.dns_records(HOST,[IP],fetch)
        for provider in ('GOOGLE','CLOUDFLARE'):
            for kind in (1,28,257):self.assertIn((provider,HOST,kind),seen)

    def test_transient_servfail_requires_fresh_successful_answer_before_passing(self):
        calls=0;rows=[]
        def fetch(url,*args):
            nonlocal calls
            data,headers=response(url)
            if query(url)==('GOOGLE',HOST,257):
                calls+=1
                if calls==1:data['Status']=2
            return data,headers
        self.assertTrue(checks.dns_records(HOST,[IP],fetch,rows));self.assertEqual(calls,2)
        self.assertEqual(len([r for r in rows if r.get('result')=='SERVFAIL']),1)

    def test_http_failures_timeouts_tls_json_and_oversize_have_distinct_safe_codes(self):
        cases=[(lambda u:urllib.error.HTTPError(u,503,CANARY,None,None),'HTTP_503',2),
               (lambda u:urllib.error.HTTPError(u,429,CANARY,None,None),'HTTP_429',2),
               (lambda u:urllib.error.HTTPError(u,404,CANARY,None,None),'HTTP_404',1),
               (lambda u:TimeoutError(CANARY),'TIMEOUT',2),
               (lambda u:urllib.error.URLError(socket.timeout(CANARY)),'TIMEOUT',2),
               (lambda u:urllib.error.URLError(ssl.SSLError(CANARY)),'TLS_ERROR',1),
               (lambda u:urllib.error.URLError(CANARY),'TRANSPORT_ERROR',2),
               (lambda u:json.JSONDecodeError(CANARY,'',0),'INVALID_JSON',1),
               (lambda u:checks.HttpsError('RESPONSE_TOO_LARGE'),'RESPONSE_TOO_LARGE',1),
               (lambda u:checks.HttpsError('REDIRECT_REFUSED'),'REDIRECT_REFUSED',1)]
        for factory,code,count in cases:
            with self.subTest(code=code):
                rows=[];calls=[]
                def fetch(url,*args):calls.append(url);raise factory(url)
                probe=checks.DnsQueries(fetch,rows)
                with self.assertRaisesRegex(checks.HttpsError,'^DNS_GOOGLE_HOST_CAA_'+code+'$'):probe.query('GOOGLE','HOST',HOST,257)
                self.assertEqual(len(calls),count);self.assertNotIn(CANARY,checks.dns_report(rows))

    def test_retry_after_is_honored_or_no_retry_is_sent(self):
        for header,calls,wait in (("3",2,3),("120",1,None),("invalid",1,None)):
            fetch=Mock(side_effect=urllib.error.HTTPError("https://dns.google/resolve",429,CANARY,{"Retry-After":header},None))
            sleep=Mock();probe=checks.DnsQueries(fetch,sleep=sleep)
            with self.assertRaisesRegex(checks.HttpsError,"HTTP_429"):probe.query("GOOGLE","HOST",HOST,257)
            self.assertEqual(fetch.call_count,calls)
            if wait is None:sleep.assert_not_called()
            else:sleep.assert_called_once_with(wait)

    def test_dns_rcodes_and_malformed_responses_are_not_nodata(self):
        cases=[({'Status':3},'NXDOMAIN'),({'Status':5},'REFUSED'),({'Status':4},'NOTIMP'),
               ({},'STATUS_MISSING'),({'Status':True},'STATUS_INVALID'),({'Status':None},'STATUS_INVALID'),
               ({'Status':0,'TC':True},'TRUNCATED'),({'Status':0,'TC':'false'},'TRUNCATION_INVALID'),
               ({'Status':0,'Answer':None},'ANSWER_NULL'),({'Status':0,'Answer':{}},'ANSWER_NOT_ARRAY'),
               ({'Status':0,'Answer':[{}]*17},'ANSWER_LIMIT'),([], 'JSON_NOT_OBJECT'),
               ({'Status':0,'Question':[{'name':'other.example','type':257}]},'QUESTION_MISMATCH'),
               ({'Status':0,'Answer':[{'name':HOST,'type':5,'data':CANARY}]},'DNS_ALIAS_OR_UNEXPECTED_ANSWER')]
        for payload,code in cases:
            with self.subTest(code=code):
                rows=[];probe=checks.DnsQueries(lambda *a:(payload,{}),rows)
                with self.assertRaisesRegex(checks.HttpsError,'^DNS_GOOGLE_HOST_CAA_'+code+'$'):probe.query('GOOGLE','HOST',HOST,257)
                self.assertNotIn(CANARY,checks.dns_report(rows))

    def test_ip_mismatch_on_either_resolver_or_unexpected_aaaa_still_blocks(self):
        for provider in ('GOOGLE','CLOUDFLARE'):
            def fetch(url,*args):
                data,headers=response(url)
                if query(url)==(provider,HOST,1):data['Answer'][0]['data']='192.0.2.11'
                return data,headers
            with self.assertRaisesRegex(checks.HttpsError,'DNS_'+provider+'_HOST_DNS_ADDRESS_MISMATCH'):checks.dns_records(HOST,[IP],fetch)
        def ipv6(url,*args):
            data,headers=response(url)
            if query(url)[2]==28:data['Answer']=[{'type':28,'name':HOST,'data':'2001:db8::1'}]
            return data,headers
        with self.assertRaisesRegex(checks.HttpsError,'DNS_ADDRESS_MISMATCH'):checks.dns_records(HOST,[IP],ipv6)

    def test_nearest_caa_inheritance_denial_and_critical_flags_remain_enforced(self):
        for policy,allowed in (('0 issue "letsencrypt.org"',True),('0 issue "other.example"',False),
                               ('0 issue "letsencrypt.org; accounturi=restricted"',False),('128 unknown "x"',False),('256 issue "letsencrypt.org"',False)):
            def fetch(url,*args):
                data,headers=response(url);provider,name,kind=query(url)
                if kind==257 and name=='duckdns.org':data['Answer']=[{'name':name,'type':257,'data':policy}]
                return data,headers
            if allowed:self.assertTrue(checks.dns_records(HOST,[IP],fetch))
            else:
                with self.assertRaises(checks.HttpsError):checks.dns_records(HOST,[IP],fetch)
        def nearest(url,*args):
            data,headers=response(url);_,name,kind=query(url)
            if kind==257:data['Answer']=[{'name':name,'type':257,'data':'0 issue "letsencrypt.org"' if name==HOST else '0 issue "other.example"'}]
            return data,headers
        self.assertTrue(checks.dns_records(HOST,[IP],nearest))

    def test_expired_total_budget_stops_requests_and_never_passes_single_resolver(self):
        fetch=Mock();rows=[];probe=checks.DnsQueries(fetch,rows);probe.end=0
        with self.assertRaisesRegex(checks.HttpsError,'TOTAL_TIMEOUT'):probe.verify(HOST,[IP])
        fetch.assert_not_called();self.assertTrue(any(r['resolver']=='CLOUDFLARE' for r in rows))

    def test_report_never_prints_untrusted_fields_names_addresses_or_raw_errors(self):
        rows=[dict.fromkeys(('resolver','scope','type','attempt','http','dns','answer','result'),value) for value in (CANARY,CANARY+'\n| <script>')]
        report=checks.dns_report(rows);self.assertNotIn(CANARY,report);self.assertIn('REDACTED',report)
        rows,outcome,success=dns_check.run(HOST,[IP],response)
        self.assertTrue(success);self.assertEqual(outcome,'DNS_CHECK_PASSED')
        self.assertNotIn(HOST,checks.dns_report(rows));self.assertNotIn(IP,checks.dns_report(rows))

    def test_manage_check_failure_writes_summary_and_never_starts_ssh(self):
        import workflow
        with tempfile.TemporaryDirectory() as folder,contextlib.ExitStack() as stack:
            event=Path(folder)/'event.json';summary=Path(folder)/'summary.md'
            event.write_text(json.dumps({'inputs':{'server_ip':'8.8.8.8','hostname':HOST,'mode':'check'}}))
            stack.enter_context(patch.dict(os.environ,{'GITHUB_EVENT_PATH':str(event),'GITHUB_STEP_SUMMARY':str(summary),'STUDIO_SSH_PASSWORD':CANARY}))
            stack.enter_context(patch.object(workflow,'verified_main'))
            ssh=stack.enter_context(patch.object(workflow,'SSH'))
            original=checks.dns_records
            def fail(host,addresses,diagnostics=None):
                def fetch(url,*args):
                    data,headers=response(url)
                    if query(url)==('GOOGLE',HOST,257):data['Status']=2
                    if query(url)[2]==1:data['Answer'][0]['data']='8.8.8.8'
                    return data,headers
                return original(host,addresses,fetch,diagnostics)
            stack.enter_context(patch.object(workflow,'dns_records',side_effect=fail))
            output=stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(workflow.main(),1);ssh.assert_not_called()
            text=summary.read_text();self.assertIn('DNS_GOOGLE_HOST_CAA_SERVFAIL',text);self.assertIn('CLOUDFLARE',text)
            self.assertNotIn(CANARY,text);self.assertNotIn(HOST,text);self.assertNotIn('8.8.8.8',text)


if __name__=='__main__':unittest.main()
