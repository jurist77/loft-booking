"""Read-only interface parsing. All addresses in fixtures are synthetic test data.

The real ip command is read without logging its output or address values.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_https as f
import test_check_phases as c
from test_check_phases import options
from phase_report import interface_report

PUBLIC='8.8.8.8'
IPV6='2606:4700:4700::1111'
CANARY='SYNTHETIC_PRIVATE_ADDRESS_PASSWORD_CONFIGURATION_NEVER_LOG'


def data(*addresses):return json.dumps([{'addr_info':list(addresses)}])


class InterfaceTests(unittest.TestCase):
    def check(self,raw,status='ok',expected=None):
        rows=[]
        try:
            result=f.inventory.check_interfaces(status,raw,expected or [PUBLIC],lambda *r:rows.append(r))
            return result,rows
        except f.checks.HttpsError as error:
            self.assertEqual(str(error),rows[-1][0])
            return None,rows

    def test_filtered_empty_objects_are_not_missing_local_errors(self):
        # iproute2 print_selected_addrinfo opens a JSON object before
        # print_addrinfo performs the scope filter; the skipped record is {}.
        raw=data({}, {'local':PUBLIC,'family':'inet','scope':'global','prefixlen':32}, {})
        with self.assertRaises(KeyError):
            for interface in json.loads(raw):
                for address in interface['addr_info']:_=address['local']
        public,rows=self.check(raw)
        self.assertEqual(public,{PUBLIC})
        self.assertEqual(rows,[('DIRECT_PUBLIC_IP_PRESENT','FILTERED_EMPTY_ENTRIES_IGNORED')])

    def test_valid_private_only_empty_and_missing_expected_are_not_invalid_or_nat_claims(self):
        for raw in ('[]', data(), data({}), data({'local':'192.0.2.10'},{}),data({'local':PUBLIC})):
            _,rows=self.check(raw,expected=[IPV6])
            self.assertEqual(rows,[('PUBLIC_IP_NOT_ON_INTERFACE','EXPECTED_ADDRESS_ABSENT')])
            self.assertNotIn('NAT',rows[-1][0])

    def test_ipv4_ipv6_normalization_and_both_families_required(self):
        raw=data({'local':PUBLIC},{'local':'2606:4700:4700:0:0:0:0:1111','family':'inet6','prefixlen':128,'scope':'global'})
        public,rows=self.check(raw,expected=[PUBLIC,IPV6])
        self.assertEqual(public,{PUBLIC,IPV6});self.assertEqual(rows,[('DIRECT_PUBLIC_IP_PRESENT','NONE')])
        _,rows=self.check(data({'local':PUBLIC}),expected=[PUBLIC,IPV6])
        self.assertEqual(rows[-1][0],'PUBLIC_IP_NOT_ON_INTERFACE')

    def test_bad_json_and_types_fail_closed_even_with_a_valid_public_record(self):
        cases=[('not-json','JSON_INVALID'),('NaN','JSON_INVALID'),('[{"addr_info":[],"extra":NaN}]','JSON_INVALID'),('{}','ROOT_NOT_ARRAY'),('null','ROOT_NOT_ARRAY'),
               ('[null]','INTERFACE_NOT_OBJECT'),('[{}]','ADDR_INFO_NOT_ARRAY'),
               ('[{"addr_info":null}]','ADDR_INFO_NOT_ARRAY'),('[{"addr_info":{}}]','ADDR_INFO_NOT_ARRAY'),
               (data(None),'ADDRESS_NOT_OBJECT'),(data(''),'ADDRESS_NOT_OBJECT'),
               (data({'family':'inet'}),'LOCAL_MISSING'),(data({'local':None}),'LOCAL_TYPE_OR_FORMAT_INVALID'),
               (data({'local':1234}),'LOCAL_TYPE_OR_FORMAT_INVALID'),(data({'local':True}),'LOCAL_TYPE_OR_FORMAT_INVALID'),
               (data({'local':CANARY}),'LOCAL_TYPE_OR_FORMAT_INVALID'),(data({'local':PUBLIC+'/32'}),'ADDRESS_INVALID'),
               (data({'local':'fe80::1%eth0'}),'LOCAL_TYPE_OR_FORMAT_INVALID'),
               (data({'local':PUBLIC,'family':'inet6'}),'FAMILY_MISMATCH'),
               (data({'local':PUBLIC,'scope':'link'}),'SCOPE_MISMATCH'),
               (data({'local':PUBLIC,'prefixlen':True}),'PREFIX_INVALID'),
               (data({'local':PUBLIC,'prefixlen':33}),'PREFIX_INVALID'),(None,'RAW_TYPE_OR_SIZE_INVALID')]
        for raw,reason in cases:
            with self.subTest(reason=reason):
                _,rows=self.check(raw)
                self.assertEqual(rows,[('INTERFACE_DATA_INVALID',reason)])
                self.assertNotIn(CANARY,interface_report(rows))
        _,rows=self.check(data({'local':PUBLIC},{'family':'inet'}))
        self.assertEqual(rows[-1],('INTERFACE_DATA_INVALID','LOCAL_MISSING'))

    def test_read_failures_are_separate_from_json_errors_and_do_not_parse_stderr(self):
        for status,reason in [('missing','COMMAND_MISSING'),('timeout','COMMAND_TIMEOUT'),('error','COMMAND_ERROR'),('output_limit','OUTPUT_LIMIT')]:
            _,rows=self.check(CANARY,status)
            self.assertEqual(rows,[('INTERFACE_READ_FAILED',reason)])
            self.assertNotIn(CANARY,interface_report(rows))

    def test_summary_only_accepts_known_result_reason_pairs(self):
        text=interface_report([(CANARY,'NONE'),('DIRECT_PUBLIC_IP_PRESENT',CANARY),('DIRECT_PUBLIC_IP_PRESENT','JSON_INVALID'),('INTERFACE_DATA_INVALID','ADDRESS_INVALID')])
        self.assertNotIn(CANARY,text);self.assertNotIn('JSON_INVALID',text)
        self.assertIn('INTERFACE_DATA_INVALID',text)
        self.assertNotIn(PUBLIC,text);self.assertNotIn(IPV6,text)

    def test_actual_ip_json_scope_global_has_no_unhandled_parse_exception(self):
        tool=shutil.which('ip')
        if not tool:
            if os.environ.get('GITHUB_ACTIONS')=='true':self.fail('IP_TOOL_REQUIRED_IN_CI')
            self.skipTest('iproute2 unavailable')
        command=subprocess.run([tool,'-j','address','show','scope','global'],capture_output=True,text=True,timeout=5)
        self.assertEqual(command.returncode,0,'READ_ONLY_IP_COMMAND_FAILED')
        _,rows=self.check(command.stdout)
        self.assertIn(rows[-1][0],('DIRECT_PUBLIC_IP_PRESENT','PUBLIC_IP_NOT_ON_INTERFACE'))


class InterfaceProtocolTests(unittest.TestCase):
    def session(self,events,mode='check'):
        body='import sys,json;h=json.loads(sys.stdin.buffer.readline());sys.stdin.buffer.read(h["code_size"]);'+''.join('print('+repr(json.dumps(e))+',flush=True);' for e in events)
        class SSH:
            password=CANARY
            def arguments(self,command):return [os.sys.executable,'-c',body]
        phases=[];rows=[];session=f.workflow.Session(SSH(),diagnostics=phases,interface_diagnostics=rows)
        return session,rows,{**options(),'mode':mode}

    def test_failure_status_and_detail_survive_pipe_and_write_safe_summary(self):
        events=[{'event':'phase','phase':'CHECK_INTERFACES'},
                {'event':'interface-result','result':'INTERFACE_DATA_INVALID','reason':'LOCAL_MISSING'},
                {'event':'result','status':'FAILED','code':'INTERFACE_DATA_INVALID','phase':'CHECK_INTERFACES','error_kind':'EXPECTED'}]
        session,rows,opts=self.session(events)
        with contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaisesRegex(f.checks.HttpsError,'INTERFACE_DATA_INVALID'):
            session.run(opts)
        self.assertEqual(rows,[('INTERFACE_DATA_INVALID','LOCAL_MISSING')]);self.assertNotIn(CANARY,output.getvalue())
        with tempfile.TemporaryDirectory() as folder:
            event=Path(folder)/'event.json';summary=Path(folder)/'summary.md';event.write_text(json.dumps({'inputs':options()}))
            def run(session,*a,**kw):
                session.interface_diagnostics.extend(rows)
                raise f.checks.HttpsError('INTERFACE_DATA_INVALID')
            with patch.dict(os.environ,{'GITHUB_EVENT_PATH':str(event),'GITHUB_STEP_SUMMARY':str(summary),'STUDIO_SSH_PASSWORD':CANARY}),patch.object(f.workflow,'verified_main'),patch.object(f.workflow,'dns_records'),patch.object(f.workflow.Session,'run',run),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(f.workflow.main(),1)
            text=summary.read_text();self.assertIn('INTERFACE_DATA_INVALID',text);self.assertIn('LOCAL_MISSING',text)
            for private in (CANARY,PUBLIC,IPV6,options()['hostname']):self.assertNotIn(private,text)

    def test_unknown_values_extra_fields_wrong_phase_duplicates_and_apply_are_rejected(self):
        stage={'event':'phase','phase':'CHECK_INTERFACES'}
        valid={'event':'interface-result','result':'DIRECT_PUBLIC_IP_PRESENT','reason':'NONE'}
        for events,mode in [([stage,{**valid,'reason':CANARY}],'check'),([stage,{**valid,'raw':CANARY}],'check'),
                            ([stage,{**valid,'result':CANARY}],'check'),([stage,{**valid,'reason':'JSON_INVALID'}],'check'),
                            ([valid],'check'),([stage,valid,valid],'check'),([valid],'apply')]:
            session,rows,opts=self.session(events,mode)
            with contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaisesRegex(f.checks.HttpsError,'INVALID_REMOTE_PROTOCOL'):
                session.run(opts)
            self.assertNotIn(CANARY,output.getvalue()+interface_report(rows))

    def test_full_bootstrap_distinguishes_read_failure_malformed_data_and_absent_public_ip(self):
        original=c.FIXTURE
        for status,raw,result,reason,phase in (
            ('timeout',CANARY,'INTERFACE_READ_FAILED','COMMAND_TIMEOUT','READ_INTERFACES'),
            ('ok','not-json','INTERFACE_DATA_INVALID','JSON_INVALID','CHECK_INTERFACES'),
            ('ok',data({'family':'inet'}),'INTERFACE_DATA_INVALID','LOCAL_MISSING','CHECK_INTERFACES'),
            ('ok',data({}, {'local':'192.0.2.10'}),'PUBLIC_IP_NOT_ON_INTERFACE','EXPECTED_ADDRESS_ABSENT','CHECK_INTERFACES')):
            changed=original.replace("def read(name,port):", "def read(name,port):\n    if name=='interfaces':return "+repr(status)+','+repr(raw))
            harness=c.FullCheckTests()
            with self.subTest(result=result,reason=reason),patch.object(c,'FIXTURE',changed):
                process,events=harness.bootstrap()
            self.assertEqual(process.returncode,1)
            self.assertEqual(events[-1]['code'],result);self.assertEqual(events[-1]['phase'],phase)
            self.assertIn({'event':'interface-result','result':result,'reason':reason},events)
            self.assertNotIn('CHECK_MEMORY',[e.get('phase') for e in events])

    def test_full_bootstrap_reports_results_for_interfaces_without_writes(self):
        # Reuse the exact bootstrap harness without importing its test class as
        # a module-level alias (unittest must not discover the same tests twice).
        harness=c.FullCheckTests();harness.setUp()
        try:
            result,events=harness.bootstrap()
            self.assertEqual(result.returncode,0)
            self.assertTrue(any(e.get('event')=='interface-result' and e.get('result')=='DIRECT_PUBLIC_IP_PRESENT' for e in events))
        finally:harness.tearDown()


if __name__=='__main__':unittest.main()
