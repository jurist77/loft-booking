"""Synthetic fixtures only: never inspect or alter host firewall/VPN."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/diagnostics'))
import probe_nft_hooks as probe
import https_readiness as runner
from test_https_readiness import fixture, CANARY


def chain(name='hidden',hook='input',family='inet',table='private',**options):
    return {'chain':{'family':family,'table':table,'name':name,'type':'filter','hook':hook,'prio':-10,'policy':'accept',**options}}


def rule(*expressions,name='hidden',family='inet',table='private'):
    return {'rule':{'family':family,'table':table,'chain':name,'expr':list(expressions),'comment':CANARY}}


def port(value,field='dport',op='=='):
    return {'match':{'left':{'payload':{'protocol':'tcp','field':field}},'op':op,'right':value}}


def summary(*entries):
    return probe.nft_hooks_summary(json.dumps({'nftables':list(entries)}),'*filter\n:INPUT DROP [0:0]\nCOMMIT\n','')


class HookTests(unittest.TestCase):
    def test_additional_inet_hook_is_distinguished_from_iptables_chain_name(self):
        data=summary(chain(name='INPUT',family='ip',table='filter',prio=0),chain())
        self.assertEqual([v['iptables_view'] for v in data['hooks']],['CHAIN_NAME_PRESENT','NFT_ONLY'])
        self.assertEqual(data['creator'],'NOT_PROVEN')
        runner.validate(fixture({'nft':json.dumps({'nftables':[chain()]})}))

    def test_extra_objects_are_counted_without_assuming_the_error_means_a_hook(self):
        data=summary(chain(),{'set':{'family':'inet','table':CANARY,'name':CANARY,'elem':['198.51.100.77']}},
                     {'flowtable':{'family':'inet','table':CANARY,'name':CANARY,'hook':'ingress'}},
                     {'counter':{'name':CANARY,'bytes':12345}})
        self.assertEqual(data['objects']['set'],1)
        self.assertEqual(data['objects']['flowtable'],1)
        self.assertEqual(data['objects']['counter'],1)
        self.assertNotIn(CANARY,json.dumps(data));self.assertNotIn('198.51.100.77',json.dumps(data))
        self.assertTrue(probe.valid_nft_audit(data))

    def test_invalid_iptables_view_is_not_misclassified_as_a_native_only_hook(self):
        raw=json.dumps({'nftables':[chain()]})
        for bad in (CANARY,'*filter\n:INPUT DROP [0:0]\n',':INPUT DROP [0:0]\nCOMMIT\n'):
            result=probe.audit_nft_hooks(lambda name:('ok',raw if name=='nft' else bad))
            self.assertEqual(result['state'],'DATA_INVALID')
            self.assertEqual(result['hooks'],[])

    def test_tcp_drop_on_443_does_not_claim_effect_on_22_or_80(self):
        h=summary(chain(),rule(port(443),{'drop':None}))['hooks'][0]
        self.assertEqual(h['tcp'],{'22':[],'80':[],'443':['DROP_POSSIBLE']})
        self.assertEqual(h['priority'],-10)

    def test_default_drop_policy_remains_possible_even_without_explicit_port_rule(self):
        h=summary(chain(policy='drop'),rule(port(443),{'accept':None}))['hooks'][0]
        self.assertIn('DROP_POSSIBLE',h['tcp']['80'])
        self.assertIn('DROP_POSSIBLE',h['tcp']['443'])
        self.assertIn('ACCEPT_OBSERVED',h['tcp']['443'])

    def test_jump_tproxy_mark_nat_and_unknown_predicates_remain_conservative(self):
        other={'chain':{'family':'inet','table':'private','name':'nested'}}
        h=summary(chain(),rule({'jump':{'target':'nested'}}),other,
            rule(port({'set':[80,443]}),{'match':{'left':{'meta':{'key':'mark'}},'op':'==','right':12345}},
                 {'mangle':{'key':{'meta':{'key':'mark'}},'value':12345}}, {'tproxy':{'port':7777}},name='nested'))['hooks'][0]
        self.assertEqual(h['tcp']['22'],[])
        self.assertIn('TPROXY_POSSIBLE',h['tcp']['443'])
        self.assertIn('UNKNOWN_REVIEW_REQUIRED',h['tcp']['443'])
        self.assertIn('MARK_OR_TRACKING_POSSIBLE',h['tcp']['80'])
        h=summary(chain(hook='prerouting',type='nat'),rule(port(80),{'dnat':{'addr':'198.51.100.99'}}))['hooks'][0]
        self.assertEqual(h['purpose'],'NAT_PATTERN')
        self.assertEqual(h['tcp']['80'],['NAT_POSSIBLE'])

    def test_reply_path_uses_source_port_instead_of_assuming_output_is_irrelevant(self):
        h=summary(chain(hook='output'),rule(port(443,'sport'),{'reject':None}))['hooks'][0]
        self.assertEqual(h['tcp']['22'],[])
        self.assertEqual(h['tcp']['443'],['REJECT_POSSIBLE'])
        h=summary(chain(hook='output'),rule(port(443),{'drop':None}))['hooks'][0]
        self.assertIn('UNKNOWN_REVIEW_REQUIRED',h['tcp']['22'])
        self.assertIn('DROP_POSSIBLE',h['tcp']['22'])

    def test_foreign_family_forward_hidden_xt_and_missing_jump_cannot_establish_safety(self):
        for entries in ((chain(hook='forward'),),(chain(family='bridge'),),
                        (chain(),rule({'xt':{'type':'target','name':CANARY}})),
                        (chain(),rule({'jump':{'target':'missing'}}))):
            h=summary(*entries)['hooks'][0]
            self.assertIn('UNKNOWN_REVIEW_REQUIRED',h['tcp']['443'])

    def test_false_match_cannot_hide_preceding_side_effect(self):
        h=summary(chain(),rule({'mangle':{}},port(9999),{'drop':None}))['hooks'][0]
        self.assertEqual(h['tcp']['443'],['MARK_OR_TRACKING_POSSIBLE'])

    def test_udp_proxy_purpose_is_visible_without_claiming_tcp_interception(self):
        protocol={'match':{'left':{'meta':{'key':'l4proto'}},'op':'==','right':'udp'}}
        h=summary(chain(),rule(protocol,{'tproxy':{'port':7777}}))['hooks'][0]
        self.assertEqual(h['purpose'],'TRANSPARENT_PROXY_PATTERN')
        self.assertEqual(h['features'],['TPROXY'])
        self.assertEqual(h['tcp'],{'22':[],'80':[],'443':[]})

    def test_new_diagnostic_has_no_command_or_write_entrypoint(self):
        import ast
        source=(ROOT/'scripts/diagnostics/probe_nft_hooks.py').read_text()
        tree=ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                self.assertTrue(all(alias.name in ('json','re') for alias in node.names))
            if isinstance(node,ast.Call):
                name=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
                self.assertNotIn(name,('open','Popen','system','unlink','rename','write_text','write_bytes','socket','connect','chmod','chown'))
                if name=='run':
                    self.assertIsInstance(node.func,ast.Name)
                    self.assertEqual(ast.unparse(node.args[0]),'name')

    def test_unknown_address_set_or_expression_does_not_prove_port_exclusion(self):
        for match in (port('@'+CANARY),port({'range':[1,65535]}),
                      {'match':{'left':{'payload':{'protocol':'ip','field':'saddr'}},'op':'==','right':'198.51.100.77'}}):
            h=summary(chain(),rule(match,{'drop':None}))['hooks'][0]
            self.assertIn('DROP_POSSIBLE',h['tcp']['443'])
        h=summary(chain(),rule(port({'range':[1000,2000]}),{'drop':None}))['hooks'][0]
        self.assertEqual(h['tcp']['443'],[])

    def test_name_and_active_vpn_are_hints_never_ownership_and_secrets_are_not_emitted(self):
        entries=[chain(name='xray',table=CANARY),rule({'tproxy':{'addr':'198.51.100.77','port':12345}},name='xray',table=CANARY)]
        data=probe.nft_hooks_summary(json.dumps({'nftables':entries}),'','', 'x-ui.service loaded active running arbitrary label\n')
        self.assertTrue(data['vpn_unit_active']);self.assertEqual(data['creator'],'NOT_PROVEN')
        self.assertEqual(data['hooks'][0]['origin_hint'],'VPN_NAME_HINT_ONLY')
        for secret in (CANARY,'198.51.100.77','12345','arbitrary label'):self.assertNotIn(secret,json.dumps(data))
        self.assertTrue(probe.valid_nft_audit(data))
        for key in ('purpose','origin_hint','id'):
            bad=copy.deepcopy(data);bad['hooks'][0][key]=CANARY
            self.assertFalse(probe.valid_nft_audit(bad))
        remote={'nft_hooks':data}
        self.assertIn('TPROXY_POSSIBLE',runner.nft_report_table(remote))
        self.assertNotIn(CANARY,runner.nft_report_table({'nft_hooks':bad}))

    def test_read_failure_invalid_json_limits_and_rule_races_are_not_clean(self):
        empty=json.dumps({'nftables':[]})
        for state in ('missing','timeout','output_limit','error'):
            result=probe.audit_nft_hooks(lambda name:(state,CANARY))
            self.assertEqual(result['state'],'READ_FAILED');self.assertNotIn(CANARY,json.dumps(result))
        for raw in ('{','{"nftables":{},"nftables":[]}','{"nftables":[true]}',json.dumps({'nftables':[chain()]*33})):
            result=probe.audit_nft_hooks(lambda name:('ok',raw if name=='nft' else ''))
            self.assertIn(result['state'],('DATA_INVALID','LIMIT_EXCEEDED'))
            self.assertEqual(result['hooks'],[])
        counts={}
        def run(name):
            counts[name]=counts.get(name,0)+1
            return 'ok',json.dumps({'nftables':[chain()]}) if name=='nft' and counts[name]>1 else empty if name=='nft' else ''
        self.assertEqual(probe.audit_nft_hooks(run)['state'],'SNAPSHOT_CHANGED')

    def test_volatile_counters_are_ignored_but_rules_and_order_are_not(self):
        entries=[chain(),rule({'counter':{'packets':1,'bytes':99}},port(443),{'drop':None})]
        changed=copy.deepcopy(entries);changed[1]['rule']['expr'][0]['counter']['bytes']=100
        def checked(second):
            counter=[0]
            def run(name):
                if name!='nft':return 'ok',''
                counter[0]+=1
                return 'ok',json.dumps({'nftables':entries if counter[0]==1 else second})
            return probe.audit_nft_hooks(run)
        self.assertEqual(checked(changed)['state'],'OBSERVED')
        changed[1]['rule']['expr'][-1]={'accept':None}
        self.assertEqual(checked(changed)['state'],'SNAPSHOT_CHANGED')

    def test_loop_budget_and_unexpected_output_are_bounded(self):
        h=summary(chain(),rule({'jump':{'target':'hidden'}}))['hooks'][0]
        self.assertIn('UNKNOWN_REVIEW_REQUIRED',h['tcp']['22'])
        for value in (None,[],{}, {'state':CANARY}):self.assertFalse(probe.valid_nft_audit(value))
        data=summary(chain());data['hooks'][0]['priority']=True
        self.assertFalse(probe.valid_nft_audit(data))

    def test_full_hook_inventory_fits_explicit_readonly_limit_and_installer_default_stays(self):
        entries=[]
        for i in range(32):
            entries.extend((chain(name='c'+str(i)),rule({'xt':{}},{'drop':None},{'mangle':{}},name='c'+str(i))))
        data=fixture();data['nft_hooks']=probe.nft_hooks_summary(json.dumps({'nftables':entries}),'','')
        raw=json.dumps(runner.validate(data)).encode()
        self.assertGreater(len(raw),10000);self.assertLess(len(raw),65536)
        import deploy
        child=Mock();child.communicate.return_value=(raw,b'');child.returncode=0;child.poll.return_value=0
        with patch.object(deploy.subprocess,'Popen',return_value=child):
            client=deploy.SSH('192.0.2.10',CANARY)
            with self.assertRaisesRegex(deploy.DeployError,'REMOTE_PROTOCOL_FAILED'):client.execute('fixture')
            self.assertEqual(client.execute('fixture',output_limit=65536),data)
            child.communicate.return_value=(b'x'*65537,b'')
            with self.assertRaisesRegex(deploy.DeployError,'REMOTE_PROTOCOL_FAILED'):client.execute('fixture',output_limit=65536)
        for limit in (None,True,0,65537):
            with patch.object(deploy.subprocess,'Popen') as call:
                with self.assertRaises(deploy.DeployError):client.execute('fixture',output_limit=limit)
                call.assert_not_called()

    def test_legacy_identity_reason_does_not_assert_residue_on_clean_vps(self):
        remote=fixture();remote['tls_residue'].update(account='missing',reason='IDENTITY_MISMATCH',identity_detail='USER_MISSING')
        for k in remote['mechanisms']['paths']:
            if k.startswith('studio_tls_'):remote['mechanisms']['paths'][k]='missing'
        self.assertEqual(runner.residue_explanation(remote),'TLS_USER_ABSENT_NO_TRACKED_OBJECTS_OBSERVED')
        remote['mechanisms']['paths']['studio_tls_data']='private'
        self.assertEqual(runner.residue_explanation(remote),'TLS_USER_ABSENT_OBJECTS_REQUIRE_REVIEW')
        remote['tls_residue']['identity_detail']='SHELL_MISMATCH'
        self.assertEqual(runner.residue_explanation(remote),'TLS_IDENTITY_PROFILE_REQUIRES_REVIEW')
        self.assertTrue(remote['tls_residue']['preservation_required'])


if __name__=='__main__':unittest.main()
