"""Pure HTTPS firewall fixtures: no SSH, subprocess, UFW or production writes."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

import test_https as h
import firewall as fw
# Reuse the existing dual-view HTTP fixtures with their actual module binding.
with patch.dict(sys.modules, {"host": fw.F}):
    spec = importlib.util.spec_from_file_location("ufw_fixture", h.ROOT / "tests/firewall/test_studio_http_access.py")
    fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)


def add(data, port, families=(4, 6)):
    nft = json.loads(data["nft"])
    for version in families:
        nf = "ip" if version == 4 else "ip6"; user = ("ufw" if version == 4 else "ufw6") + "-user-input"
        data["ip"+str(version)] = data["ip"+str(version)].replace("COMMIT", f"-A {user} -p tcp -m tcp --dport {port} -j ACCEPT\nCOMMIT")
        zero = "0.0.0.0/0" if version == 4 else "::/0"
        data["user"+str(version)] = data["user"+str(version)].replace("COMMIT", f"### tuple ### allow tcp {port} {zero} any {zero} in\n-A {user} -p tcp --dport {port} -j ACCEPT\nCOMMIT")
        nft["nftables"].append(fixtures.nft_allow(nf, user, port))
        data["ufw"] += f"{port}/tcp ALLOW IN Anywhere\n"
    data["nft"] = json.dumps(nft)


class Fixture:
    def __init__(self): self.data = fixtures.fixture(); self.writes = []; self.after = None
    def take(self): return copy.deepcopy(self.data)
    def operation(self, before, apply, port, families):
        if apply:
            self.writes.append((port, families)); add(self.data, port, families)
            if self.after: self.after(self.data)
    def plan(self): return fw.plan(self.take(), 4, lambda: None, self.operation)[1]
    def enable(self, **kwargs):
        return fw.enable(fw.fingerprint(self.data), sorted(self.plan()), [fixtures.ADDRESS], take_state=self.take,
                         guard=contextlib.nullcontext, implementation=lambda: None, operation=kwargs.pop("operation", self.operation), **kwargs)


class FirewallTests(unittest.TestCase):
    def test_clean_plan_is_read_only_and_only_missing_80_443_are_added(self):
        f=Fixture();before=f.take();self.assertEqual(f.plan(),{80:(4,6),443:(4,6)})
        self.assertEqual(f.writes,[]);self.assertEqual(before,f.data)
        final=f.enable();self.assertEqual(final,fw.fingerprint(f.data));self.assertEqual(f.plan(),{})
        self.assertEqual([p for p,_ in f.writes],[80,443])
        self.assertEqual(before['protected'],f.data['protected'])
        self.assertEqual(fw.F.firewall_plan(f.data,22,True)[1],())

    def test_existing_access_requires_no_change_and_mixed_families_do_not_duplicate(self):
        f=Fixture();add(f.data,80);add(f.data,443)
        self.assertEqual(f.plan(),{});self.assertEqual(f.writes,[])
        f=Fixture();add(f.data,80,(4,));add(f.data,443)
        self.assertEqual(f.plan(),{80:(6,)})
        f.enable();self.assertEqual(f.writes,[(80,(6,))]);self.assertEqual(f.plan(),{})

    def test_bad_ssh_policy_conflict_nat_unknown_nft_and_stale_persisted_state_block(self):
        for change in (
            lambda d:d.update(ufw='Status: inactive\n'),
            lambda d:d.update(ufw='Status: active\nDefault: allow (incoming)\n'),
            lambda d:d.update(ip4=d['ip4'].replace('--dport 22','--dport 23')),
            lambda d:d.update(ip4=d['ip4'].replace('COMMIT','-A ufw-user-input -p tcp --dport 80 -j DROP\nCOMMIT')),
            lambda d:d.update(ip4=d['ip4']+'*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 80 -j REDIRECT\nCOMMIT\n'),
            lambda d:d.update(nft=json.dumps({'nftables':json.loads(d['nft'])['nftables']+[{'table':{'family':'inet','name':'foreign'}}]})),
            lambda d:d.update(user4=d['user4'].replace('--dport 22','--dport 23')),
        ):
            f=Fixture();change(f.data)
            with self.assertRaises((fw.F.Unsafe,h.checks.HttpsError)): f.plan()
            self.assertEqual(f.writes,[])

    def test_changed_check_fingerprint_never_writes(self):
        f=Fixture()
        with self.assertRaisesRegex(h.checks.HttpsError,'HTTPS_FIREWALL_STATE_CHANGED'):
            fw.enable('0'*64,[80,443],[fixtures.ADDRESS],take_state=f.take,guard=contextlib.nullcontext,implementation=lambda:None,operation=f.operation)
        self.assertEqual(f.writes,[])

    def test_postflight_changed_ssh_or_policy_or_foreign_rule_demands_review_without_rollback(self):
        for change in (
            lambda d:d.update(ip4=d['ip4'].replace('--dport 22','--dport 23')),
            lambda d:d.update(ip6=d['ip6'].replace(':INPUT DROP',':INPUT ACCEPT')),
            lambda d:d.update(ip4=d['ip4'].replace('COMMIT','-A ufw-user-input -p tcp --dport 9999 -j ACCEPT\nCOMMIT')),
            lambda d:d['protected'].update({'/etc/default/ufw':'00'}),
        ):
            f=Fixture();f.after=change
            with self.assertRaisesRegex(h.checks.HttpsError,'HTTPS_FIREWALL_CHANGE_UNCONFIRMED_REVIEW_REQUIRED'):f.enable()
            self.assertEqual([p for p,_ in f.writes],[80])

    def test_failed_append_or_transport_after_first_rule_retains_state_and_retry_only_adds_missing(self):
        f=Fixture()
        def failed(before,apply,port,families):
            if apply and port==443:raise OSError(fixtures.CANARY)
            f.operation(before,apply,port,families)
        with self.assertRaisesRegex(h.checks.HttpsError,'HTTPS_FIREWALL_CHANGE_UNCONFIRMED_REVIEW_REQUIRED'):f.enable(operation=failed)
        self.assertEqual(f.plan(),{443:(4,6)});f.enable();self.assertEqual([p for p,_ in f.writes],[80,443])
        self.assertEqual(f.plan(),{})

    def test_standard_openssh_profile_metadata_and_stock_rh0_filter_are_preserved(self):
        f=Fixture()
        for v in (4,6):f.data['user'+str(v)]=f.data['user'+str(v)].replace(' in\n',' OpenSSH - in\n')
        f.enable();self.assertEqual(f.plan(),{})
        args=['-A','ufw6-before-input','-m','rt','--rt-type','0','-j','DROP']
        self.assertEqual(fw.F.ip_rule(args,443),(False,'DROP'))
        with self.assertRaises(fw.F.Unsafe):fw.F.ip_rule(args)
        with self.assertRaises(fw.F.Unsafe):fw.F.ip_rule(args[:-3]+['1','-j','DROP'],443)

    def test_apply_is_not_reached_before_full_studio_admission_or_missing_confirmation(self):
        with patch.object(h.host,'apply') as apply:
            args={'server_ip':'8.8.8.8','additional_ip':'','hostname':h.DOMAIN,'mode':'apply','confirmation':'','nonce':h.NONCE}
            with patch.object(h.host.os,'geteuid',return_value=0),patch.object(h.host.signal,'signal'),contextlib.redirect_stdout(__import__('io').StringIO()):
                self.assertEqual(h.host.entry(args),1)
            apply.assert_not_called()

    def test_verified_firewall_add_precedes_probe_and_failed_network_proof_never_changes_studio(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            fixture=h.Fixture(Path(tmp)); original=fixture.ops.inspector; calls=[0]
            def inspect(*args,**kw):
                value=original(*args,**kw);calls[0]+=1
                return {**value,'firewall_plan':[80,443] if calls[0]==1 else []}
            fixture.ops.inspector=inspect
            def failed_proof(phase,nonce):raise h.checks.HttpsError('EXTERNAL_PROOF_NOT_CONFIRMED')
            with fixture.patches(),patch.object(fw,'enable',return_value='c'*64) as enable:
                with self.assertRaisesRegex(h.checks.HttpsError,'EXTERNAL_PROOF_NOT_CONFIRMED'):fixture.run(ack=failed_proof)
            enable.assert_called_once()
            self.assertEqual(fixture.events,[{'event':'firewall-result','ports':[80,443]},{'event':'ports-probe'}])
            self.assertNotIn('prepare',fixture.ops.calls);self.assertNotIn('cutover',fixture.ops.calls)
            self.assertEqual(fixture.installer.UNIT.read_text(),'old-unit')

    def test_opaque_compatibility_requires_both_pinned_stock_views_and_exact_user_rule_correlation(self):
        f=Fixture();data=f.take();reference=fw.F.stock_shape(data)
        # This toy fixture is not the production stock reference.
        with self.assertRaisesRegex(fw.F.Unsafe,'STANDARD_UFW_PROFILE_UNCONFIRMED'):fw.F.stock_nft_profile(data)
        rules=fw.F.stock_nft_profile(data,profiles=(reference,));self.assertTrue(rules)
        add(data,80);add(data,443)
        self.assertEqual(fw.F.stock_shape(data),reference)
        fw.F.stock_nft_profile(data,profiles=(reference,))
        for changed in ('user','base','files','count'):
            bad=copy.deepcopy(data);nf=json.loads(bad['nft'])
            if changed=='user':
                item=next(r['rule'] for r in nf['nftables'] if 'rule' in r and r['rule']['chain']=='ufw-user-input')
                item['expr'].insert(0,{'xt':{'type':'match','name':'conntrack'}})
            elif changed=='base':nf['nftables'].append({'chain':{'family':'inet','table':'foreign','name':'OTHER'}})
            elif changed=='files':bad['protected']['/etc/ufw/before.rules']='00'
            else:nf['nftables'].append(copy.deepcopy(next(r for r in nf['nftables'] if 'rule' in r and r['rule']['chain']=='ufw-user-input')))
            bad['nft']=json.dumps(nf)
            with self.assertRaises(fw.F.Unsafe):fw.F.stock_nft_profile(bad,profiles=(reference,))

    def test_bundled_module_and_all_safe_codes_are_in_protocol(self):
        source=h.workflow.source()
        self.assertIn(b"'studio_firewall'",source);self.assertIn(b"'firewall'",source)
        self.assertIn('HTTPS_UFW_PATH_NOT_PROVEN',h.workflow.SAFE_REMOTE_CODES)
