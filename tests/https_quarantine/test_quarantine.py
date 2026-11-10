import ast
import copy
import io
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

from fixtures import FixtureOps,host,ROOT
import quarantine_workflow as runner

HEALTH={'http':200,'ok':True,'error':'none'}
SECRET='SYNTHETIC_SECRET'


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.ops=FixtureOps(Path(self.tmp.name))

    def invoke(self,mode='quarantine',confirmation=host.CONFIRM):
        return host.quarantine_once(mode,confirmation,self.ops)

    def assertNoMutation(self):
        for name in host.TLS_ROOTS:self.assertTrue(self.ops.path(name).is_dir())
        for name in host.QROOTS:self.assertFalse(self.ops.path(name).exists())
        self.assertEqual(self.ops.commands,[])

    def test_check_is_readonly_and_confirmation_is_exact_before_any_operations(self):
        result=self.invoke('check','');self.assertEqual(result['status'],'READY');self.assertNoMutation()
        for text in ('',host.CONFIRM+' ',SECRET):
            result=self.invoke(confirmation=text);self.assertEqual(result['code'],'CONFIRMATION_REQUIRED');self.assertNoMutation()

    def test_real_atomic_moves_private_journal_identity_reservation_and_canary(self):
        baseline=self.ops.baseline();inodes=[host.q_stat(self.ops.path(p))[:2] for p in host.TLS_ROOTS]
        result=self.invoke();self.assertEqual(result['status'],'SUCCESS',result)
        self.assertEqual(self.ops.commands,['user','group']);self.assertEqual(self.ops.baseline(),baseline)
        for target,inode in zip(host.TARGETS,inodes):self.assertEqual(host.q_stat(self.ops.path(target))[:2],inode)
        for name in host.QROOTS:self.assertEqual(self.ops.path(name).stat().st_mode&0o777,0o700)
        journal=self.ops.path(host.JOURNAL);self.assertEqual(journal.stat().st_mode&0o777,0o600)
        value=json.loads(journal.read_text());self.assertEqual(value['phase'],'COMPLETE');self.assertEqual(value['moved'],3)
        self.assertEqual(len(value['manifest']),9);self.assertEqual(value['identity'],self.ops.user)
        self.assertEqual(runner.validate(result),result)

    def test_repeat_is_blocked_never_adopts_or_overwrites_quarantine(self):
        self.assertEqual(self.invoke()['status'],'SUCCESS')
        before=self.ops.path(host.JOURNAL).read_bytes();result=self.invoke()
        self.assertEqual(result['status'],'BLOCKED');self.assertFalse(result['changed'])
        self.assertEqual(self.ops.path(host.JOURNAL).read_bytes(),before)

    def test_unknown_or_held_names_and_unmatched_proof_stop_before_writes(self):
        for fault in ('proof:1','proof:2'):
            with tempfile.TemporaryDirectory() as tmp:
                self.ops=FixtureOps(Path(tmp));self.ops.fault=fault
                self.assertEqual(self.invoke()['status'],'BLOCKED');self.assertNoMutation()
        self.ops=FixtureOps(Path(self.tmp.name));self.ops.users[host.HOLD]=dict(self.ops.user)
        self.assertEqual(self.invoke()['code'],'IDENTITY_COLLISION');self.assertNoMutation()

    def test_quarantine_collision_or_bad_health_is_no_permission_to_move(self):
        self.ops.path(host.QROOTS[0]).mkdir();result=self.invoke()
        self.assertEqual(result['code'],'QUARANTINE_COLLISION');self.assertEqual(self.ops.moves,0)
        self.ops.path(host.QROOTS[0]).rmdir();self.ops.health_ok=False
        self.assertEqual(self.invoke()['status'],'BLOCKED');self.assertNoMutation()

    def test_changed_baseline_unknown_files_keys_and_checkpoint_stop(self):
        for leaf in ('unexpected','managed.json','transaction.json'):
            p=self.ops.base/leaf;p.write_text(SECRET)
            self.assertEqual(self.invoke()['status'],'BLOCKED');self.assertNoMutation();p.unlink()
        p=self.ops.data/'key.pem';p.write_text(SECRET)
        self.assertEqual(self.invoke()['status'],'BLOCKED');self.assertNoMutation()

    def test_baseline_change_or_journal_disk_error_never_causes_further_steps(self):
        initial=self.ops.baseline()
        with patch.object(self.ops,'baseline',side_effect=[initial,{'changed':True}]):
            self.assertEqual(self.invoke()['status'],'BLOCKED');self.assertNoMutation()
        with patch.object(self.ops,'journal',side_effect=OSError(SECRET)):
            result=self.invoke();self.assertEqual(result['status'],'MANUAL_REVIEW_REQUIRED')
            self.assertEqual(self.ops.moves,0);self.assertEqual(self.ops.commands,[])
            self.assertTrue(all(self.ops.path(p).exists() for p in host.TLS_ROOTS))
            self.assertNotIn(SECRET,json.dumps(result))

    def test_moved_file_tampering_fails_before_account_rename(self):
        original=self.ops.move
        def altered(source,target):
            original(source,target)
            if source==host.TLS_ROOTS[0]:(self.ops.path(target)/'control.py').write_text(SECRET)
        with patch.object(self.ops,'move',side_effect=altered):
            result=self.invoke();self.assertEqual(result['status'],'MANUAL_REVIEW_REQUIRED')
            self.assertEqual(self.ops.commands,[])

    def test_move_interruptions_leave_durable_intent_without_identity_changes(self):
        for move in (1,2,3):
            for timing in ('before','after'):
                with self.subTest(move=move,timing=timing),tempfile.TemporaryDirectory() as tmp:
                    self.ops=FixtureOps(Path(tmp));self.ops.fault=f'move:{move}:{timing}'
                    result=self.invoke();self.assertEqual(result['status'],'MANUAL_REVIEW_REQUIRED')
                    value=json.loads(self.ops.path(host.JOURNAL).read_text())
                    self.assertEqual(value['phase'],('MOVE_BASE','MOVE_CONFIG','MOVE_DATA')[move-1])
                    self.assertEqual(self.ops.commands,[])
                    self.assertNotIn(SECRET,json.dumps(result))

    def test_account_partial_failure_never_deletes_or_blindly_reverts(self):
        for fault in ('user:before','user:after','group:before','group:after','dependencies'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                self.ops=FixtureOps(Path(tmp));self.ops.fault=fault
                result=self.invoke();self.assertEqual(result['status'],'MANUAL_REVIEW_REQUIRED')
                self.assertTrue(all(self.ops.path(p).is_dir() for p in host.TARGETS))
                self.assertTrue(self.ops.path(host.JOURNAL).exists())
                self.assertNotIn(SECRET,json.dumps(result))

    def test_noreplace_rejects_destination_and_no_copy_fallback(self):
        self.ops.make_containers();target=self.ops.path(host.TARGETS[0]);target.mkdir()
        with self.assertRaises(host.QuarantineError):self.ops.move(host.TLS_ROOTS[0],host.TARGETS[0])
        self.assertTrue(self.ops.base.is_dir());self.assertEqual(list(target.iterdir()),[])

    def test_existing_installer_lock_is_required_and_other_holder_blocks(self):
        with self.ops.lock():self.assertEqual(self.invoke()['status'],'BLOCKED')
        self.assertNoMutation();self.ops.path(host.LOCK).unlink()
        self.assertEqual(self.invoke()['status'],'BLOCKED');self.assertFalse(self.ops.path(host.LOCK).exists())

    def test_schema_secret_redaction_lost_reply_and_external_postcheck(self):
        completed=self.invoke();ssh=Mock();ssh.execute.return_value=completed
        with patch.object(runner,'payload',return_value=b'safe-fixture'):
            health=Mock(side_effect=[HEALTH,{'http':None,'ok':False,'error':'timeout'}])
            result=runner.run('192.0.2.10','quarantine',host.CONFIRM,SECRET,lambda *a:ssh,health)
            self.assertEqual(result['status'],'MANUAL_REVIEW_REQUIRED');self.assertEqual(result['moved'],3)
            ssh.execute.side_effect=runner.DeployError('SSH_TIMEOUT_OR_TRANSPORT_FAILED')
            result=runner.run('192.0.2.10','quarantine',host.CONFIRM,SECRET,lambda *a:ssh,lambda *a:HEALTH)
            self.assertEqual(result['status'],'OUTCOME_UNKNOWN_MANUAL_REVIEW')
            ssh.execute.side_effect=runner.DeployError('SSH_AUTH_FAILED')
            result=runner.run('192.0.2.10','quarantine',host.CONFIRM,SECRET,lambda *a:ssh,lambda *a:HEALTH)
            self.assertEqual(result['status'],'BLOCKED');self.assertEqual(result['changes'],'none')
        self.assertNotIn(SECRET,json.dumps(result))
        bad=copy.deepcopy(completed);bad['secret']=SECRET
        with self.assertRaises(ValueError):runner.validate(bad)

    def test_options_branch_confirmation_and_password_fail_before_network(self):
        for raw in ({'server_ip':'$(danger)'},{'server_ip':'192.0.2.10','mode':'apply'},
                {'server_ip':'192.0.2.10','mode':'quarantine'}, {'server_ip':'192.0.2.10','mode':'check','confirmation':SECRET}):
            with self.assertRaises((ValueError,runner.DeployError)):runner.options(raw)
        with patch.dict(os.environ,{'GITHUB_REF':'refs/heads/other'}),patch.object(runner,'run') as call,patch('sys.stdout',io.StringIO()):
            self.assertEqual(runner.main(),1);call.assert_not_called()

    def test_payload_and_workflow_boundaries_no_other_mutations(self):
        source=runner.payload('check','').decode();ast.parse(source)
        for banned in ('userdel','groupdel','rmtree','unlink(','os.remove(','systemctl restart','ufw allow','iptables -A','shell=True'):
            self.assertNotIn(banned,source)
        flow=(ROOT/'.github/workflows/quarantine-studio-https-prepare.yml').read_text()
        for banned in ('  push:','  schedule:','STUDIO_SSH_KNOWN_HOSTS','${{ inputs.server_ip }}'):
            self.assertNotIn(banned,flow)
        self.assertIn("github.ref == 'refs/heads/main'",flow);self.assertIn('workflow_dispatch:',flow)
        self.assertIn('contents: read',flow);self.assertIn('STUDIO_SSH_PASSWORD',flow)
        argv=runner.SSH('192.0.2.10',SECRET).arguments('python3 -I -B -S -')
        self.assertIn('StrictHostKeyChecking=no',argv);self.assertNotIn(SECRET,' '.join(argv))
        definitions=source.rsplit('\nos.umask(0o077)',1)[0]
        namespace={'__name__':'isolated_fixture'};exec(compile(definitions,'quarantine-fixture','exec'),namespace)
        fake=Mock()
        result=namespace['quarantine_once']('quarantine','wrong',fake)
        self.assertEqual(result['code'],'CONFIRMATION_REQUIRED');fake.lock.assert_not_called()

    def test_native_fixture_cannot_run_without_disposable_ci_guard(self):
        env={**os.environ,'GITHUB_ACTIONS':'false'}
        result=subprocess.run([sys.executable,'-B',str(ROOT/'tests/https_quarantine/real_identity.py')],env=env,
            capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0);self.assertIn('DISPOSABLE_CI_REQUIRED',result.stderr)


if __name__=='__main__':unittest.main()
