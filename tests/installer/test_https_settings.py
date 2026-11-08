"""HTTPS lifecycle settings with real backup fixtures, no real SSH or services."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[2]/'scripts/installer'
sys.path.insert(0,str(SCRIPTS))
import remote
import backup
import deploy
from maintenance import Maintenance
from test_maintenance import FakeHost

TLS={'format':1,'hostname':'fixture.duckdns.org'}


class HttpsLifecycleTests(unittest.TestCase):
    def test_pending_cutover_blocks_all_regular_lifecycle_reads_and_recovery_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=root/'config';config.mkdir();unit=root/'app.service';unit.write_text('prior unit')
            state={'format':1,'managed_by':'studio-installer','phase':'ready','current':'a'*40+'-'+'b'*16+'-'+'c'*8,
                   'port':3000,'https_pending':True,'unit_sha256':'old-checksum','https':TLS}
            path=config/'state.json';path.write_text(json.dumps(state));os.chmod(path,0o600)
            original=Path.lstat
            def root_owned(p):
                value=original(p)
                return SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_nlink=value.st_nlink)
            with patch.object(remote,'CONFIG',config),patch.object(remote,'UNIT',unit),patch.object(Path,'lstat',root_owned):
                for kwargs in ({},{'allow_pending':True}):
                    with self.assertRaisesRegex(remote.InstallError,'HTTPS_TRANSACTION_PENDING'):remote.load_state(**kwargs)
                self.assertEqual(remote.load_state(allow_https_pending=True),state)
                state['https_pending']=False;path.write_text(json.dumps(state))
                with self.assertRaisesRegex(remote.InstallError,'UNIT_CHANGED_OUTSIDE_INSTALLER'):remote.load_state(allow_https_pending=True)

    def test_snapshot_records_https_metadata_but_no_keys_or_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            host=FakeHost(Path(tmp));host.state['https']=TLS;stream=io.BytesIO()
            Maintenance(host).snapshot('daily',output=stream)
            path=Path(tmp)/'snapshot.tar.gz';path.write_bytes(stream.getvalue())
            manifest=backup.validate_bundle(path)
            self.assertEqual(manifest['https'],TLS)
            with tarfile.open(path) as archive:
                self.assertFalse(any(name.endswith(('.key','.env','.pem')) or 'server.env' in name for name in archive.getnames()))
            self.assertEqual(host.state['https'],TLS)

    def test_https_snapshot_refuses_http_or_uninstalled_target_before_any_mutation(self):
        with patch.object(remote,'host_facts',return_value={'arch':'x64'}),patch.object(remote,'inspect_archive',return_value={}), \
                patch.object(remote,'load_state',return_value=None),patch.object(backup,'validate_bundle',return_value={'https':TLS}),patch.object(remote,'run') as commands:
            with self.assertRaisesRegex(remote.InstallError,'HTTPS_TARGET_REQUIRED_FOR_RESTORE'):
                remote.install(Path('/tmp/not-read'),'a'*64,'b'*40,restore_bundle=Path('/tmp/not-read-either'),confirmed=True)
            commands.assert_not_called()

    def test_same_version_noop_preserves_https_despite_transport_ip_argument(self):
        state={'current':'fixture','version':'b'*40,'port':3000,'origin':'https://fixture.duckdns.org','https':TLS}
        with patch.object(remote,'host_facts',return_value={'arch':'x64'}),patch.object(remote,'inspect_archive',return_value={}), \
                patch.object(remote,'load_state',return_value=state),patch.object(remote,'managed_account',return_value=SimpleNamespace(pw_uid=11,pw_gid=11)), \
                patch.object(remote,'owned_directory'),patch.object(remote,'private_environment',return_value=remote.environment_text(3000,https=TLS)), \
                patch.object(remote,'health'),patch.object(remote,'api_health'),patch.object(remote,'helper'),patch.object(remote,'run') as commands:
            value=remote.install(Path('/tmp/not-read'),'a'*64,'b'*40,origin_host='192.0.2.2')
            self.assertEqual(value['https'],TLS);self.assertEqual(value['url'],'https://fixture.duckdns.org')
            self.assertEqual(value['operation'],'already-current')
            self.assertTrue(all(call.args[0][1] not in ('stop','restart') for call in commands.call_args_list))

    def test_installer_source_bundle_contains_transport_settings_before_dependencies(self):
        code=deploy.remote_source();compile(code,'fixture','exec')
        self.assertLess(code.index(b"'transport_settings'"),code.index(b"'backup'"))
        self.assertLess(len(code),100000)


if __name__=='__main__':unittest.main()
