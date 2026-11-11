"""CI setup contracts and isolated shell fixtures; no package/network access."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'scripts/ci/install-browser.sh'


class BrowserSetupTests(unittest.TestCase):
    def shell(self,arch='x86_64',release='24.04',download=0,browser=0):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);tools=root/'bin';tools.mkdir();trace=root/'trace'
            os_release=root/'os-release';os_release.write_text(f'ID=ubuntu\nVERSION_ID="{release}"\n')
            source=SOURCE.read_text();self.assertEqual(source.count('/etc/os-release'),1)
            (root/'setup.sh').write_text(source.replace('/etc/os-release',str(os_release)))
            cli=root/'node_modules/.bin/playwright';cli.parent.mkdir(parents=True);cli.touch();cli.chmod(0o755)
            fake='''#!/usr/bin/python3
import json,os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
with open(os.environ['FIXTURE_TRACE'],'a') as f:f.write(json.dumps([name,*sys.argv[1:]])+'\\n')
if name=='uname':print(os.environ['FIXTURE_ARCH'])
if name=='npx':sys.exit(int(os.environ['FIXTURE_DOWNLOAD']))
if name=='node':sys.stdin.read();sys.exit(int(os.environ['FIXTURE_BROWSER']))
'''
            for name in ('uname','npx','node'):
                path=tools/name;path.write_text(fake);path.chmod(0o755)
            result=subprocess.run(['/bin/bash','setup.sh'],cwd=root,capture_output=True,text=True,
                env={**os.environ,'PATH':str(tools)+':/usr/bin:/bin','FIXTURE_TRACE':str(trace),
                    'FIXTURE_ARCH':arch,'FIXTURE_DOWNLOAD':str(download),'FIXTURE_BROWSER':str(browser)},timeout=10)
            return result,[json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []

    def test_both_native_architectures_install_locked_full_browser_and_really_launch(self):
        for arch in ('x86_64','aarch64'):
            result,calls=self.shell(arch=arch)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(calls,[['uname','-m'],['npx','--no-install','playwright','install','--no-shell','chromium'],['node','--input-type=module']])
        source=SOURCE.read_text()
        for required in ('chromium.launch','chromium.executablePath()','headless: true','page.screenshot()','await browser.close()'):
            self.assertIn(required,source)
        for forbidden in ('apt-get','sudo ','--with-deps','SKIP_VALIDATE','ignoreHTTPSErrors','|| true','continue-on-error'):
            self.assertNotIn(forbidden,source)

    def test_dns_download_failure_is_nonzero_and_never_runs_smoke(self):
        result,calls=self.shell(download=42)
        self.assertEqual(result.returncode,42)
        self.assertNotIn('node',[call[0] for call in calls])

    def test_missing_runtime_or_browser_failure_is_not_reported_as_success(self):
        result,calls=self.shell(browser=43)
        self.assertEqual(result.returncode,43);self.assertEqual(calls[-1][0],'node')

    def test_unsupported_host_or_arch_fails_before_download(self):
        for kwargs in ({'release':'26.04'},{'arch':'riscv64'}):
            result,calls=self.shell(**kwargs)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn('npx',[call[0] for call in calls])

    def test_workflows_pin_platform_keep_all_gates_and_support_old_release_sources(self):
        backend=(ROOT/'.github/workflows/backend-checks.yml').read_text()
        package=(ROOT/'.github/workflows/installer-package.yml').read_text()
        self.assertIn('runs-on: ubuntu-24.04',backend);self.assertNotIn('ubuntu-latest',backend)
        self.assertIn('node-version: "24.12.0"',backend)
        self.assertIn('bash scripts/ci/install-browser.sh',backend)
        self.assertIn('bash .studio-verified-control/scripts/ci/install-browser.sh',package)
        build=package.index('- name: Build native, private SERVER root filesystem')
        checkout=package.index('- name: Checkout current reviewed lifecycle controls')
        browser=package.index('- name: Install browser on the disposable release runner')
        copy=package.index('- name: Use current controls for old-version restore acceptance')
        self.assertLess(build,checkout);self.assertLess(checkout,browser);self.assertLess(browser,copy)
        self.assertEqual(package.count('path: .studio-verified-control'),1)
        self.assertIn('ref: ${{ github.workflow_sha }}',package)
        for text in (backend,package):
            self.assertNotIn('--with-deps',text);self.assertNotIn('continue-on-error',text)
            for command in ('npm test','npm run typecheck','npm run lint','npm run test:integration','npm run test:api:http','npm run test:server:http'):
                self.assertIn(command,text)
        self.assertIn('if ! command -v gpg >/dev/null; then',package)
        self.assertIn('if ! command -v certutil >/dev/null; then',package)
        self.assertEqual(package.count('APT::Update::Error-Mode=any'),2)


class ExactMainGateTests(unittest.TestCase):
    def test_all_four_exact_push_checks_required_and_failed_or_skipped_newer_run_blocks(self):
        folder=ROOT/'scripts/installer';sys.path.insert(0,str(folder))
        try:
            spec=importlib.util.spec_from_file_location('ci_exact_main_gate',folder/'verify-main.py')
            gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        finally:sys.path.pop(0)
        sha='a'*40
        env={'STUDIO_SERVER_IP':'192.0.2.10','STUDIO_PASSWORD_PRESENT':'true','GITHUB_SHA':sha,
             'GITHUB_REF':'refs/heads/main','GITHUB_REPOSITORY':'owner/repo','STUDIO_BACKUP_PASSWORD_PRESENT':'true',
             'STUDIO_BACKUP_TOKEN_PRESENT':'true','STUDIO_BACKUP_REPOSITORY':'owner/private-fixture'}
        names=('Check backend foundation','Check read-only VPS audit tool','Check universal installer','Check Studio HTTPS')
        successful=[{'name':n,'databaseId':i,'status':'completed','conclusion':'success'} for i,n in enumerate(names)]
        def check(runs,expected):
            with patch.dict(os.environ,env),patch.object(gate.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(runs))) as api,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(),expected)
                argv=api.call_args.args[0]
                self.assertEqual(argv[argv.index('--commit')+1],sha)
                self.assertEqual(argv[argv.index('--event')+1],'push')
        check(successful,0)
        for name in names:
            check([r for r in successful if r['name']!=name],1)
            for conclusion in ('failure','skipped','cancelled','timed_out'):
                check(successful+[{'name':name,'databaseId':99,'status':'completed','conclusion':conclusion}],1)
            check(successful+[{'name':name,'databaseId':99,'status':'in_progress','conclusion':None}],1)


if __name__=='__main__':unittest.main()
