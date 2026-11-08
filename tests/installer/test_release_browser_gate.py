"""Release contract: browser/SQLite checks are mandatory before publication."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseBrowserGateTests(unittest.TestCase):
    def test_native_x64_and_arm64_packages_require_browser_gate_before_publish(self):
        text = (ROOT / ".github/workflows/installer-package.yml").read_text()
        self.assertIn("arch: x64\n            runner: ubuntu-24.04", text)
        self.assertIn("arch: arm64\n            runner: ubuntu-24.04-arm", text)
        build = text.index("- name: Build native, private SERVER root filesystem")
        browser = text.index("- name: Require real browser journeys from the exact release package")
        systemd = text.index("- name: Real systemd installation")
        publish = text.index("- name: Publish only the verified immutable package")
        self.assertLess(build, browser); self.assertLess(browser, systemd); self.assertLess(systemd, publish)
        step = text[browser:systemd]
        self.assertIn("PACKAGE_CHECKSUM_FAILED", step)
        self.assertIn("export STUDIO_E2E_RELEASE_ROOT=", step)
        self.assertIn("npm run test:server:browser", step)
        self.assertNotIn("continue-on-error", step); self.assertNotIn("if:", step)
        self.assertNotIn("|| true", step)

    def test_install_rebuilds_same_checked_main_sha_through_required_package_job(self):
        text = (ROOT / ".github/workflows/install-studio.yml").read_text()
        self.assertIn("uses: ./.github/workflows/installer-package.yml", text)
        self.assertIn("source_sha: ${{ github.sha }}", text)
        self.assertIn("needs: [validate, packages]", text)
        check = (ROOT / "scripts/installer/verify-main.py").read_text()
        self.assertIn('"Check universal installer"', check)
        self.assertIn('"MAIN_CHECKS_NOT_SUCCESSFUL"', check)

    def test_https_native_browser_and_recovery_gate_is_mandatory_before_publish(self):
        text=(ROOT/'.github/workflows/installer-package.yml').read_text()
        start=text.index('- name: Require real Caddy TLS')
        publish=text.index('- name: Publish only the verified immutable package')
        self.assertLess(start,publish)
        self.assertIn('tests/https/real_systemd.py',text[start:publish])
        self.assertIn('tests/https/local_tls.py',text[start:publish])
        self.assertNotIn('continue-on-error',text[start:publish])
        self.assertIn('github.workflow_sha',text)
        restore=(ROOT/'.github/workflows/restore-studio.yml').read_text()
        self.assertIn('Require successful current HTTPS-aware receiver checks',restore)


if __name__ == "__main__": unittest.main()
