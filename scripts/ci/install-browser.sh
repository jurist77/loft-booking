#!/usr/bin/env bash
# Disposable Ubuntu CI runner only. No APT, sudo, services or VPS access.
set -euo pipefail
. /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then
  echo '::error::CI_BROWSER_REQUIRES_UBUNTU_24_04'
  exit 1
fi
case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) echo '::error::CI_BROWSER_ARCH_UNSUPPORTED'; exit 1 ;;
esac
test -x node_modules/.bin/playwright
# npm ci selected the lockfile version. Do not install a floating CLI, optional
# Xvfb/font packs or a second headless-shell binary that our tests never use.
# Playwright retains its own bounded multi-URL download retries and TLS checks.
export PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT=60000
npx --no-install playwright install --no-shell chromium
node --input-type=module <<'JS'
import { chromium } from '@playwright/test';
const browser = await chromium.launch({ executablePath: chromium.executablePath(), headless: true });
try {
  const page = await browser.newPage();
  await page.setContent('<html lang="ru"><body><button>Проверка браузера</button></body></html>');
  await page.getByRole('button', { name: 'Проверка браузера' }).click();
  if ((await page.screenshot()).length < 100) throw new Error('CI_BROWSER_RENDER_FAILED');
  console.log('CI_BROWSER_READY: locked Chromium; real headless launch, Cyrillic DOM, click and render');
} finally {
  await browser.close();
}
JS
