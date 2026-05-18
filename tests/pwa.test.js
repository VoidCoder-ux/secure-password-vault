import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('iPhone home screen metadata and manifest fields are present', async () => {
  const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const manifest = JSON.parse(await readFile(new URL('../public/manifest.webmanifest', import.meta.url), 'utf8'));

  assert.match(html, /apple-mobile-web-app-capable/);
  assert.match(html, /apple-mobile-web-app-status-bar-style/);
  assert.match(html, /apple-touch-icon/);
  assert.equal(manifest.id, './');
  assert.equal(manifest.display, 'standalone');
  assert.ok(manifest.icons.some((icon) => icon.sizes === '192x192' && icon.type === 'image/png'));
  assert.ok(manifest.icons.some((icon) => icon.sizes === '512x512' && icon.type === 'image/png'));
});

test('service worker and touch target styles stay in place', async () => {
  const sw = await readFile(new URL('../public/sw.js', import.meta.url), 'utf8');
  const css = await readFile(new URL('../src/styles.css', import.meta.url), 'utf8');

  assert.match(sw, /secure-password-vault-v2/);
  assert.match(sw, /manifest\.webmanifest/);
  assert.match(sw, /icon-192\.png/);
  assert.match(css, /env\(safe-area-inset-bottom\)/);
  assert.match(css, /\.btn\.compact\s*\{[^}]*min-height:\s*44px/s);
  assert.match(css, /\.check-line\s*\{[^}]*min-height:\s*44px/s);
});
