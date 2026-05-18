import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateEncryptedPayload } from '../src/crypto.js';
import { readFile } from 'node:fs/promises';

test('invalid imported vault payload is rejected before it can be stored', () => {
  assert.throws(() => validateEncryptedPayload({ foo: 'bar' }), /Kasa formati/);
});

test('vault import normalization keeps URLs restricted to web protocols', async () => {
  const source = await readFile(new URL('../src/main.js', import.meta.url), 'utf8');

  assert.match(source, /url:\s*normalizeUrl\(safeString\(entry\.url\)\.trim\(\)\)/);
  assert.match(source, /const candidate = \/\^\[a-z\]\[a-z\\d\+\.-\]\*:\//);
  assert.match(source, /\['http:', 'https:'\]\.includes\(url\.protocol\)/);
});
