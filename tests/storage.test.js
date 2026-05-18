import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateEncryptedPayload } from '../src/crypto.js';

test('invalid imported vault payload is rejected before it can be stored', () => {
  assert.throws(() => validateEncryptedPayload({ foo: 'bar' }), /Kasa formati/);
});
