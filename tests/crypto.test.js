import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createEncryptedVault,
  encryptVaultWithKey,
  getFastTestKdfParams,
  lockKey,
  unlockVault
} from '../src/crypto.js';

test('vault round-trip encrypts and decrypts with the master password', async () => {
  const vault = {
    createdAt: '2026-05-18T00:00:00.000Z',
    updatedAt: '2026-05-18T00:00:00.000Z',
    entries: [{ id: '1', title: 'GitHub', username: 'user', password: 'secret-value' }]
  };

  const { payload, key } = await createEncryptedVault('very-strong-master-password', vault, await getFastTestKdfParams());
  assert.notEqual(payload.ciphertext.includes('secret-value'), true);

  const unlocked = await unlockVault('very-strong-master-password', payload);
  assert.equal(unlocked.vault.entries[0].password, 'secret-value');

  vault.entries[0].password = 'changed-secret';
  const updatedPayload = await encryptVaultWithKey(vault, key, payload);
  const updated = await unlockVault('very-strong-master-password', updatedPayload);
  assert.equal(updated.vault.entries[0].password, 'changed-secret');
  assert.notEqual(updatedPayload.nonce, payload.nonce);

  lockKey(key);
});

test('wrong master password fails authentication', async () => {
  const { payload } = await createEncryptedVault(
    'very-strong-master-password',
    { createdAt: '', updatedAt: '', entries: [] },
    await getFastTestKdfParams()
  );

  await assert.rejects(() => unlockVault('wrong-master-password', payload));
});
