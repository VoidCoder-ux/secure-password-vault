import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generatePassword, passwordScore } from '../src/password.js';

test('password generator includes requested character groups', () => {
  const password = generatePassword({ length: 32, lower: true, upper: true, digits: true, symbols: true });
  assert.equal(password.length, 32);
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /\d/);
  assert.match(password, /[^a-zA-Z0-9]/);
  assert.equal(passwordScore(password), 5);
});

test('password generator rejects impossible options', () => {
  assert.throws(() => generatePassword({ length: 2, lower: true, upper: true, digits: true, symbols: true }));
});
