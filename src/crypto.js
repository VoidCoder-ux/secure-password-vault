import { argon2id } from '@noble/hashes/argon2.js';

const VAULT_VERSION = 1;
const KEY_BYTES = 32;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const MIN_CIPHERTEXT_BYTES = 16;
const AAD = 'secure-password-vault:v1';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KDF_LIMITS = {
  memoryKiB: { min: 32768, max: 262144 },
  timeCost: { min: 2, max: 6 },
  parallelism: { min: 1, max: 1 }
};

export async function initCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto desteklenmiyor.');
  }
  return globalThis.crypto;
}

export async function getDefaultKdfParams() {
  await initCrypto();
  return {
    algorithm: 'argon2id13',
    memoryKiB: 65536,
    timeCost: 3,
    parallelism: 1
  };
}

export async function getFastTestKdfParams() {
  await initCrypto();
  return {
    algorithm: 'argon2id13',
    memoryKiB: KDF_LIMITS.memoryKiB.min,
    timeCost: KDF_LIMITS.timeCost.min,
    parallelism: 1
  };
}

export async function createEncryptedVault(masterPassword, vault, kdfParams) {
  await initCrypto();
  const salt = randomBytes(SALT_BYTES);
  const params = kdfParams || (await getDefaultKdfParams());
  const key = deriveKey(masterPassword, salt, params);
  const payload = await encryptVaultWithKey(vault, key, {
    version: VAULT_VERSION,
    kdf: params,
    salt: toBase64(salt)
  });
  return { payload, key };
}

export async function unlockVault(masterPassword, payload) {
  await initCrypto();
  validatePayload(payload);
  const salt = fromBase64(payload.salt);
  const key = deriveKey(masterPassword, salt, payload.kdf);
  try {
    const vault = await decryptVaultWithKey(payload, key);
    return { vault, key };
  } catch (error) {
    lockKey(key);
    throw error;
  }
}

export async function encryptVaultWithKey(vault, key, previousPayload) {
  const nonce = randomBytes(NONCE_BYTES);
  const cryptoKey = await importAesKey(key);
  const plaintext = encoder.encode(JSON.stringify(vault));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: encoder.encode(AAD), tagLength: 128 },
    cryptoKey,
    plaintext
  );

  return {
    version: previousPayload.version || VAULT_VERSION,
    kdf: previousPayload.kdf,
    salt: previousPayload.salt,
    cipher: 'aes-256-gcm',
    nonce: toBase64(nonce),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    updatedAt: new Date().toISOString()
  };
}

export async function decryptVaultWithKey(payload, key) {
  validatePayload(payload);
  const cryptoKey = await importAesKey(key);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(payload.nonce), additionalData: encoder.encode(AAD), tagLength: 128 },
    cryptoKey,
    fromBase64(payload.ciphertext)
  );
  return JSON.parse(decoder.decode(plaintext));
}

export function lockKey(key) {
  if (key && key.byteLength) {
    key.fill(0);
  }
}

export function validateEncryptedPayload(payload) {
  validatePayload(payload);
  return true;
}

function deriveKey(masterPassword, salt, params) {
  if (!masterPassword || masterPassword.length < 12) {
    throw new Error('Ana parola en az 12 karakter olmali.');
  }

  return argon2id(encoder.encode(masterPassword), salt, {
    t: params.timeCost,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: KEY_BYTES,
    maxmem: 2 ** 32 - 1
  });
}

function validatePayload(payload) {
  if (!payload || payload.version !== VAULT_VERSION) {
    throw new Error('Kasa formati desteklenmiyor.');
  }
  if (!payload.kdf || payload.kdf.algorithm !== 'argon2id13') {
    throw new Error('KDF ayarlari desteklenmiyor.');
  }
  validateKdfParams(payload.kdf);
  if (payload.cipher !== 'aes-256-gcm') {
    throw new Error('Sifreleme bicimi desteklenmiyor.');
  }
  if (!payload.salt || !payload.nonce || !payload.ciphertext) {
    throw new Error('Kasa dosyasi eksik veya bozuk.');
  }
  const salt = decodeField(payload.salt, 'Salt');
  const nonce = decodeField(payload.nonce, 'Nonce');
  const ciphertext = decodeField(payload.ciphertext, 'Ciphertext');
  if (salt.byteLength !== SALT_BYTES) {
    throw new Error('Kasa salt uzunlugu gecersiz.');
  }
  if (nonce.byteLength !== NONCE_BYTES) {
    throw new Error('Kasa nonce uzunlugu gecersiz.');
  }
  if (ciphertext.byteLength < MIN_CIPHERTEXT_BYTES) {
    throw new Error('Kasa sifreli veri uzunlugu gecersiz.');
  }
}

function validateKdfParams(kdf) {
  validateIntegerRange(kdf.memoryKiB, KDF_LIMITS.memoryKiB, 'Argon2 bellek ayari');
  validateIntegerRange(kdf.timeCost, KDF_LIMITS.timeCost, 'Argon2 zaman ayari');
  validateIntegerRange(kdf.parallelism, KDF_LIMITS.parallelism, 'Argon2 paralellik ayari');
}

function validateIntegerRange(value, limits, label) {
  if (!Number.isInteger(value) || value < limits.min || value > limits.max) {
    throw new Error(`${label} desteklenen aralikta degil.`);
  }
}

function decodeField(value, label) {
  try {
    return fromBase64(value);
  } catch {
    throw new Error(`${label} base64 bicimi gecersiz.`);
  }
}

function toBase64(bytes) {
  if (typeof btoa === 'function') {
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(value) {
  if (typeof atob === 'function') {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  }
  return new Uint8Array(Buffer.from(value, 'base64'));
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function importAesKey(key) {
  return crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
