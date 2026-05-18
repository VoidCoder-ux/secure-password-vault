const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const DIGITS = '23456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';

export function generatePassword(options = {}) {
  const length = Number(options.length || 24);
  const pools = [];

  if (options.lower !== false) pools.push(LOWER);
  if (options.upper !== false) pools.push(UPPER);
  if (options.digits !== false) pools.push(DIGITS);
  if (options.symbols !== false) pools.push(SYMBOLS);

  if (!pools.length) {
    throw new Error('En az bir karakter grubu secilmeli.');
  }
  if (length < pools.length || length > 128) {
    throw new Error('Sifre uzunlugu secilen karakter gruplarina uygun degil.');
  }

  const required = pools.map((pool) => pick(pool));
  const all = pools.join('');
  const remaining = Array.from({ length: length - required.length }, () => pick(all));
  return shuffle([...required, ...remaining]).join('');
}

export function passwordScore(password) {
  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 20) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^a-zA-Z0-9]/.test(password)) score += 1;
  return Math.min(score, 5);
}

function pick(pool) {
  const index = secureRandomInt(pool.length);
  return pool[index];
}

function shuffle(values) {
  for (let index = values.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomInt(index + 1);
    [values[index], values[swapIndex]] = [values[swapIndex], values[index]];
  }
  return values;
}

function secureRandomInt(max) {
  if (!Number.isSafeInteger(max) || max <= 0) {
    throw new Error('Gecersiz rastgele aralik.');
  }

  const limit = Math.floor(0xffffffff / max) * max;
  const bytes = new Uint32Array(1);
  do {
    crypto.getRandomValues(bytes);
  } while (bytes[0] >= limit);
  return bytes[0] % max;
}
