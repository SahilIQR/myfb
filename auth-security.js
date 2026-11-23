const crypto = require('crypto');

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizePhone(value) {
  const compact = String(value || '').trim().replace(/[\s()-]/g, '');
  if (/^0[6-8]\d{8}$/.test(compact)) return `+27${compact.slice(1)}`;
  if (/^\+27[6-8]\d{8}$/.test(compact)) return compact;
  return null;
}

function isValidSouthAfricanId(value) {
  const id = String(value || '').trim();
  if (!/^\d{13}$/.test(id)) return false;
  const month = Number(id.slice(2, 4));
  const day = Number(id.slice(4, 6));
  const date = new Date(Date.UTC(2000 + Number(id.slice(0, 2)), month - 1, day));
  if (month < 1 || month > 12 || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return false;

  let sum = 0;
  for (let index = id.length - 1, position = 0; index >= 0; index -= 1, position += 1) {
    let digit = Number(id[index]);
    if (position % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

function identityDigest(value) {
  const secret = String(process.env.IDENTITY_HASH_SECRET || '');
  if (secret.length < 32) return null;
  return crypto.createHmac('sha256', secret).update(String(value)).digest('hex');
}

function hashRecoveryToken(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function isValidAccountPassword(value) {
  return typeof value === 'string' && value.length >= 6 && /\S/.test(value);
}

function isStrongPassword(value) {
  return value.length >= 12 && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /\d/.test(value) && /[^A-Za-z0-9]/.test(value);
}

module.exports = {
  normalizeUsername,
  normalizePhone,
  isValidSouthAfricanId,
  identityDigest,
  hashRecoveryToken,
  isValidAccountPassword,
  isStrongPassword
};
