const test = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeUsername,
  normalizePhone,
  isValidSouthAfricanId,
  identityDigest,
  hashRecoveryToken,
  isValidAccountPassword,
  isStrongPassword
} = require('../auth-security');

test('normalizes usernames and South African mobile numbers', () => {
  assert.equal(normalizeUsername('  Bright.User_1 '), 'bright.user_1');
  assert.equal(normalizePhone('082 123 4567'), '+27821234567');
  assert.equal(normalizePhone('+27 (82) 123-4567'), '+27821234567');
  assert.equal(normalizePhone('+447700900123'), null);
});

test('checks South African ID checksum and calendar date without claiming identity', () => {
  assert.equal(isValidSouthAfricanId('8001015009087'), true);
  assert.equal(isValidSouthAfricanId('8002315009087'), false);
  assert.equal(isValidSouthAfricanId('8001015009088'), false);
  assert.equal(isValidSouthAfricanId('not-an-id'), false);
});

test('uses a keyed digest for identity matching and a one-way reset-token hash', () => {
  const previousSecret = process.env.IDENTITY_HASH_SECRET;
  process.env.IDENTITY_HASH_SECRET = 'test-only-identity-key-that-is-long-enough';
  const firstDigest = identityDigest('8001015009087');
  assert.equal(identityDigest('8001015009087'), firstDigest);
  assert.notEqual(firstDigest, '8001015009087');
  if (previousSecret === undefined) delete process.env.IDENTITY_HASH_SECRET;
  else process.env.IDENTITY_HASH_SECRET = previousSecret;

  const token = 'single-use-secret-token';
  assert.equal(hashRecoveryToken(token), hashRecoveryToken(token));
  assert.notEqual(hashRecoveryToken(token), token);
});

test('enforces password length and character diversity', () => {
  assert.equal(isStrongPassword('LongPassword123!'), true);
  assert.equal(isStrongPassword('short'), false);
  assert.equal(isStrongPassword('longbutnocase123!'), false);
  assert.equal(isStrongPassword('LongPasswordOnly!'), false);
});

test('allows six-character customer passwords without weakening admin password rules', () => {
  assert.equal(isValidAccountPassword('abc123'), true);
  assert.equal(isValidAccountPassword('abc12'), false);
  assert.equal(isValidAccountPassword(''), false);
  assert.equal(isValidAccountPassword('      '), false);
  assert.equal(isStrongPassword('abc123'), false);
});
