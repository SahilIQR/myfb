const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const {
  DEFAULT_LIMITS,
  initializeWallet,
  createWalletService,
  parseRandToCents
} = require('../wallet');

function createHarness() {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL)');
  db.pragma('foreign_keys = ON');
  initializeWallet(db);
  const userA = Number(db.prepare('INSERT INTO users (email) VALUES (?)').run('a@example.test').lastInsertRowid);
  const userB = Number(db.prepare('INSERT INTO users (email) VALUES (?)').run('b@example.test').lastInsertRowid);
  const service = createWalletService(db);
  return { db, service, userA, userB };
}

function reserve(service, userId, amountCents, idempotencyKey = 'a'.repeat(32), now = new Date()) {
  return service.reserveDeposit({
    userId,
    amountCents,
    paymentMethod: 'provider_checkout',
    idempotencyKey,
    now
  });
}

function providerEvent(service, payment, overrides = {}) {
  return service.applyVerifiedProviderEvent({
    reference: payment.reference,
    providerReference: `provider-${payment.reference}`,
    eventId: `event-${payment.reference}`,
    status: 'confirmed',
    amountCents: payment.amount_cents,
    currency: 'ZAR',
    signatureValid: true,
    timestamp: new Date(),
    ...overrides
  });
}

test('amounts are parsed as exact cents and reject malformed values', () => {
  assert.equal(parseRandToCents('20'), 2000);
  assert.equal(parseRandToCents('20.5'), 2050);
  assert.equal(parseRandToCents('20.05'), 2005);
  assert.equal(parseRandToCents('20.005'), null);
  assert.equal(parseRandToCents('1,000.00'), null);
  assert.equal(parseRandToCents('-20'), null);
  assert.equal(parseRandToCents(''), null);
});

test('upgrades legacy R300 single-deposit default to no configured ceiling', () => {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL);
    CREATE TABLE wallet_global_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL);
  `);
  db.prepare('INSERT INTO wallet_global_settings (setting_key, setting_value) VALUES (?, ?)').run('singleDepositCents', '30000');
  initializeWallet(db);
  assert.equal(createWalletService(db).getGlobalLimits().singleDepositCents, null);
  db.close();
});

test('defaults enforce minimum, no configured single-deposit maximum, daily and monthly limits', () => {
  const { db, service, userA } = createHarness();
  assert.deepEqual(service.getGlobalLimits(), DEFAULT_LIMITS);
  assert.equal(service.validateDeposit(userA, 1999).valid, false);
  assert.equal(service.validateDeposit(userA, 2000).valid, true);
  assert.equal(service.validateDeposit(userA, 30001).valid, true);
  assert.equal(service.validateDeposit(userA, 50001).valid, false);

  const now = new Date();
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT INTO wallet_transactions (
      user_id, reference, transaction_type, amount_cents, currency, payment_method,
      status, idempotency_key, created_at, updated_at
    ) VALUES (?, ?, 'deposit', ?, 'ZAR', 'provider_checkout', 'confirmed', ?, ?, ?)
  `).run(userA, 'MONTH-RESERVE', 199000, 'b'.repeat(32), yesterday, yesterday);
  assert.equal(service.validateDeposit(userA, 2000, now).valid, false);
  db.close();
});

test('daily and monthly accounting follows Africa/Johannesburg boundaries, not UTC dates', () => {
  const { db, service, userA, userB } = createHarness();
  db.prepare(`
    INSERT INTO wallet_transactions (
      user_id, reference, transaction_type, amount_cents, currency, payment_method,
      status, idempotency_key, created_at, updated_at
    ) VALUES (?, 'JHB-MONTH-BOUNDARY', 'deposit', 198000, 'ZAR', 'provider_checkout', 'confirmed', ?, ?, ?)
  `).run(userA, '9'.repeat(32), '2026-09-30T22:10:00.000Z', '2026-09-30T22:10:00.000Z');
  const octoberNow = new Date('2026-10-13T12:00:00.000Z');
  assert.equal(service.getTotals(userA, octoberNow).monthlyDepositCents, 198000);
  assert.equal(service.validateDeposit(userA, 2000, octoberNow).valid, true);
  assert.equal(service.validateDeposit(userA, 2001, octoberNow).valid, false);

  db.prepare(`
    INSERT INTO wallet_transactions (
      user_id, reference, transaction_type, amount_cents, currency, payment_method,
      status, idempotency_key, created_at, updated_at
    ) VALUES (?, 'JHB-DAY-BOUNDARY', 'deposit', 48000, 'ZAR', 'provider_checkout', 'pending', ?, ?, ?)
  `).run(userB, 'a'.repeat(32), '2026-10-12T22:10:00.000Z', '2026-10-12T22:10:00.000Z');
  const johannesburgNextDay = new Date('2026-10-12T22:20:00.000Z');
  assert.equal(service.getTotals(userB, johannesburgNextDay).dailyDepositCents, 48000);
  assert.equal(service.validateDeposit(userB, 2000, johannesburgNextDay).valid, true);
  assert.equal(service.validateDeposit(userB, 2001, johannesburgNextDay).valid, false);
  db.close();
});

test('pending deposits reserve daily capacity and concurrent requests cannot exceed it', async () => {
  const { db, service, userA } = createHarness();
  reserve(service, userA, 30000, '1'.repeat(32));
  const outcomes = await Promise.allSettled([
    Promise.resolve().then(() => reserve(service, userA, 15000, '2'.repeat(32))),
    Promise.resolve().then(() => reserve(service, userA, 15000, '3'.repeat(32)))
  ]);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  assert.equal(service.getTotals(userA).dailyDepositCents, 45000);
  assert.equal(service.validateDeposit(userA, 5001).valid, false);
  db.close();
});

test('idempotent reservations return the existing transaction and provider replay credits once', () => {
  const { db, service, userA } = createHarness();
  const first = reserve(service, userA, 2000);
  const repeated = reserve(service, userA, 2000);
  assert.equal(first.created, true);
  assert.equal(repeated.created, false);
  assert.equal(repeated.transaction.reference, first.transaction.reference);

  assert.deepEqual(providerEvent(service, first.transaction), { status: 'confirmed' });
  assert.deepEqual(providerEvent(service, first.transaction), { duplicate: true });
  assert.equal(service.getTotals(userA).balanceCents, 2000);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM wallet_entries WHERE user_id = ?').get(userA).count, 1);
  db.close();
});

test('invalid signatures and stale webhook timestamps are rejected without credit', () => {
  const { db, service, userA } = createHarness();
  const { transaction: payment } = reserve(service, userA, 2000);
  assert.throws(() => providerEvent(service, payment, { signatureValid: false }), /signature/);
  assert.throws(() => providerEvent(service, payment, { timestamp: new Date(Date.now() - 6 * 60 * 1000) }), /replay window/);
  assert.equal(service.getTotals(userA).balanceCents, 0);
  assert.equal(db.prepare('SELECT status FROM wallet_transactions WHERE id = ?').get(payment.id).status, 'pending');
  db.close();
});

test('verified failed and cancelled provider events remain uncredited and release reservations', () => {
  const { db, service, userA } = createHarness();
  const failed = reserve(service, userA, 20000, '4'.repeat(32)).transaction;
  assert.deepEqual(providerEvent(service, failed, { status: 'failed' }), { status: 'failed' });
  const cancelled = reserve(service, userA, 20000, '5'.repeat(32)).transaction;
  assert.deepEqual(providerEvent(service, cancelled, { status: 'cancelled' }), { status: 'cancelled' });
  assert.equal(service.getTotals(userA).pendingDepositCents, 0);
  assert.equal(service.getTotals(userA).balanceCents, 0);
  db.close();
});

test('amount mismatches and limit changes after payment are reconciled instead of silently credited', () => {
  const { db, service, userA } = createHarness();
  const mismatch = reserve(service, userA, 2000, '6'.repeat(32)).transaction;
  assert.deepEqual(providerEvent(service, mismatch, { amountCents: 2001 }), { reviewRequired: true });
  assert.equal(db.prepare('SELECT status FROM wallet_transactions WHERE id = ?').get(mismatch.id).status, 'review');

  const overLimit = reserve(service, userA, 30000, '7'.repeat(32)).transaction;
  service.setGlobalLimits({
    minimumDepositCents: 2000,
    singleDepositCents: 10000,
    dailyDepositCents: 10000,
    monthlyDepositCents: 10000
  }, userA);
  const result = providerEvent(service, overLimit, { eventId: `limit-${overLimit.reference}` });
  assert.equal(result.reviewRequired, true);
  const stored = db.prepare('SELECT status, reconciliation_status FROM wallet_transactions WHERE id = ?').get(overLimit.id);
  assert.equal(stored.status, 'review');
  assert.equal(stored.reconciliation_status, 'refund_or_manual_review_required');
  assert.equal(service.getTotals(userA).balanceCents, 0);
  db.close();
});

test('wallets are isolated per account and unsupported payment types are rejected', () => {
  const { db, service, userA, userB } = createHarness();
  const payment = reserve(service, userA, 2000).transaction;
  providerEvent(service, payment);
  assert.equal(service.getTotals(userA).balanceCents, 2000);
  assert.equal(service.getTotals(userB).balanceCents, 0);
  assert.throws(() => service.reserveDeposit({
    userId: userB,
    amountCents: 2000,
    paymentMethod: 'ott_voucher',
    idempotencyKey: '8'.repeat(32)
  }), /not configured/);
  db.close();
});

test('customers can lower limits, increases cool off, and deposit pauses apply server-side', () => {
  const { db, service, userA } = createHarness();
  const current = service.saveUserLimits(userA, { single: 10000, daily: 20000, monthly: 40000 });
  assert.equal(current.scheduled, false);
  assert.equal(service.validateDeposit(userA, 10001).valid, false);

  const increase = service.saveUserLimits(userA, { single: 20000, daily: 50000, monthly: 100000 });
  assert.equal(increase.scheduled, true);
  assert.equal(new Date(increase.effectiveAt).getTime() - Date.now() >= 7 * 24 * 60 * 60 * 1000 - 1000, true);

  service.pauseDeposits(userA, 7);
  assert.match(service.validateDeposit(userA, 2000).reason, /paused/);
  db.close();
});

test('admin review/refund requests are auditable and cannot forge a successful transaction', () => {
  const { db, service, userA } = createHarness();
  const payment = reserve(service, userA, 2000).transaction;
  service.queueReview({ adminUserId: userA, reference: payment.reference, reason: 'Check provider payment status', action: 'refund_request' });
  assert.equal(db.prepare('SELECT status FROM wallet_transactions WHERE id = ?').get(payment.id).status, 'pending');
  assert.equal(db.prepare('SELECT reconciliation_status FROM wallet_transactions WHERE id = ?').get(payment.id).reconciliation_status, 'refund_requested_manual_review');
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM wallet_admin_audit WHERE transaction_reference = ?').get(payment.reference).count, 1);
  assert.throws(() => service.queueReview({ adminUserId: userA, reference: payment.reference, reason: 'x', action: 'refund_request' }), /reason/);
  db.close();
});

test('limit configuration is bounded and malformed webhook status cannot credit funds', () => {
  const { db, service, userA } = createHarness();
  assert.throws(() => service.setGlobalLimits({
    minimumDepositCents: 20000,
    singleDepositCents: 10000,
    dailyDepositCents: 30000,
    monthlyDepositCents: 40000
  }, userA), /Limits must be positive/);
  const payment = reserve(service, userA, 2000).transaction;
  assert.throws(() => providerEvent(service, payment, { status: 'succeeded' }), /Unsupported/);
  assert.equal(service.getTotals(userA).balanceCents, 0);
  db.close();
});

test('administrator can remove the single-deposit cap while daily and monthly limits remain enforced', () => {
  const { db, service, userA } = createHarness();
  service.setGlobalLimits({
    minimumDepositCents: 2000,
    singleDepositCents: null,
    dailyDepositCents: 50000,
    monthlyDepositCents: 200000
  }, userA);
  assert.equal(service.getGlobalLimits().singleDepositCents, null);
  assert.equal(service.validateDeposit(userA, 30001).valid, true);
  assert.equal(service.validateDeposit(userA, 50001).valid, false);
  db.close();
});

test('deposit-page settings persist valid quick amounts and requested methods without activating them', () => {
  const { db, service, userA } = createHarness();
  service.saveDepositSettings({
    quickAmountsCents: [2000, 5000, 10000],
    requestedPaymentMethods: {
      bank_card: true,
      eft: false,
      instant_eft: false,
      ott_voucher: false,
      other: false
    }
  }, userA);
  const settings = service.getDepositSettings();
  assert.deepEqual(settings.quickAmountsCents, [2000, 5000, 10000]);
  assert.equal(settings.requestedPaymentMethods.bank_card, true);
  assert.throws(() => service.saveDepositSettings({
    quickAmountsCents: [50001],
    requestedPaymentMethods: settings.requestedPaymentMethods
  }, userA), /within the configured deposit limits/);
  db.close();
});
