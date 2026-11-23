const crypto = require('crypto');

const DEFAULT_LIMITS = Object.freeze({
  minimumDepositCents: 2000,
  singleDepositCents: null,
  dailyDepositCents: 50000,
  monthlyDepositCents: 200000
});

const PAYMENT_METHODS = Object.freeze([
  'bank_card',
  'eft',
  'instant_eft',
  'ott_voucher',
  'other'
]);
const DEFAULT_QUICK_AMOUNTS_CENTS = Object.freeze([2000, 5000, 10000, 20000]);

const PROVIDER_STATUS = new Set(['pending', 'confirmed', 'failed', 'cancelled']);

function initializeWallet(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      reference TEXT NOT NULL UNIQUE,
      transaction_type TEXT NOT NULL CHECK (transaction_type IN ('deposit', 'withdrawal')),
      amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
      currency TEXT NOT NULL DEFAULT 'ZAR',
      payment_method TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'failed', 'cancelled', 'review', 'refund_pending', 'refunded')),
      provider_reference TEXT,
      idempotency_key TEXT NOT NULL,
      reconciliation_status TEXT NOT NULL DEFAULT 'not_required',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      FOREIGN KEY(user_id) REFERENCES users(id),
      UNIQUE(user_id, idempotency_key)
    );

    CREATE TABLE IF NOT EXISTS wallet_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      transaction_id INTEGER NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      amount_cents INTEGER NOT NULL CHECK (amount_cents != 0),
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      FOREIGN KEY(transaction_id) REFERENCES wallet_transactions(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS wallet_provider_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider_event_id TEXT NOT NULL UNIQUE,
      transaction_id INTEGER NOT NULL,
      received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      FOREIGN KEY(transaction_id) REFERENCES wallet_transactions(id)
    );

    CREATE TABLE IF NOT EXISTS wallet_user_limits (
      user_id INTEGER PRIMARY KEY,
      single_limit_cents INTEGER,
      daily_limit_cents INTEGER,
      monthly_limit_cents INTEGER,
      requested_single_limit_cents INTEGER,
      requested_daily_limit_cents INTEGER,
      requested_monthly_limit_cents INTEGER,
      requested_effective_at TEXT,
      deposits_paused_until TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS wallet_global_settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS wallet_admin_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_user_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      transaction_reference TEXT,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      FOREIGN KEY(admin_user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS wallet_transactions_user_created
      ON wallet_transactions(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS wallet_transactions_status
      ON wallet_transactions(status, created_at DESC);
  `);

  const insertSetting = db.prepare('INSERT OR IGNORE INTO wallet_global_settings (setting_key, setting_value) VALUES (?, ?)');
  for (const [key, value] of Object.entries(DEFAULT_LIMITS)) {
    insertSetting.run(key, value === null ? 'unlimited' : String(value));
  }
  insertSetting.run('quickAmountsCents', JSON.stringify(DEFAULT_QUICK_AMOUNTS_CENTS));
  insertSetting.run('paymentMethods', JSON.stringify(Object.fromEntries(PAYMENT_METHODS.map((method) => [method, false]))));

  // Older versions seeded R300 as the single-deposit default; preserve all other configured limits.
  db.prepare("UPDATE wallet_global_settings SET setting_value = 'unlimited' WHERE setting_key = 'singleDepositCents' AND setting_value = '30000'").run();
}

function formatRand(cents) {
  return new Intl.NumberFormat('en-ZA', { style: 'currency', currency: 'ZAR' }).format(cents / 100);
}

function parseRandToCents(value) {
  const text = String(value ?? '').trim();
  if (!/^\d{1,14}(?:\.\d{1,2})?$/.test(text)) return null;
  const [rands, fraction = ''] = text.split('.');
  const cents = Number(rands) * 100 + Number(fraction.padEnd(2, '0'));
  return Number.isSafeInteger(cents) ? cents : null;
}

function johannesburgDate(timestamp) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Africa/Johannesburg',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(new Date(timestamp));
  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${values.year}-${values.month}-${values.day}`;
}

function createWalletService(db) {
  const transaction = db.transaction((callback) => callback());

  function getGlobalLimits() {
    const rows = db.prepare('SELECT setting_key, setting_value FROM wallet_global_settings').all();
    const limits = { ...DEFAULT_LIMITS };
    for (const row of rows) {
      if (Object.hasOwn(limits, row.setting_key)) {
        limits[row.setting_key] = row.setting_value === 'unlimited' ? null : Number(row.setting_value);
      }
    }
    return limits;
  }

  function getDepositSettings() {
    const rows = db.prepare('SELECT setting_key, setting_value FROM wallet_global_settings WHERE setting_key IN (?, ?)').all('quickAmountsCents', 'paymentMethods');
    const values = Object.fromEntries(rows.map(({ setting_key, setting_value }) => [setting_key, setting_value]));
    let methods;
    let quickAmounts;
    try {
      methods = JSON.parse(values.paymentMethods || '{}');
      quickAmounts = JSON.parse(values.quickAmountsCents || '[]');
    } catch (error) {
      throw new Error('Stored deposit settings are invalid.', { cause: error });
    }
    const configuredMethods = Object.fromEntries(PAYMENT_METHODS.map((method) => [method, methods[method] === true]));
    const limits = getGlobalLimits();
    const uniqueQuickAmounts = [...new Set(quickAmounts.filter((amount) => Number.isSafeInteger(amount) && amount >= limits.minimumDepositCents))];
    return {
      quickAmountsCents: uniqueQuickAmounts.slice(0, 6),
      requestedPaymentMethods: configuredMethods
    };
  }

  function getUserLimits(userId, now = new Date()) {
    refreshScheduledLimits(userId, now);
    const global = getGlobalLimits();
    const row = db.prepare('SELECT * FROM wallet_user_limits WHERE user_id = ?').get(userId);
    return {
      minimumDepositCents: global.minimumDepositCents,
      singleDepositCents: row?.single_limit_cents == null
        ? global.singleDepositCents
        : global.singleDepositCents == null
          ? row.single_limit_cents
          : Math.min(global.singleDepositCents, row.single_limit_cents),
      dailyDepositCents: Math.min(global.dailyDepositCents, row?.daily_limit_cents || global.dailyDepositCents),
      monthlyDepositCents: Math.min(global.monthlyDepositCents, row?.monthly_limit_cents || global.monthlyDepositCents),
      depositsPausedUntil: row?.deposits_paused_until || null,
      requestedEffectiveAt: row?.requested_effective_at || null,
      requestedSingleLimitCents: row?.requested_single_limit_cents || null,
      requestedDailyLimitCents: row?.requested_daily_limit_cents || null,
      requestedMonthlyLimitCents: row?.requested_monthly_limit_cents || null
    };
  }

  function refreshScheduledLimits(userId, now) {
    const row = db.prepare('SELECT * FROM wallet_user_limits WHERE user_id = ?').get(userId);
    if (!row?.requested_effective_at || new Date(row.requested_effective_at) > now) return;
    db.prepare(`
      UPDATE wallet_user_limits
      SET single_limit_cents = requested_single_limit_cents,
          daily_limit_cents = requested_daily_limit_cents,
          monthly_limit_cents = requested_monthly_limit_cents,
          requested_single_limit_cents = NULL,
          requested_daily_limit_cents = NULL,
          requested_monthly_limit_cents = NULL,
          requested_effective_at = NULL
      WHERE user_id = ?
    `).run(userId);
  }

  function getTotals(userId, now = new Date(), excludeTransactionId = null) {
    const entries = db.prepare(`
      SELECT t.amount_cents, t.status, t.created_at, t.updated_at
      FROM wallet_transactions t
      WHERE t.user_id = ? AND t.transaction_type = 'deposit'
        AND t.status IN ('pending', 'confirmed', 'review')
        AND (? IS NULL OR t.id != ?)
    `).all(userId, excludeTransactionId, excludeTransactionId);
    const today = johannesburgDate(now);
    const month = today.slice(0, 7);
    let daily = 0;
    let monthly = 0;
    let pending = 0;
    let review = 0;
    let confirmed = 0;
    for (const entry of entries) {
      if (entry.status === 'confirmed') {
        const confirmedDate = johannesburgDate(new Date(entry.updated_at));
        if (confirmedDate === today) daily += entry.amount_cents;
        if (confirmedDate.slice(0, 7) === month) monthly += entry.amount_cents;
        confirmed += entry.amount_cents;
      } else {
        // Keep unresolved reservations active across date boundaries until the provider settles them.
        daily += entry.amount_cents;
        monthly += entry.amount_cents;
        if (entry.status === 'pending') pending += entry.amount_cents;
        if (entry.status === 'review') review += entry.amount_cents;
      }
    }
    const balance = db.prepare('SELECT COALESCE(SUM(amount_cents), 0) AS amount FROM wallet_entries WHERE user_id = ?').get(userId).amount;
    const withdrawals = db.prepare(`
      SELECT COALESCE(SUM(amount_cents), 0) AS amount FROM wallet_transactions
      WHERE user_id = ? AND transaction_type = 'withdrawal' AND status = 'confirmed'
    `).get(userId).amount;
    return {
      balanceCents: balance,
      confirmedDepositCents: confirmed,
      confirmedWithdrawalCents: withdrawals,
      pendingDepositCents: pending,
      reviewDepositCents: review,
      dailyDepositCents: daily,
      monthlyDepositCents: monthly
    };
  }

  function getGlobalTotals(now = new Date()) {
    const today = johannesburgDate(now);
    const month = today.slice(0, 7);
    let daily = 0;
    let monthly = 0;
    for (const row of db.prepare(`
      SELECT amount_cents, created_at, updated_at FROM wallet_transactions
      WHERE transaction_type = 'deposit' AND status = 'confirmed'
    `).all()) {
      const date = johannesburgDate(new Date(row.updated_at));
      if (date === today) daily += row.amount_cents;
      if (date.slice(0, 7) === month) monthly += row.amount_cents;
    }
    return { dailyDepositCents: daily, monthlyDepositCents: monthly };
  }

  function validateDeposit(userId, amountCents, now = new Date(), excludeTransactionId = null) {
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0) return { valid: false, reason: 'Enter a valid deposit amount.' };
    const limits = getUserLimits(userId, now);
    const totals = getTotals(userId, now, excludeTransactionId);
    if (limits.depositsPausedUntil && new Date(limits.depositsPausedUntil) > now) {
      return { valid: false, reason: `Deposits are paused until ${new Date(limits.depositsPausedUntil).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' })}.`, limits, totals };
    }
    if (amountCents < limits.minimumDepositCents) return { valid: false, reason: `The minimum deposit is ${formatRand(limits.minimumDepositCents)}.`, limits, totals };
    if (limits.singleDepositCents !== null && amountCents > limits.singleDepositCents) return { valid: false, reason: `The single-deposit limit is ${formatRand(limits.singleDepositCents)}.`, limits, totals };
    if (totals.dailyDepositCents + amountCents > limits.dailyDepositCents) return { valid: false, reason: `This would exceed your daily deposit limit of ${formatRand(limits.dailyDepositCents)}.`, limits, totals };
    if (totals.monthlyDepositCents + amountCents > limits.monthlyDepositCents) return { valid: false, reason: `This would exceed your calendar-month deposit limit of ${formatRand(limits.monthlyDepositCents)}.`, limits, totals };
    return { valid: true, limits, totals };
  }

  function reserveDeposit({ userId, amountCents, paymentMethod, idempotencyKey, now = new Date() }) {
    if (!idempotencyKey || !/^[a-f0-9]{32,128}$/i.test(idempotencyKey)) throw new Error('A valid idempotency key is required.');
    if (!['provider_checkout'].includes(paymentMethod)) throw new Error('This payment method is not configured.');
    return transaction.immediate(() => {
      const existing = db.prepare('SELECT * FROM wallet_transactions WHERE user_id = ? AND idempotency_key = ?').get(userId, idempotencyKey);
      if (existing) return { created: false, transaction: existing };
      const validation = validateDeposit(userId, amountCents, now);
      if (!validation.valid) {
        const error = new Error(validation.reason);
        error.code = 'DEPOSIT_LIMIT';
        throw error;
      }
      const reference = `MYFB-${crypto.randomBytes(12).toString('hex').toUpperCase()}`;
      const result = db.prepare(`
        INSERT INTO wallet_transactions (
          user_id, reference, transaction_type, amount_cents, currency,
          payment_method, status, idempotency_key
        ) VALUES (?, ?, 'deposit', ?, 'ZAR', ?, 'pending', ?)
      `).run(userId, reference, amountCents, paymentMethod, idempotencyKey);
      const created = db.prepare('SELECT * FROM wallet_transactions WHERE id = ?').get(result.lastInsertRowid);
      return { created: true, transaction: created };
    });
  }

  function applyVerifiedProviderEvent({ reference, providerReference, eventId, status, amountCents, currency, signatureValid, timestamp, now = new Date() }) {
    if (signatureValid !== true) throw new Error('Provider signature verification failed.');
    if (!eventId || String(eventId).length > 200) throw new Error('A valid provider event ID is required.');
    if (!(timestamp instanceof Date) || Math.abs(now.getTime() - timestamp.getTime()) > 5 * 60 * 1000) {
      throw new Error('Provider event is outside the accepted replay window.');
    }
    if (!PROVIDER_STATUS.has(status)) throw new Error('Unsupported provider payment status.');
    return transaction.immediate(() => {
      const existingEvent = db.prepare('SELECT id FROM wallet_provider_events WHERE provider_event_id = ?').get(eventId);
      if (existingEvent) return { duplicate: true };
      const payment = db.prepare('SELECT * FROM wallet_transactions WHERE reference = ?').get(reference);
      if (!payment || payment.transaction_type !== 'deposit' || payment.status !== 'pending') return { ignored: true };
      db.prepare('INSERT INTO wallet_provider_events (provider_event_id, transaction_id) VALUES (?, ?)').run(eventId, payment.id);
      if (Number(amountCents) !== payment.amount_cents || currency !== payment.currency) {
        db.prepare(`UPDATE wallet_transactions SET status = 'review', reconciliation_status = 'amount_or_currency_mismatch', provider_reference = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
          .run(providerReference || null, payment.id);
        return { reviewRequired: true };
      }
      if (status !== 'confirmed') {
        db.prepare(`UPDATE wallet_transactions SET status = ?, provider_reference = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
          .run(status, providerReference || null, payment.id);
        return { status };
      }
      const validation = validateDeposit(payment.user_id, payment.amount_cents, now, payment.id);
      if (!validation.valid) {
        db.prepare(`UPDATE wallet_transactions SET status = 'review', reconciliation_status = 'refund_or_manual_review_required', provider_reference = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
          .run(providerReference || null, payment.id);
        return { reviewRequired: true, reason: validation.reason };
      }
      db.prepare(`UPDATE wallet_transactions SET status = 'confirmed', reconciliation_status = 'reconciled', provider_reference = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
        .run(providerReference || null, payment.id);
      db.prepare('INSERT INTO wallet_entries (transaction_id, user_id, amount_cents) VALUES (?, ?, ?)')
        .run(payment.id, payment.user_id, payment.amount_cents);
      return { status: 'confirmed' };
    });
  }

  function saveUserLimits(userId, values, now = new Date()) {
    const limits = getUserLimits(userId);
    const globalLimits = getGlobalLimits();
    const candidate = {
      single: values.single,
      daily: values.daily,
      monthly: values.monthly
    };
    const candidateEffectiveSingle = candidate.single == null
      ? globalLimits.singleDepositCents
      : globalLimits.singleDepositCents == null
        ? candidate.single
        : Math.min(candidate.single, globalLimits.singleDepositCents);
    if ((candidate.single !== null && !Number.isSafeInteger(candidate.single)) ||
        !Number.isSafeInteger(candidate.daily) ||
        !Number.isSafeInteger(candidate.monthly) ||
        (candidate.single !== null && candidate.single < limits.minimumDepositCents) ||
        (candidateEffectiveSingle !== null && candidate.daily < candidateEffectiveSingle) ||
        candidate.monthly < candidate.daily ||
        (candidate.single !== null && globalLimits.singleDepositCents !== null && candidate.single > globalLimits.singleDepositCents) ||
        candidate.daily > globalLimits.dailyDepositCents ||
        candidate.monthly > globalLimits.monthlyDepositCents) {
      throw new Error('Personal limits must be valid and cannot exceed the configured account limits.');
    }
    const current = [limits.singleDepositCents, limits.dailyDepositCents, limits.monthlyDepositCents];
    const requested = [candidateEffectiveSingle, candidate.daily, candidate.monthly];
    const hasIncrease = requested.some((value, index) => value == null ? current[index] != null : current[index] == null ? false : value > current[index]);
    const hasDecrease = requested.some((value, index) => value == null ? false : current[index] == null || value < current[index]);
    if (hasIncrease && hasDecrease) throw new Error('Submit limit decreases first; increases require a separate cooling-off request.');
    if (hasIncrease) {
      const effectiveAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
      db.prepare(`
        INSERT INTO wallet_user_limits (
          user_id, requested_single_limit_cents, requested_daily_limit_cents,
          requested_monthly_limit_cents, requested_effective_at
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          requested_single_limit_cents = excluded.requested_single_limit_cents,
          requested_daily_limit_cents = excluded.requested_daily_limit_cents,
          requested_monthly_limit_cents = excluded.requested_monthly_limit_cents,
          requested_effective_at = excluded.requested_effective_at
      `).run(userId, candidate.single, candidate.daily, candidate.monthly, effectiveAt);
      return { scheduled: true, effectiveAt };
    }
    db.prepare(`
      INSERT INTO wallet_user_limits (user_id, single_limit_cents, daily_limit_cents, monthly_limit_cents)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        single_limit_cents = excluded.single_limit_cents,
        daily_limit_cents = excluded.daily_limit_cents,
        monthly_limit_cents = excluded.monthly_limit_cents,
        requested_single_limit_cents = NULL,
        requested_daily_limit_cents = NULL,
        requested_monthly_limit_cents = NULL,
        requested_effective_at = NULL
    `).run(userId, candidate.single, candidate.daily, candidate.monthly);
    return { scheduled: false };
  }

  function pauseDeposits(userId, durationDays, now = new Date()) {
    if (!Number.isInteger(durationDays) || durationDays < 1 || durationDays > 365) throw new Error('Choose a pause period from 1 to 365 days.');
    const until = new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`
      INSERT INTO wallet_user_limits (user_id, deposits_paused_until) VALUES (?, ?)
      ON CONFLICT(user_id) DO UPDATE SET deposits_paused_until = excluded.deposits_paused_until
    `).run(userId, until);
    return until;
  }

  function queueReview({ adminUserId, reference, reason, action = 'payment_review' }) {
    if (!reason || String(reason).trim().length < 8) throw new Error('Provide a review reason of at least 8 characters.');
    const payment = db.prepare('SELECT id FROM wallet_transactions WHERE reference = ?').get(reference);
    if (!payment) throw new Error('Transaction not found.');
    const reconciliation = action === 'refund_request' ? 'refund_requested_manual_review' : 'manual_review';
    transaction.immediate(() => {
      db.prepare(`UPDATE wallet_transactions SET reconciliation_status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
        .run(reconciliation, payment.id);
      db.prepare('INSERT INTO wallet_admin_audit (admin_user_id, action, transaction_reference, details) VALUES (?, ?, ?, ?)')
        .run(adminUserId, action, reference, String(reason).trim());
    });
  }

  function setGlobalLimits(values, adminUserId) {
    const minimum = values.minimumDepositCents;
    const single = values.singleDepositCents;
    const daily = values.dailyDepositCents;
    const monthly = values.monthlyDepositCents;
    if (!Number.isSafeInteger(minimum) || minimum <= 0 ||
        (single !== null && (!Number.isSafeInteger(single) || single < minimum)) ||
        !Number.isSafeInteger(daily) || daily < minimum || (single !== null && daily < single) ||
        !Number.isSafeInteger(monthly) || monthly < daily) {
      throw new Error('Limits must be positive valid amounts, with daily and monthly limits consistent with the minimum and single-deposit maximum.');
    }
    transaction.immediate(() => {
      const upsert = db.prepare(`
        INSERT INTO wallet_global_settings (setting_key, setting_value) VALUES (?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value
      `);
      for (const [key, value] of Object.entries({
        minimumDepositCents: minimum,
        singleDepositCents: single,
        dailyDepositCents: daily,
        monthlyDepositCents: monthly
      })) upsert.run(key, value === null ? 'unlimited' : String(value));
      db.prepare('INSERT INTO wallet_admin_audit (admin_user_id, action, details) VALUES (?, ?, ?)')
        .run(adminUserId, 'global_limits_updated', JSON.stringify({ minimum, single, daily, monthly }));
    });
  }

  function saveDepositSettings({ quickAmountsCents, requestedPaymentMethods }, adminUserId) {
    const limits = getGlobalLimits();
    if (!Array.isArray(quickAmountsCents) || quickAmountsCents.length > 6 ||
        quickAmountsCents.some((amount) => !Number.isSafeInteger(amount) || amount < limits.minimumDepositCents ||
          (limits.singleDepositCents !== null && amount > limits.singleDepositCents) ||
          amount > limits.dailyDepositCents || amount > limits.monthlyDepositCents)) {
      throw new Error('Quick amounts must be valid amounts within the configured deposit limits.');
    }
    if (!requestedPaymentMethods || Object.keys(requestedPaymentMethods).some((method) => !PAYMENT_METHODS.includes(method)) ||
        PAYMENT_METHODS.some((method) => typeof requestedPaymentMethods[method] !== 'boolean')) {
      throw new Error('Payment method settings are invalid.');
    }
    transaction.immediate(() => {
      const upsert = db.prepare(`
        INSERT INTO wallet_global_settings (setting_key, setting_value) VALUES (?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value
      `);
      upsert.run('quickAmountsCents', JSON.stringify([...new Set(quickAmountsCents)]));
      upsert.run('paymentMethods', JSON.stringify(requestedPaymentMethods));
      db.prepare('INSERT INTO wallet_admin_audit (admin_user_id, action, details) VALUES (?, ?, ?)')
        .run(adminUserId, 'deposit_options_updated', JSON.stringify({ quickAmountsCents, requestedPaymentMethods }));
    });
  }

  return {
    getGlobalLimits,
    getDepositSettings,
    getUserLimits,
    getTotals,
    getGlobalTotals,
    validateDeposit,
    reserveDeposit,
    applyVerifiedProviderEvent,
    saveUserLimits,
    pauseDeposits,
    queueReview,
    setGlobalLimits,
    saveDepositSettings
  };
}

module.exports = {
  DEFAULT_LIMITS,
  PAYMENT_METHODS,
  initializeWallet,
  createWalletService,
  formatRand,
  parseRandToCents
};
