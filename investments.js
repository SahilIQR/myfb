function initializeInvestments(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS investment_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      reference TEXT NOT NULL UNIQUE,
      activity_type TEXT NOT NULL CHECK (activity_type IN ('subscription', 'redemption', 'fee', 'distribution')),
      amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
      currency TEXT NOT NULL DEFAULT 'ZAR',
      status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'failed', 'cancelled', 'review')),
      product_reference TEXT,
      provider_reference TEXT,
      idempotency_key TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      FOREIGN KEY(user_id) REFERENCES users(id),
      UNIQUE(user_id, idempotency_key)
    );

    CREATE INDEX IF NOT EXISTS investment_transactions_user_created
      ON investment_transactions(user_id, created_at DESC);
  `);
}

function getInvestmentActivity(db, userId) {
  return db.prepare(`
    SELECT reference, activity_type, amount_cents, currency, status,
           product_reference, provider_reference, created_at, updated_at
    FROM investment_transactions
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 200
  `).all(userId);
}

function getInvestmentTotals(db, userId) {
  const rows = db.prepare(`
    SELECT activity_type, amount_cents
    FROM investment_transactions
    WHERE user_id = ? AND status = 'confirmed'
      AND activity_type IN ('subscription', 'redemption')
  `).all(userId);
  return rows.reduce((total, row) => {
    total.confirmedSubscriptionsCents += row.activity_type === 'subscription' ? row.amount_cents : 0;
    total.confirmedRedemptionsCents += row.activity_type === 'redemption' ? row.amount_cents : 0;
    return total;
  }, { confirmedSubscriptionsCents: 0, confirmedRedemptionsCents: 0 });
}

module.exports = { initializeInvestments, getInvestmentActivity, getInvestmentTotals };
