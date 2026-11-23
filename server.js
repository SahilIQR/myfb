const express = require('express');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const { authenticator } = require('otplib');
const {
  normalizeUsername,
  normalizePhone,
  hashRecoveryToken,
  isValidAccountPassword,
  isStrongPassword
} = require('./auth-security');
const defaultAccountMessaging = require('./account-messaging');
require('dotenv').config();

if (process.env.NODE_ENV === 'production' && String(process.env.SESSION_SECRET || '').length < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 characters in production.');
}

const app = express();
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 3000);
const baseUrl = process.env.APP_URL || `http://localhost:${PORT}`;
const defaultDataDirectory = process.platform === 'win32'
  ? path.join(process.env.LOCALAPPDATA || os.homedir(), 'MYFB Investment', 'data')
  : (process.env.RENDER === 'true' ? '/var/data' : path.join(__dirname, 'data'));
const dataDirectory = path.resolve(process.env.MYFB_DATA_DIR || defaultDataDirectory);
const dbPath = path.join(dataDirectory, 'myfb.db');
const DEFAULT_ANNOUNCEMENT = 'MYFB provides user profiles and private support chat. No deposits or investment transactions are available.';
const DEFAULT_COMMUNITY_RULES = [
  'Be respectful. Harassment, threats, hate speech, and impersonation are not allowed.',
  'Do not share passwords, payment credentials, or another person’s private information.',
  'Use your private room for account support. Do not send spam, scams, or unlawful content.',
  'Administrators may close rooms or suspend accounts while reviewing credible reports.'
].join('\n\n');

fs.mkdirSync(dataDirectory, { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

const INVESTMENT_PRODUCT_STATUSES = Object.freeze([
  'Draft',
  'Pending verification',
  'Pending authorization',
  'Approved for publication',
  'Published',
  'Suspended',
  'Archived'
]);

const INVESTMENT_PRODUCT_TEXT_FIELDS = Object.freeze([
  'name',
  'description',
  'potential_outcomes',
  'provider_name',
  'provider_information',
  'fees',
  'time_horizon',
  'eligibility',
  'risk_level',
  'risk_disclosures',
  'liquidity_conditions',
  'terms',
  'provider_verification_reference',
  'legal_review_reference',
  'authorization_reference',
  'documented_approval_reference',
  'payment_operations_reference',
  'transaction_operations_reference'
]);

function publishedInvestmentProducts() {
  if (!investmentServiceConfiguration.enabled) return [];
  return db.prepare(`
    SELECT * FROM investment_products
    WHERE status = 'Published'
      AND provider_verified = 1
      AND legal_reviewed = 1
      AND authorization_verified = 1
      AND payment_operations_verified = 1
      AND transaction_operations_verified = 1
      AND length(trim(name)) > 0
      AND length(trim(description)) > 0
      AND length(trim(provider_name)) > 0
      AND length(trim(provider_information)) > 0
      AND length(trim(fees)) > 0
      AND length(trim(time_horizon)) > 0
      AND length(trim(eligibility)) > 0
      AND length(trim(risk_level)) > 0
      AND length(trim(risk_disclosures)) > 0
      AND length(trim(liquidity_conditions)) > 0
      AND length(trim(terms)) > 0
      AND length(trim(provider_verification_reference)) > 0
      AND length(trim(legal_review_reference)) > 0
      AND length(trim(authorization_reference)) > 0
      AND length(trim(documented_approval_reference)) > 0
      AND length(trim(payment_operations_reference)) > 0
      AND length(trim(transaction_operations_reference)) > 0
    ORDER BY name COLLATE NOCASE
  `).all();
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ''));
}

function isValidPasswordForUser(password, user) {
  return user.role === 'admin' ? isStrongPassword(password) : isValidAccountPassword(password);
}

function passwordRequirementMessage(user) {
  return user.role === 'admin'
    ? 'Administrator passwords must have at least 12 characters with lowercase and uppercase letters, a number, and a symbol.'
    : 'Use a password with at least 6 characters.';
}

async function hashPassword(password) {
  return bcrypt.hashSync(password, 12);
}

function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      is_verified INTEGER DEFAULT 0,
      verification_token TEXT,
      two_factor_secret TEXT,
      two_factor_enabled INTEGER DEFAULT 0,
      security_question TEXT,
      security_answer_hash TEXT,
      address TEXT,
      country TEXT,
      timezone TEXT,
      annual_income TEXT,
      risk_tolerance TEXT,
      portfolio_goal TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      description TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'completed',
      reference TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS support_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      status TEXT NOT NULL DEFAULT 'new'
    );

    CREATE TABLE IF NOT EXISTS account_security_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      subject_digest TEXT,
      source_digest TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS site_settings (
      setting_key TEXT PRIMARY KEY,
      setting_value TEXT NOT NULL,
      updated_by INTEGER REFERENCES users(id),
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS site_settings_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_user_id INTEGER NOT NULL REFERENCES users(id),
      setting_key TEXT NOT NULL,
      previous_value TEXT NOT NULL,
      new_value TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS investment_products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT UNIQUE,
      name TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      potential_outcomes TEXT NOT NULL DEFAULT '',
      provider_name TEXT NOT NULL DEFAULT '',
      provider_information TEXT NOT NULL DEFAULT '',
      minimum_amount_cents INTEGER,
      fees TEXT NOT NULL DEFAULT '',
      time_horizon TEXT NOT NULL DEFAULT '',
      eligibility TEXT NOT NULL DEFAULT '',
      risk_level TEXT NOT NULL DEFAULT '',
      risk_disclosures TEXT NOT NULL DEFAULT '',
      liquidity_conditions TEXT NOT NULL DEFAULT '',
      terms TEXT NOT NULL DEFAULT '',
      provider_verification_reference TEXT NOT NULL DEFAULT '',
      legal_review_reference TEXT NOT NULL DEFAULT '',
      authorization_reference TEXT NOT NULL DEFAULT '',
      documented_approval_reference TEXT NOT NULL DEFAULT '',
      payment_operations_reference TEXT NOT NULL DEFAULT '',
      transaction_operations_reference TEXT NOT NULL DEFAULT '',
      provider_verified INTEGER NOT NULL DEFAULT 0,
      legal_reviewed INTEGER NOT NULL DEFAULT 0,
      authorization_verified INTEGER NOT NULL DEFAULT 0,
      payment_operations_verified INTEGER NOT NULL DEFAULT 0,
      transaction_operations_verified INTEGER NOT NULL DEFAULT 0,
      approved_content_hash TEXT,
      status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN (
        'Draft', 'Pending verification', 'Pending authorization',
        'Approved for publication', 'Published', 'Suspended', 'Archived'
      )),
      created_by INTEGER REFERENCES users(id),
      updated_by INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS investment_product_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL REFERENCES investment_products(id),
      admin_user_id INTEGER NOT NULL REFERENCES users(id),
      action TEXT NOT NULL,
      previous_status TEXT,
      new_status TEXT NOT NULL,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS chat_rooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id INTEGER NOT NULL REFERENCES chat_rooms(id) ON DELETE CASCADE,
      sender_id INTEGER NOT NULL REFERENCES users(id),
      sender_role TEXT NOT NULL CHECK (sender_role IN ('user', 'admin')),
      body TEXT NOT NULL CHECK (length(trim(body)) > 0 AND length(body) <= 4000),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS user_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reporter_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      reported_username TEXT NOT NULL,
      reason TEXT NOT NULL CHECK (reason IN ('harassment', 'impersonation', 'spam', 'other')),
      details TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewing', 'resolved', 'dismissed')),
      admin_notes TEXT NOT NULL DEFAULT '',
      reviewed_by INTEGER REFERENCES users(id),
      reviewed_at TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS moderation_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER REFERENCES user_reports(id) ON DELETE SET NULL,
      admin_user_id INTEGER NOT NULL REFERENCES users(id),
      target_user_id INTEGER NOT NULL REFERENCES users(id),
      action TEXT NOT NULL,
      previous_account_status TEXT NOT NULL,
      new_account_status TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS chat_messages_room_created
      ON chat_messages(room_id, created_at, id);
    CREATE INDEX IF NOT EXISTS user_reports_status_created
      ON user_reports(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS user_reports_reporter_created
      ON user_reports(reporter_user_id, created_at DESC);
  `);

  const userColumns = db.prepare('PRAGMA table_info(users)').all();
  const addMissingColumn = (columnName, definition) => {
    if (!userColumns.some((column) => column.name === columnName)) {
      db.exec(`ALTER TABLE users ADD COLUMN ${columnName} ${definition}`);
    }
  };

  addMissingColumn('first_name', 'TEXT');
  addMissingColumn('last_name', 'TEXT');
  addMissingColumn('username', 'TEXT');
  addMissingColumn('phone_verified', 'INTEGER NOT NULL DEFAULT 0');
  addMissingColumn('identity_status', "TEXT NOT NULL DEFAULT 'unverified'");
  addMissingColumn('identity_method', "TEXT NOT NULL DEFAULT 'legacy_review'");
  addMissingColumn('id_number_hash', 'TEXT');
  addMissingColumn('account_status', "TEXT NOT NULL DEFAULT 'active'");
  addMissingColumn('session_version', 'INTEGER NOT NULL DEFAULT 0');
  addMissingColumn('password_reset_token_hash', 'TEXT');
  addMissingColumn('password_reset_expires_at', 'INTEGER');
  addMissingColumn('password_reset_used_at', 'INTEGER');
  addMissingColumn('password_reset_requested_at', 'INTEGER');
  addMissingColumn('password_reset_request_window_started_at', 'INTEGER');
  addMissingColumn('password_reset_requests', 'INTEGER NOT NULL DEFAULT 0');
  addMissingColumn('phone_otp_requested_at', 'INTEGER');
  addMissingColumn('phone_otp_attempts', 'INTEGER NOT NULL DEFAULT 0');
  addMissingColumn('phone_otp_window_started_at', 'INTEGER');
  addMissingColumn('phone_otp_requests', 'INTEGER NOT NULL DEFAULT 0');
  addMissingColumn('terms_accepted_at', 'TEXT');
  addMissingColumn('privacy_notice_version', 'TEXT');
  addMissingColumn('marketing_email', 'TEXT');
  addMissingColumn('marketing_consent', 'INTEGER NOT NULL DEFAULT 0');
  addMissingColumn('marketing_consent_at', 'TEXT');
  const supportColumns = db.prepare('PRAGMA table_info(support_messages)').all();
  if (!supportColumns.some((column) => column.name === 'user_id')) {
    db.exec('ALTER TABLE support_messages ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE');
  }
  const addSupportColumn = (name, definition) => {
    if (!supportColumns.some((column) => column.name === name)) {
      db.exec(`ALTER TABLE support_messages ADD COLUMN ${name} ${definition}`);
    }
  };
  addSupportColumn('admin_response', 'TEXT');
  addSupportColumn('responded_by', 'INTEGER REFERENCES users(id)');
  addSupportColumn('updated_at', 'TEXT');
  const investmentProductColumns = db.prepare('PRAGMA table_info(investment_products)').all();
  if (!investmentProductColumns.some((column) => column.name === 'approved_content_hash')) {
    db.exec('ALTER TABLE investment_products ADD COLUMN approved_content_hash TEXT');
  }
  if (!investmentProductColumns.some((column) => column.name === 'potential_outcomes')) {
    db.exec("ALTER TABLE investment_products ADD COLUMN potential_outcomes TEXT NOT NULL DEFAULT ''");
  }
  db.prepare("UPDATE support_messages SET status = 'open' WHERE status = 'new' OR status IS NULL").run();

  const usersWithoutUsername = db.prepare('SELECT id, email FROM users WHERE username IS NULL OR username = ?').all('');
  const updateUsername = db.prepare('UPDATE users SET username = ? WHERE id = ?');
  for (const user of usersWithoutUsername) {
    const emailName = normalizeUsername(String(user.email).split('@')[0]).replace(/[^a-z0-9._-]/g, '').slice(0, 20);
    updateUsername.run(`${emailName || 'member'}-${user.id}`, user.id);
  }
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users(username COLLATE NOCASE);
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_normalized_unique ON users(lower(email));
    CREATE UNIQUE INDEX IF NOT EXISTS users_verified_phone_unique ON users(phone)
      WHERE phone_verified = 1 AND phone IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS users_identity_hash_unique ON users(id_number_hash)
      WHERE id_number_hash IS NOT NULL;
  `);

  db.prepare("UPDATE users SET username = 'member-' || id WHERE username IS NULL OR username = ''").run();
  db.prepare("UPDATE users SET is_verified = 1, account_status = 'active' WHERE role != 'admin'").run();
  const adminUsername = normalizeUsername(process.env.ADMIN_USERNAME);
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');
  const configuredAdminEmail = normalizeEmail(process.env.ADMIN_EMAIL || '');
  if (adminUsername || adminPassword) {
    if (!/^[a-z0-9][a-z0-9._-]{2,29}$/.test(adminUsername) || !isStrongPassword(adminPassword)) {
      throw new Error('Set both ADMIN_USERNAME and a strong ADMIN_PASSWORD (12+ characters with upper/lowercase, a number, and a symbol).');
    }
    if (configuredAdminEmail && !isValidEmail(configuredAdminEmail)) {
      throw new Error('ADMIN_EMAIL must be a valid email address.');
    }
    const savedAdminId = Number(db.prepare(`SELECT setting_value FROM site_settings
      WHERE setting_key = 'configured_admin_id'`).get()?.setting_value || 0);
    const configuredAdmin = savedAdminId ? db.prepare('SELECT id FROM users WHERE id = ?').get(savedAdminId) : null;
    const existingAdmin = db.prepare(`SELECT id, role FROM users
      WHERE lower(username) = ?`).get(adminUsername);
    if (existingAdmin && existingAdmin.role !== 'admin') {
      throw new Error('ADMIN_USERNAME already belongs to a non-admin account.');
    }
    const legacyAdmin = existingAdmin || configuredAdmin ? null : db.prepare(`SELECT id FROM users
      WHERE account_status = 'admin_setup_required' OR lower(email) = ?`).get('sahil.lume@gmail.com');
    const adminEmail = configuredAdminEmail || `${adminUsername}@admin.myfb.invalid`;
    if (existingAdmin || configuredAdmin || legacyAdmin) {
      const adminId = existingAdmin ? existingAdmin.id : (configuredAdmin ? configuredAdmin.id : legacyAdmin.id);
      db.prepare(`UPDATE users SET username = ?, email = ?, password_hash = ?, role = 'admin',
        is_verified = 1, account_status = 'active', session_version = session_version + 1,
        updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
        .run(adminUsername, adminEmail, bcrypt.hashSync(adminPassword, 12), adminId);
      db.prepare(`INSERT INTO site_settings (setting_key, setting_value) VALUES ('configured_admin_id', ?)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value`).run(String(adminId));
    } else {
      const adminId = db.prepare(`INSERT INTO users (
        full_name, first_name, last_name, username, email, password_hash, role,
        is_verified, account_status, terms_accepted_at, privacy_notice_version
      ) VALUES (?, ?, ?, ?, ?, ?, 'admin', 1, 'active', CURRENT_TIMESTAMP, '2026-01')`)
        .run('MYFB Administrator', 'MYFB', 'Administrator', adminUsername, adminEmail, bcrypt.hashSync(adminPassword, 12));
      db.prepare('INSERT INTO chat_rooms (user_id) VALUES (?)').run(adminId.lastInsertRowid);
      db.prepare(`INSERT INTO site_settings (setting_key, setting_value) VALUES ('configured_admin_id', ?)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value`).run(String(adminId.lastInsertRowid));
    }
  } else {
    const legacyAdmin = db.prepare(`SELECT id FROM users
      WHERE (lower(email) = ? AND role = 'admin') OR account_status = 'admin_setup_required'`).get('sahil.lume@gmail.com');
    if (legacyAdmin) {
      db.prepare(`UPDATE users SET password_hash = ?, email = ?, marketing_email = NULL,
        marketing_consent = 0, marketing_consent_at = NULL, role = 'user', account_status = 'admin_setup_required',
        session_version = session_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
        .run(bcrypt.hashSync(crypto.randomBytes(48).toString('hex'), 12), `legacy-admin-${legacyAdmin.id}@myfb.invalid`, legacyAdmin.id);
      console.warn('Legacy development administrator disabled. Configure ADMIN_USERNAME and ADMIN_PASSWORD to enable administrator access.');
    }
  }
  db.prepare(`UPDATE users SET email = 'account-' || id || '@myfb.invalid'
    WHERE email NOT LIKE '%@myfb.invalid' AND role != 'admin'`).run();
  db.prepare('INSERT OR IGNORE INTO chat_rooms (user_id) SELECT id FROM users').run();
  if (!db.prepare("SELECT id FROM users WHERE role = 'admin' AND account_status = 'active' LIMIT 1").get()) {
    console.warn('No administrator is configured. Set ADMIN_USERNAME and ADMIN_PASSWORD to enable admin access.');
  }
  db.prepare(`UPDATE users SET id_number_hash = NULL, identity_method = 'deferred_bank_setup'
    WHERE id_number_hash IS NOT NULL OR identity_method IN ('south_african_id', 'alternative_review')`).run();
  db.prepare("DELETE FROM account_security_audit WHERE created_at < datetime('now', '-90 days')").run();
  const setDefault = db.prepare('INSERT OR IGNORE INTO site_settings (setting_key, setting_value) VALUES (?, ?)');
  setDefault.run('announcement', DEFAULT_ANNOUNCEMENT);
  setDefault.run('community_rules', DEFAULT_COMMUNITY_RULES);
  setDefault.run('whatsapp_number', '');
  db.prepare(`UPDATE site_settings SET setting_value = ? WHERE setting_key = 'announcement'
    AND setting_value = ?`).run(
    DEFAULT_ANNOUNCEMENT,
    'MYFB Investment shares educational information to help you make informed decisions. This is not personal investment advice.'
  );
  db.prepare(`UPDATE site_settings SET setting_value = ? WHERE setting_key = 'announcement'
    AND setting_value = ?`).run(
    DEFAULT_ANNOUNCEMENT,
    'MYFB Investment shares educational information for clearer investment decisions. This is not personal investment advice. Developed by Sahil Phakathwayo. Contact us on WhatsApp or leave a message here.'
  );
}

initDatabase();
const paymentConfiguration = Object.freeze({
  requestedProvider: String(process.env.PAYMENT_PROVIDER || 'none').trim().toLowerCase(),
  provider: 'none',
  mode: 'test',
  realPaymentsEnabled: false,
  supportedMethods: []
});
const investmentServiceConfiguration = Object.freeze({
  provider: 'none',
  enabled: false
});
const PAYMENT_METHOD_LABELS = Object.freeze({
  bank_card: 'Visa / Mastercard hosted checkout',
  eft: 'EFT or bank transfer',
  instant_eft: 'Instant EFT',
  ott_voucher: 'OTT voucher',
  other: 'Other provider-supported method'
});

function recordSecurityEvent(req, eventType, subject = '') {
  const key = process.env.AUDIT_HASH_SECRET || process.env.SESSION_SECRET || 'development-audit-key-change-me';
  const digest = (value) => crypto.createHmac('sha256', key).update(String(value)).digest('hex');
  db.prepare('INSERT INTO account_security_audit (event_type, subject_digest, source_digest) VALUES (?, ?, ?)')
    .run(eventType, subject ? digest(subject) : null, digest(req.ip || 'unknown'));
}

const publicPages = new Set([
  '/',
  '/about',
  '/how-it-works',
  '/investment-information',
  '/trading-risks',
  '/faq',
  '/contact',
  '/login',
  '/register',
  '/privacy-policy',
  '/terms-and-conditions',
  '/risk-disclosure',
  '/complaints-procedure',
  '/account-security'
]);

function getCurrentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId) || null;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function getSiteSetting(key) {
  return db.prepare('SELECT setting_value FROM site_settings WHERE setting_key = ?').get(key)?.setting_value || '';
}

function whatsappUrl(number = getSiteSetting('whatsapp_number')) {
  const digits = String(number || '').replace(/\D/g, '');
  return digits.length >= 10 && digits.length <= 15 ? `https://wa.me/${digits}` : '';
}

function parseOptionalRandToCents(value) {
  if (String(value ?? '').trim() === '') return null;
  return parseRandToCents(value);
}

function csrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  return `<input type="hidden" name="_csrf" value="${escapeHtml(req.session.csrfToken)}" />`;
}

function requireCsrf(req, res, next) {
  const expected = Buffer.from(String(req.session.csrfToken || ''));
  const received = Buffer.from(String(req.body._csrf || ''));
  if (expected.length !== received.length || expected.length === 0 || !crypto.timingSafeEqual(expected, received)) {
    return res.status(403).send('Request could not be verified. Refresh the page and try again.');
  }
  next();
}

function setFlash(req, message, type = 'success') {
  if (!req.session.flash) {
    req.session.flash = [];
  }
  req.session.flash.push({ message, type });
}

function buildNavigation(user) {
  const publicLinks = [
    ['Home', '/'],
    ['About Us', '/about'],
    ['How It Works', '/how-it-works'],
    ['Investment Information', '/investment-information'],
    ['Trading Risks', '/trading-risks'],
    ['FAQs', '/faq'],
    ['Contact Us', '/contact']
  ];

  const authLinks = [
    ['Dashboard', '/dashboard'],
    ['Account', '/account'],
    ['Chat room', '/rooms'],
    ['Notifications', '/notifications'],
    ['Security Centre', '/security'],
  ];

  const adminLinks = [
    ['Admin Dashboard', '/admin'],
    ['Chat rooms', '/admin/rooms'],
    ['Website Settings', '/admin/settings'],
    ['Security Centre', '/security'],
  ];

  const navItems = user
    ? (user.role === 'admin' ? [...adminLinks, ['Sign Out', '/logout']] : [...authLinks, ['Sign Out', '/logout']])
    : [...publicLinks, ['Sign In', '/login'], ['Create Account', '/register']];

  return navItems.map(([label, href]) => `
    <a href="${href}" class="nav-link">${label}</a>
  `).join('');
}

function renderPage({ title, user, body, pageClass = 'page-shell' }) {
  body = body.replace(/<main\b/, '<main id="main-content"');
  if (!body.includes('id="main-content"')) {
    body = `<main id="main-content">${body}</main>`;
  }
  const flashMessages = global.__flash || [];
  const flashHtml = flashMessages.length
    ? flashMessages.map(({ type, message }) => `
      <div class="flash ${type}">${message}</div>
    `).join('')
    : '';

  const navHtml = buildNavigation(user);
  const adminBadge = user && user.role === 'admin' ? '<span class="admin-pill">Administrator</span>' : '';
  const announcement = getSiteSetting('announcement');
  const whatsapp = whatsappUrl();

  return `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <meta name="description" content="MYFB Investment provides secure account access, private customer support, and clear investment education." />
      <meta name="theme-color" content="#0B1220" />
      <meta property="og:type" content="website" />
      <meta property="og:title" content="${title} | MYFB Investment" />
      <meta property="og:description" content="Secure accounts, private support rooms, and transparent investment education." />
      <title>${title} | MYFB Investment</title>
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
      <link rel="stylesheet" href="/css/style.css" />
    </head>
    <body class="${pageClass}">
      <a class="skip-link" href="#main-content">Skip to main content</a>
      <header class="site-header">
        <div class="developer-credit-bar">
          <div class="container">Developed by <strong>Sahil Phakathwayo</strong></div>
        </div>
        <div class="container nav-wrap">
          <a href="/" class="brand" aria-label="MYFB Investment homepage">
            <span class="brand-mark">M</span>
            <span class="brand-text">
              <strong>MYFB</strong>
              <small>Investment</small>
            </span>
          </a>
          <nav class="main-nav" aria-label="Main navigation">
            ${navHtml}
          </nav>
          <button class="theme-toggle" type="button" aria-label="Switch to dark theme" aria-pressed="false">Dark mode</button>
          <button class="nav-toggle" aria-label="Open navigation menu" aria-expanded="false">☰</button>
        </div>
      </header>
      <div class="flash-container">${flashHtml}</div>
      ${adminBadge ? `<div class="admin-banner">${adminBadge}</div>` : ''}
      ${announcement ? `<div class="announcement" role="region" aria-label="MYFB Investment announcement"><div class="announcement-track"><span>${escapeHtml(announcement)}</span><span aria-hidden="true">${escapeHtml(announcement)}</span></div></div>` : ''}
      ${body}
      <footer class="site-footer">
        <div class="container footer-grid">
          <div>
            <div class="brand brand-footer">
              <span class="brand-mark">M</span>
              <span class="brand-text">
                <strong>MYFB</strong>
                <small>Investment</small>
              </span>
            </div>
            <p>Professional account access, investment education, and transparent digital support for modern investors.</p>
          </div>
          <div>
            <h4>Company</h4>
            <ul>
              <li><a href="/about">About Us</a></li>
              <li><a href="/contact">Contact Us</a></li>
              <li><a href="/faq">Frequently Asked Questions</a></li>
            </ul>
          </div>
          <div>
            <h4>Legal</h4>
            <ul>
              <li><a href="/privacy-policy">Privacy Policy</a></li>
              <li><a href="/terms-and-conditions">Terms and Conditions</a></li>
              <li><a href="/risk-disclosure">Risk Disclosure</a></li>
              <li><a href="/complaints-procedure">Complaints Procedure</a></li>
              <li><a href="/community-rules">Community Rules</a></li>
            </ul>
          </div>
          <div>
            <h4>Support</h4>
            <ul>
              <li><a href="/account-security">Account Security</a></li>
              <li><a href="/support">Help and Support</a></li>
              ${whatsapp ? `<li><a href="${whatsapp}" target="_blank" rel="noopener noreferrer">Contact us on WhatsApp</a></li>` : ''}
              <li><a href="/login">Sign In</a></li>
            </ul>
          </div>
        </div>
        <div class="container footer-bottom">
          <span>© 2026 MYFB Investment. All rights reserved.</span>
          <span>Educational information only. Not investment advice.</span>
          <span>Website Developed by Sahil Phakathwayo</span>
        </div>
      </footer>
      <script src="/js/main.js"></script>
    </body>
    </html>`;
}

function renderPublicPage({ title, user, pageClass, body }) {
  return renderPage({ title, user, pageClass, body: `<main class="container page-layout">${body}</main>` });
}

function buildStatCard(label, value, tone = 'info') {
  return `
    <div class="stat-card ${tone}">
      <span class="label">${label}</span>
      <strong>${value}</strong>
    </div>
  `;
}

function homePageBody(user) {
  return `
    <main class="hero-section">
      <div class="container hero-grid">
        <div class="hero-copy">
          <p class="eyebrow">MYFB INVESTMENT</p>
          <h1>MAKE YOUR FUTURE BRIGHT</h1>
          <p class="lead">Create a secure account, manage your profile, and contact the MYFB team through private support chat.</p>
          <div class="cta-row">
            <a href="/register" class="btn btn-primary">Create Your Account</a>
            <a href="/how-it-works" class="btn btn-secondary">Learn How It Works</a>
          </div>
          <ul class="quick-benefits">
            <li>Username and password sign-in</li>
            <li>Private customer support rooms</li>
            <li>No deposits or financial transactions</li>
          </ul>
        </div>
        <div class="hero-visual" aria-label="Private support chat preview">
          <div class="visual-panel">
            <div class="panel-header">
              <span class="status-dot green"></span>
              <span class="status-dot gold"></span>
              <span class="status-dot red"></span>
              <span class="visual-title">Private support room</span>
            </div>
            <div class="chat-preview">
              <p class="chat-preview-label">Example conversation</p>
              <p class="chat-bubble customer">I need help updating my profile.</p>
              <p class="chat-bubble">Of course. Send your question here.</p>
            </div>
            <div class="account-summary">
              <div>
                <small>Account access</small>
                <strong>Username and password</strong>
              </div>
              <span class="positive">Private</span>
            </div>
            <div class="profile-metrics">
              <div>
                <small>Your profile</small>
                <strong>Update your details</strong>
              </div>
              <div>
                <small>Support</small>
                <strong>Chat privately</strong>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>

    <section class="container section-block">
      <div class="section-header center">
        <p class="eyebrow accent">Trust and transparency</p>
        <h2>Built around clarity, security, and good decision-making.</h2>
      </div>
      <div class="card-grid three-col">
        <article class="info-card">
          <div class="icon-wrap">01</div>
          <h3>Account Management</h3>
          <p>Review your profile, security settings, notifications, and account activity in one place.</p>
        </article>
        <article class="info-card">
          <div class="icon-wrap">02</div>
          <h3>Personal Profile</h3>
          <p>Keep your profile details and account preferences up to date from your signed-in account.</p>
        </article>
        <article class="info-card">
          <div class="icon-wrap">03</div>
          <h3>Private Support Chat</h3>
          <p>Open your private room to contact the admin team. Your conversation is not public.</p>
        </article>
        <article class="info-card">
          <div class="icon-wrap">04</div>
          <h3>Account Security</h3>
          <p>Sign in with a username and password, and change your password from your account when needed.</p>
        </article>
        <article class="info-card">
          <div class="icon-wrap">05</div>
          <h3>Advertising Preferences</h3>
          <p>Email is optional and used only for advertising if you choose to provide it and consent.</p>
        </article>
        <article class="info-card">
          <div class="icon-wrap">06</div>
          <h3>No Financial Transactions</h3>
          <p>This website does not accept deposits, process withdrawals, or provide investment transactions.</p>
        </article>
      </div>
    </section>

    <section class="container section-block alt-bg">
      <div class="section-header center">
        <p class="eyebrow accent">How it works</p>
        <h2>Simple, secure, and transparent steps.</h2>
      </div>
      <div class="timeline-grid">
        <div class="timeline-item">
          <span class="step-num">1</span>
          <h3>Create an Account</h3>
          <p>Create an account using a username and password. Email is optional and requires advertising consent.</p>
        </div>
        <div class="timeline-item">
          <span class="step-num">2</span>
          <h3>Set Up Your Profile</h3>
          <p>Review your profile details and choose whether to opt in to advertising email.</p>
        </div>
        <div class="timeline-item">
          <span class="step-num">3</span>
          <h3>Sign In Securely</h3>
          <p>Use a strong password and update it from your account whenever you need to.</p>
        </div>
        <div class="timeline-item">
          <span class="step-num">4</span>
          <h3>Chat Privately</h3>
          <p>Send a message to the admin team through your private support room.</p>
        </div>
        <div class="timeline-item">
          <span class="step-num">5</span>
          <h3>Explore Educational Information</h3>
          <p>Read public information; no deposits, withdrawals, or investment transactions are available.</p>
        </div>
      </div>
    </section>

    <section class="container section-block">
      <div class="section-header center">
        <p class="eyebrow accent">Investment education</p>
        <h2>Understanding the basics before you decide.</h2>
      </div>
      <div class="educational-grid">
        <div class="education-copy">
          <ul>
            <li><strong>What investing means:</strong> allocating money with the goal of creating future value, while accepting the possibility of loss.</li>
            <li><strong>How financial markets work:</strong> they connect buyers and sellers through price discovery, liquidity, and changing economic conditions.</li>
            <li><strong>Saving vs investing:</strong> saving focuses on security and access to cash; investing aims for growth but carries risk.</li>
            <li><strong>Why investments can lose value:</strong> markets fluctuate and some products are more volatile than others.</li>
            <li><strong>Past performance is not a guarantee:</strong> previous results do not predict future outcomes.</li>
            <li><strong>Fees and risks matter:</strong> charges, taxes, and product-specific risks can materially affect outcomes.</li>
            <li><strong>Verify providers before paying money:</strong> confirm the legitimacy and terms of any financial service before transferring funds.</li>
          </ul>
        </div>
        <div class="highlight-card">
          <h3>Your Financial Journey Starts With Understanding.</h3>
          <div class="cta-row stacked">
            <a href="/register" class="btn btn-primary">Create Account</a>
            <a href="/investment-information" class="btn btn-secondary">Explore Investment Information</a>
          </div>
        </div>
      </div>
    </section>
  `;
}

function renderStaticPage({ title, user, html, pageClass = 'public-page' }) {
  return renderPage({ title, user, pageClass, body: `<div class="content-panel">${html}</div>` });
}

function passwordStrengthControl(inputId, adminPasswordPolicy = false) {
  return `
    <div class="full-span password-strength" data-password-strength-for="${inputId}"
      data-admin-password-policy="${adminPasswordPolicy}">
      <div class="password-strength-track" role="meter" aria-labelledby="${inputId}-strength-label"
        aria-valuemin="0" aria-valuemax="4" aria-valuenow="0" aria-valuetext="Not entered"><span></span></div>
      <p class="password-strength-label" id="${inputId}-strength-label" aria-live="polite">
        Password strength: <strong data-strength-label>Not entered</strong>
      </p>
    </div>
  `;
}

function aboutPage(user) {
  return renderStaticPage({
    title: 'About Us',
    user,
    pageClass: 'about-page',
    html: `
      <p class="eyebrow accent">About MYFB Investment</p>
      <h1>Trusted financial access, designed around clarity.</h1>
      <p>MYFB Investment helps people manage their financial life with confidence. We provide secure account access, transparent information, practical educational resources, and straightforward account support.</p>
      <p>Our mission is to help customers understand what they are signing up for, review their activity, and make informed decisions based on clear information, realistic risk awareness, and reliable digital tools.</p>
      <div class="card-grid two-col">
        <article class="info-card">
          <h3>Our approach</h3>
          <p>We focus on clarity, education, and strong digital safeguards so people can access their account and understand product information without confusion.</p>
        </article>
        <article class="info-card">
          <h3>Our promise</h3>
          <p>We do not promise guaranteed returns or risk-free investments. We provide tools and educational context so customers can evaluate opportunities responsibly.</p>
        </article>
      </div>
    `
  });
}

function faqPage(user) {
  return renderStaticPage({
    title: 'Frequently Asked Questions',
    user,
    html: `
      <p class="eyebrow accent">FAQs</p>
      <h1>Questions we hear most often.</h1>
      <div class="faq-list">
        <div class="faq-item">
          <h3>Do I need to register before I can review investment information?</h3>
          <p>Not necessarily. Public information is available without an account, but account access is required for personal dashboards and secure updates.</p>
        </div>
        <div class="faq-item">
          <h3>Can I deposit money or make an investment here?</h3>
          <p>No. MYFB provides profiles, private support chat, and public educational information. It does not accept deposits or provide financial transactions.</p>
        </div>
        <div class="faq-item">
          <h3>How do I protect my account?</h3>
          <p>Use a strong, unique password and change it from your signed-in account when needed.</p>
        </div>
        <div class="faq-item">
          <h3>Can I contact support if I need help?</h3>
          <p>Yes. Sign in and send a message through your private support room. Email is optional and is only collected for advertising with your consent.</p>
        </div>
      </div>
    `
  });
}

function contactPage(user, req) {
  const whatsapp = whatsappUrl();
  return renderStaticPage({
    title: 'Contact Us',
    user,
    html: `
      <p class="eyebrow accent">Contact</p>
      <h1>Contact the MYFB team</h1>
      <p>For private account help, sign in and send a message in your chat room. Each conversation is visible only to its customer and authorized administrators.</p>
      ${user
        ? '<p><a class="btn btn-primary" href="/rooms">Open your private chat room</a></p>'
        : '<p><a class="btn btn-primary" href="/register">Create an account to chat</a> <a class="btn btn-secondary" href="/login">Sign in</a></p>'}
      ${whatsapp ? `<p><a class="btn btn-secondary" href="${whatsapp}" target="_blank" rel="noopener noreferrer">Contact us on WhatsApp</a></p>` : ''}
    `
  });
}

function staticLegalPage({ title, user, heading, body }) {
  return renderStaticPage({
    title,
    user,
    html: `
      <p class="eyebrow accent">${title}</p>
      <h1>${heading}</h1>
      ${body}
    `
  });
}

function loginPage(user, errorMessage = '', csrf = '') {
  const message = errorMessage ? `<div class="alert error">${escapeHtml(errorMessage)}</div>` : '';
  return renderPage({
    title: 'Sign In',
    user,
    pageClass: 'auth-page',
    body: `
      <main class="container auth-wrap">
        <div class="auth-card">
          <p class="eyebrow accent">Welcome back</p>
          <h1>Sign in to your account</h1>
          ${message}
          <form method="POST" action="/login" class="stacked-form">
            ${csrf}
            <label>
              Username
              <input type="text" name="username" autocomplete="username" placeholder="Enter your username" required />
            </label>
            <label>
              Password
              <input type="password" name="password" autocomplete="current-password" placeholder="Enter your password" required />
            </label>
            <button type="submit" class="btn btn-primary full-width">Sign In</button>
          </form>
          <p class="auth-links">Email verification is not required. Use your username to sign in.</p>
          <p class="auth-links">Need an account? <a href="/register">Create one here</a></p>
        </div>
      </main>
    `
  });
}

function registerPage(user, errorMessage = '', csrf = '') {
  const message = errorMessage ? `<div class="alert error">${escapeHtml(errorMessage)}</div>` : '';
  return renderPage({
    title: 'Create Account',
    user,
    pageClass: 'auth-page',
    body: `
      <main class="container auth-wrap">
        <div class="auth-card wide">
          <p class="eyebrow accent">Create your account</p>
          <h1>Register with MYFB Investment</h1>
          ${message}
          <form method="POST" action="/register" class="stacked-form two-col-form">
            ${csrf}
            <label>
              Legal first name
              <input type="text" name="firstName" autocomplete="given-name" required />
            </label>
            <label>
              Legal last name
              <input type="text" name="lastName" autocomplete="family-name" required />
            </label>
            <label>
              Username
              <input type="text" name="username" autocomplete="username" minlength="3" maxlength="30" pattern="[A-Za-z0-9][A-Za-z0-9._\\x2d]{2,29}" required />
            </label>
            <label class="full-span">
              Optional email for advertising
              <input type="email" name="email" autocomplete="email" placeholder="you@example.com" />
            </label>
            <label class="full-span checkbox-label">
              <input type="checkbox" name="marketingConsent" value="on" />
              I agree to receive advertising emails. This is optional and is not used for sign-in or account verification.
            </label>
            <label>
              Password
              <input id="register-password" type="password" name="password" autocomplete="new-password"
                minlength="6" placeholder="At least 6 characters"
                aria-describedby="register-password-strength-label register-password-requirements"
                required />
            </label>
            <label>
              Confirm password
              <input type="password" name="confirmPassword" autocomplete="new-password" required />
            </label>
            ${passwordStrengthControl('register-password')}
            <p class="full-span form-help" id="register-password-requirements">Use at least 6 characters. Longer, unique passwords are safer.</p>
            <p class="full-span form-help">Your email is optional and is only saved for advertising if you opt in. You can create an account with just your username and password.</p>
            <label class="full-span checkbox-label">
              <input type="checkbox" name="termsAccepted" value="on" required />
              I accept the <a href="/terms-and-conditions">Terms and Conditions</a> and acknowledge the <a href="/privacy-policy">Privacy Notice</a>.
            </label>
            <button type="submit" class="btn btn-primary full-width full-span">Create account</button>
          </form>
          <p class="auth-links">Already registered? <a href="/login">Sign in</a></p>
        </div>
      </main>
    `
  });
}

function recoveryPage(kind, errorMessage = '', csrf = '', token = '', adminPasswordPolicy = false) {
  const forgotPassword = kind === 'password';
  const message = errorMessage ? `<div class="alert error">${escapeHtml(errorMessage)}</div>` : '';
  const title = forgotPassword ? 'Forgot Password?' : 'Forgot Username?';
  const action = forgotPassword ? '/forgot-password' : '/forgot-username';
  const reset = kind === 'reset';
  const passwordMinLength = adminPasswordPolicy ? 12 : 6;
  const passwordRequirements = adminPasswordPolicy
    ? 'Administrator passwords require 12+ characters with lowercase and uppercase letters, a number, and a symbol.'
    : 'Use at least 6 characters. Longer, unique passwords are safer.';
  return renderPage({
    title: reset ? 'Reset Password' : title,
    user: null,
    pageClass: 'auth-page',
    body: `
      <main class="container auth-wrap">
        <div class="auth-card">
          <p class="eyebrow accent">Account recovery</p>
          <h1>${reset ? 'Choose a new password' : title}</h1>
          ${message}
          ${reset ? `
            <form method="POST" action="/reset-password/${encodeURIComponent(token)}" class="stacked-form">
              ${csrf}
              <label>New password<input id="reset-password" type="password" name="password" autocomplete="new-password"
                minlength="${passwordMinLength}" placeholder="At least ${passwordMinLength} characters"
                aria-describedby="reset-password-strength-label reset-password-requirements" required /></label>
              ${passwordStrengthControl('reset-password', adminPasswordPolicy)}
              <p class="form-help" id="reset-password-requirements">${passwordRequirements}</p>
              <label>Confirm new password<input type="password" name="confirmPassword" autocomplete="new-password" required /></label>
              <button class="btn btn-primary full-width" type="submit">Reset password</button>
            </form>
          ` : `
            <form method="POST" action="${action}" class="stacked-form">
              ${csrf}
              <label>${forgotPassword ? 'Registered email address' : 'Verified email address or mobile number'}
                <input type="text" name="identifier" autocomplete="email" required />
              </label>
              <button class="btn btn-primary full-width" type="submit">Continue</button>
            </form>
          `}
          <p class="auth-links"><a href="/login">Return to sign in</a></p>
        </div>
      </main>
    `
  });
}

function phoneVerificationPage(user, errorMessage = '', csrf = '', codeEntry = false) {
  const message = errorMessage ? `<div class="alert error">${escapeHtml(errorMessage)}</div>` : '';
  const messaging = reqSmsConfigured();
  return renderPage({
    title: 'Verify mobile number',
    user,
    pageClass: 'auth-page',
    body: `
      <main class="container auth-wrap"><div class="auth-card">
        <p class="eyebrow accent">Account security</p>
        <h1>Verify your mobile number</h1>
        ${message}
        <p>Phone verification is separate from email verification and authenticator-app codes.</p>
        ${messaging ? (codeEntry ? `
          <form method="POST" action="/verify-phone" class="stacked-form">
            ${csrf}
            <label>SMS verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="10" required /></label>
            <button class="btn btn-primary full-width" type="submit">Verify number</button>
          </form>
          <form method="POST" action="/verify-phone/send">${csrf}<button class="btn btn-secondary full-width" type="submit">Send a new code</button></form>
        ` : `
          <form method="POST" action="/verify-phone/send" class="stacked-form">
            ${csrf}<button class="btn btn-primary full-width" type="submit">Send verification code</button>
          </form>
        `) : '<div class="alert">SMS verification is not configured. Your account remains restricted and no code has been sent.</div>'}
      </div></main>
    `
  });
}

function reqSmsConfigured() {
  const messaging = app.locals.accountMessaging || defaultAccountMessaging;
  return messaging.twilioConfigured();
}

function twoFactorPage(user, errorMessage = '', csrf = '') {
  const message = errorMessage ? `<div class="alert error">${escapeHtml(errorMessage)}</div>` : '';
  return renderPage({
    title: 'Two-Factor Authentication',
    user,
    pageClass: 'auth-page',
    body: `
      <main class="container auth-wrap">
        <div class="auth-card">
          <p class="eyebrow accent">Secure sign in</p>
          <h1>Enter your authentication code</h1>
          ${message}
          <form method="POST" action="/two-factor" class="stacked-form">
            ${csrf}
            <label>
              6-digit authenticator code
              <input type="text" name="code" inputmode="numeric" maxlength="6" placeholder="123456" required />
            </label>
            <button type="submit" class="btn btn-primary full-width">Verify code</button>
          </form>
        </div>
      </main>
    `
  });
}

function dashboardBody(user) {
  const notificationsCount = db.prepare('SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = 0').get(user.id).count;
  const room = db.prepare('SELECT id FROM chat_rooms WHERE user_id = ?').get(user.id);
  const messageCount = room
    ? db.prepare('SELECT COUNT(*) AS count FROM chat_messages WHERE room_id = ?').get(room.id).count
    : 0;

  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div>
          <p class="eyebrow accent">Dashboard</p>
          <h1>Welcome back, ${escapeHtml(user.full_name)}</h1>
        </div>
        <a href="/rooms" class="btn btn-primary">Open your chat room</a>
      </section>

      <div class="stats-grid">
        ${buildStatCard('Open notifications', String(notificationsCount), 'info')}
        ${buildStatCard('Chat messages', String(messageCount), 'success')}
        ${buildStatCard('Account', 'Active', 'info')}
      </div>

      <section class="panel glass-panel customer-journey">
        <p class="eyebrow accent">Your MYFB account</p>
        <h2>Profile and private support</h2>
        <p>Manage your profile, choose whether to receive advertising emails, and use your private room to contact an administrator.</p>
        <div class="journey-links">
          <a href="/account"><strong>View your profile</strong><span>Update your name and optional advertising email</span></a>
          <a href="/rooms"><strong>Open your chat room</strong><span>Message the MYFB administrator privately</span></a>
          <a href="/report-user"><strong>Report a user</strong><span>Send a private report to the admin team</span></a>
          <a href="/notifications"><strong>Notifications</strong><span>${notificationsCount} unread notification${notificationsCount === 1 ? '' : 's'}</span></a>
        </div>
      </section>
    </main>
  `;
}

function accountBody(user, req) {
  const latest = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  const adminPasswordPolicy = latest.role === 'admin';
  const passwordMinLength = adminPasswordPolicy ? 12 : 6;
  const passwordRequirements = adminPasswordPolicy
    ? 'Administrator passwords require 12+ characters with lowercase and uppercase letters, a number, and a symbol.'
    : 'Use at least 6 characters. Longer, unique passwords are safer.';
  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div>
          <p class="eyebrow accent">Account</p>
          <h1>Account details</h1>
        </div>
      </section>
      <div class="panel glass-panel full-width-panel">
        <form method="POST" action="/account" class="stacked-form two-col-form">
          ${csrfToken(req)}
          <label>
            Display name
            <input type="text" name="fullName" value="${escapeHtml(latest.full_name)}" required />
          </label>
          <label>Username<input type="text" value="${escapeHtml(latest.username)}" readonly /></label>
          <label class="full-span">
            Optional email for advertising
            <input type="email" name="marketingEmail" value="${escapeHtml(latest.marketing_email || '')}" autocomplete="email" />
          </label>
          <label class="full-span checkbox-label">
            <input type="checkbox" name="marketingConsent" value="on" ${latest.marketing_consent ? 'checked' : ''} />
            I agree to receive advertising emails. Uncheck to withdraw consent and remove this email.
          </label>
          <p class="full-span form-help">Your email is never used for sign-in, account verification, or support replies.</p>
          <button type="submit" class="btn btn-primary">Save changes</button>
        </form>
      </div>
      <section class="panel glass-panel full-width-panel">
        <h2>Change password</h2>
        <p>Email-based password recovery is disabled. Change your password here while signed in.</p>
        <form method="POST" action="/account/password" class="stacked-form two-col-form">
          ${csrfToken(req)}
          <label>Current password<input type="password" name="currentPassword" autocomplete="current-password" required /></label>
          <label>New password<input id="account-new-password" type="password" name="password" autocomplete="new-password"
            minlength="${passwordMinLength}" placeholder="At least ${passwordMinLength} characters"
            aria-describedby="account-new-password-strength-label account-new-password-requirements" required /></label>
          ${passwordStrengthControl('account-new-password', adminPasswordPolicy)}
          <p class="full-span form-help" id="account-new-password-requirements">${passwordRequirements}</p>
          <label class="full-span">Confirm new password<input type="password" name="confirmPassword" autocomplete="new-password" required /></label>
          <button type="submit" class="btn btn-primary">Update password</button>
        </form>
      </section>
    </main>
  `;
}

function transactionsBody(user) {
  const search = String(user.transactionSearch || '').trim().slice(0, 100);
  const status = String(user.transactionStatus || '').trim();
  const conditions = ['user_id = ?'];
  const parameters = [user.id];
  if (search) {
    conditions.push('(reference LIKE ? OR provider_reference LIKE ?)');
    parameters.push(`%${search}%`, `%${search}%`);
  }
  if (['pending', 'confirmed', 'failed', 'cancelled', 'review', 'refund_pending', 'refunded'].includes(status)) {
    conditions.push('status = ?');
    parameters.push(status);
  }
  const txs = db.prepare(`SELECT * FROM wallet_transactions WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC LIMIT 200`).all(...parameters);
  const rows = txs.length ? txs.map((tx) => {
    const transactionDate = tx.status === 'confirmed' ? tx.updated_at : tx.created_at;
    return `
    <tr>
      <td>${escapeHtml(tx.reference)}</td>
      <td>${escapeHtml(tx.transaction_type)}</td>
      <td>${escapeHtml(tx.payment_method)}</td>
      <td>${escapeHtml(tx.status)}</td>
      <td>${formatRand(tx.amount_cents)}</td>
      <td>${escapeHtml(tx.provider_reference || '—')}</td>
      <td>${escapeHtml(new Date(transactionDate).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' }))}</td>
      <td>${tx.transaction_type === 'deposit' && tx.status === 'confirmed' ? `<a href="/transactions/${encodeURIComponent(tx.reference)}/receipt">Receipt</a>` : '—'}</td>
    </tr>
  `;
  }).join('') : '<tr><td colspan="8">No wallet transactions found.</td></tr>';

  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div>
          <p class="eyebrow accent">Transactions</p>
          <h1>Wallet transaction history</h1>
        </div>
      </section>
      <div class="panel glass-panel full-width-panel">
        <form method="GET" action="/transactions" class="filter-form">
          <label>Reference search<input type="search" name="q" maxlength="100" value="${escapeHtml(search)}" /></label>
          <label>Status
            <select name="status">
              <option value="">All statuses</option>
              ${['pending', 'confirmed', 'failed', 'cancelled', 'review', 'refund_pending', 'refunded'].map((item) => `<option value="${item}" ${status === item ? 'selected' : ''}>${item}</option>`).join('')}
            </select>
          </label>
          <button class="btn btn-primary" type="submit">Filter</button>
        </form>
        <table class="data-table">
          <thead>
            <tr>
              <th>Reference</th><th>Type</th><th>Payment method</th>
              <th>Status</th>
              <th>Amount</th><th>Provider reference</th><th>Date and time (Johannesburg)</th><th>Receipt</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </main>
  `;
}

function walletBody(user) {
  const totals = wallet.getTotals(user.id);
  const limits = wallet.getUserLimits(user.id);
  return `
    <main class="container dashboard-shell">
      <section class="page-topper"><div><p class="eyebrow accent">Customer wallet · ZAR</p><h1>Your wallet</h1></div></section>
      <div class="stats-grid">
        ${buildStatCard('Available balance', formatRand(totals.balanceCents), 'info')}
        ${buildStatCard('Confirmed deposits', formatRand(totals.confirmedDepositCents), 'success')}
        ${buildStatCard('Total withdrawals', formatRand(totals.confirmedWithdrawalCents), 'warning')}
        ${buildStatCard('Pending deposits', formatRand(totals.pendingDepositCents), 'warning')}
        ${buildStatCard('Deposits under review', formatRand(totals.reviewDepositCents), 'warning')}
      </div>
      <div class="account-actions">
        <a class="btn btn-primary" href="/wallet/deposit">Deposit money</a>
        <a class="btn btn-secondary" href="/wallet/withdraw">Withdraw money</a>
        <a class="btn btn-secondary" href="/transactions">Transaction history</a>
      </div>
      <section class="panel glass-panel">
        <h2>Payment methods</h2>
        <p class="warning-callout">Test mode is active. No payment provider is connected, so no money will be charged or credited.</p>
        <div class="payment-method-grid">
          <article class="payment-method-card unavailable"><h3>Bank card</h3><p>Visa / Mastercard hosted checkout: unavailable</p></article>
          <article class="payment-method-card unavailable"><h3>Bank transfer / EFT</h3><p>Provider-generated instructions and references: unavailable</p></article>
          <article class="payment-method-card unavailable"><h3>Instant EFT</h3><p>Unavailable; no configured provider supports it here.</p></article>
          <article class="payment-method-card unavailable"><h3>OTT vouchers</h3><p>Unavailable. No authorized merchant integration or permitted investment use has been verified.</p></article>
        </div>
        <p>Fees, processing times, withdrawals and refunds cannot be quoted until an approved provider and the business terms are configured. Do not send card details, banking credentials, or voucher codes to anyone.</p>
      </section>
      <section class="panel glass-panel responsible-money">
        <h2>Responsible money management</h2>
        <p>Only deposit money you can afford to lose. Keep money for your essential needs and emergencies separate. Investment values can fall, and you may lose some or all of the money you invest. Depositing money does not guarantee a profit.</p>
        <p>Current limits: minimum ${formatRand(limits.minimumDepositCents)}; single deposit ${limits.singleDepositCents == null ? 'no cap configured' : formatRand(limits.singleDepositCents)}; daily ${formatRand(limits.dailyDepositCents)}; monthly ${formatRand(limits.monthlyDepositCents)}. These are configurable controls, not legal limits.</p>
        <a href="/wallet/limits">Manage limits and deposit pause</a>
      </section>
    </main>
  `;
}

function investmentActivityBody(user) {
  const activity = getInvestmentActivity(db, user.id);
  const totals = getInvestmentTotals(db, user.id);
  const rows = activity.length ? activity.map((entry) => `
    <tr>
      <td>${escapeHtml(entry.reference)}</td>
      <td>${escapeHtml(entry.activity_type)}</td>
      <td>${escapeHtml(entry.product_reference || '—')}</td>
      <td>${escapeHtml(entry.status)}</td>
      <td>${formatRand(entry.amount_cents)}</td>
      <td>${escapeHtml(new Date(entry.status === 'confirmed' ? entry.updated_at : entry.created_at).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' }))}</td>
    </tr>
  `).join('') : '<tr><td colspan="6">No confirmed or pending investment activity is recorded.</td></tr>';
  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div><p class="eyebrow accent">Separate investment activity</p><h1>Investments</h1></div>
        <a href="/wallet" class="btn btn-secondary">Back to wallet</a>
      </section>
      <section class="payment-unavailable-card" role="status">
        <span class="unavailable-icon" aria-hidden="true">i</span>
        <div>
          <h2>Investment services are not available</h2>
          <p>MYFB has no configured investment products, authorized service provider, or eligibility process. No investment can be opened from this website, and no returns or portfolio values are being generated.</p>
          <p>Wallet funding is separate and cannot be invested or moved into an investment automatically.</p>
        </div>
      </section>
      <div class="stats-grid">
        ${buildStatCard('Confirmed subscriptions recorded', formatRand(totals.confirmedSubscriptionsCents), 'info')}
        ${buildStatCard('Confirmed redemptions recorded', formatRand(totals.confirmedRedemptionsCents), 'info')}
        ${buildStatCard('Investment service status', investmentServiceConfiguration.enabled ? 'Available' : 'Unavailable', 'warning')}
      </div>
      <section class="panel glass-panel full-width-panel">
        <h2>Investment activity history</h2>
        <p>Investment records are stored separately from wallet deposits and withdrawals. This screen does not calculate or promise returns.</p>
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>Reference</th><th>Activity</th><th>Product</th><th>Status</th><th>Amount</th><th>Date and time (Johannesburg)</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </section>
      <section class="panel glass-panel">
        <h2>Before any investment service can open</h2>
        <p>The business must identify the applicable South African authorization and customer-protection requirements, verify the service/provider and eligibility criteria, publish product terms and fees, and implement the authorized investment and custody operations.</p>
        <a href="/investment-information">Review investment information</a>
      </section>
    </main>
  `;
}

function adminInvestmentBody() {
  const activity = db.prepare(`
    SELECT t.*, u.email
    FROM investment_transactions t
    JOIN users u ON u.id = t.user_id
    ORDER BY t.created_at DESC
    LIMIT 500
  `).all();
  const rows = activity.length ? activity.map((entry) => `
    <tr>
      <td>${escapeHtml(entry.reference)}</td>
      <td>${escapeHtml(entry.email)}</td>
      <td>${escapeHtml(entry.activity_type)}</td>
      <td>${escapeHtml(entry.product_reference || '—')}</td>
      <td>${escapeHtml(entry.status)}</td>
      <td>${formatRand(entry.amount_cents)}</td>
      <td>${escapeHtml(new Date(entry.status === 'confirmed' ? entry.updated_at : entry.created_at).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' }))}</td>
    </tr>
  `).join('') : '<tr><td colspan="7">No investment activity is recorded.</td></tr>';
  return `
    <main class="container dashboard-shell">
      <section class="page-topper"><div><p class="eyebrow accent">Administrator · investment activity</p><h1>Investment service status</h1></div></section>
      <section class="payment-unavailable-card" role="status">
        <span class="unavailable-icon" aria-hidden="true">i</span>
        <div>
          <h2>${investmentServiceConfiguration.enabled ? 'Investment service configured' : 'Investment service unavailable'}</h2>
          <p>Active integration: ${escapeHtml(investmentServiceConfiguration.provider)}. This admin view is read-only; it cannot create investments, alter balances, or claim returns.</p>
        </div>
      </section>
      <section class="panel glass-panel">
        <h2>Investment activity ledger</h2>
        <p>Investment records are separate from wallet funding. Proposed product records may be kept for review, but this prototype has no verified investment provider, enabled investment integration, completed customer eligibility process, or investment activity creation workflow.</p>
        <div class="table-scroll"><table class="data-table">
          <thead><tr><th>Reference</th><th>Customer</th><th>Activity</th><th>Product</th><th>Status</th><th>Amount</th><th>Date and time (Johannesburg)</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
      </section>
      <section class="panel glass-panel">
        <h2>Launch prerequisites</h2>
        <p>Obtain qualified legal review of the exact business model and any required authorizations; approve a legitimate investment provider and custody/funds arrangement; define eligibility and customer verification; publish product-specific fees, risks and withdrawal terms; and implement an independently tested investment transaction workflow before enabling service.</p>
      </section>
    </main>
  `;
}

function investmentProductCard(product) {
  const minimum = product.minimum_amount_cents == null ? 'Not configured' : formatRand(product.minimum_amount_cents);
  return `
    <article class="product-card">
      <p class="eyebrow accent">${escapeHtml(product.status)}</p>
      <h2>${escapeHtml(product.name)}</h2>
      <p>${escapeHtml(product.description)}</p>
      <dl class="product-facts">
        <div><dt>Provider</dt><dd>${escapeHtml(product.provider_name)}</dd></div>
        <div><dt>Minimum investment</dt><dd>${escapeHtml(minimum)}</dd></div>
        <div><dt>Fees and charges</dt><dd>${escapeHtml(product.fees)}</dd></div>
        <div><dt>Time horizon</dt><dd>${escapeHtml(product.time_horizon)}</dd></div>
        <div><dt>Eligibility</dt><dd>${escapeHtml(product.eligibility)}</dd></div>
        <div><dt>Risk level</dt><dd>${escapeHtml(product.risk_level)}</dd></div>
        <div><dt>Liquidity and withdrawals</dt><dd>${escapeHtml(product.liquidity_conditions)}</dd></div>
      </dl>
      <p><a class="btn btn-secondary" href="/investment-information/${encodeURIComponent(product.slug)}">Review full product details</a></p>
    </article>
  `;
}

function investmentProductDetails(product, user) {
  const minimum = product.minimum_amount_cents == null ? 'Not specified' : formatRand(product.minimum_amount_cents);
  return renderStaticPage({
    title: product.name,
    user,
    html: `
      <p class="eyebrow accent">Investment product information</p>
      <h1>${escapeHtml(product.name)}</h1>
      <p class="product-lead">${escapeHtml(product.description)}</p>
      <div class="product-facts">
        <div><dt>Provider</dt><dd>${escapeHtml(product.provider_name)}</dd></div>
        <div><dt>Provider information</dt><dd>${escapeHtml(product.provider_information)}</dd></div>
        <div><dt>Possible outcomes</dt><dd>${escapeHtml(product.potential_outcomes)}</dd></div>
        <div><dt>Minimum investment</dt><dd>${escapeHtml(minimum)}</dd></div>
        <div><dt>Fees and charges</dt><dd>${escapeHtml(product.fees)}</dd></div>
        <div><dt>How it works / time horizon</dt><dd>${escapeHtml(product.time_horizon)}</dd></div>
        <div><dt>Eligibility requirements</dt><dd>${escapeHtml(product.eligibility)}</dd></div>
        <div><dt>Risk level</dt><dd>${escapeHtml(product.risk_level)}</dd></div>
        <div><dt>Liquidity and withdrawals</dt><dd>${escapeHtml(product.liquidity_conditions)}</dd></div>
        <div><dt>Risk disclosures</dt><dd>${escapeHtml(product.risk_disclosures)}</dd></div>
        <div><dt>Product terms and conditions</dt><dd>${escapeHtml(product.terms)}</dd></div>
        <div><dt>Authorization information</dt><dd>${escapeHtml(product.authorization_reference)}</dd></div>
      </div>
      <section class="payment-unavailable-card" role="note">
        <span class="unavailable-icon" aria-hidden="true">i</span>
        <div><h2>Information only — no investment order can be placed here</h2>
          <p>Read all product terms and disclosures carefully. This information page is not a personal recommendation, suitability assessment, or investment instruction. Acknowledging a disclosure does not replace legal checks or eligibility assessments.</p>
          <p>Never send funds based only on this page. Provider and authorization information must be independently checked with the relevant official sources.</p>
        </div>
      </section>
      <p><a href="/investment-information">Back to investment information</a> · <a href="/trading-risks">Trading risks</a> · <a href="/risk-disclosure">Risk disclosure</a> · <a href="/support">Contact support</a></p>
    `
  });
}

function investmentProductAdminFields(product = {}) {
  const textField = (key, label, options = {}) => {
    const required = options.required ? 'required' : '';
    const control = options.multiline
      ? `<textarea rows="3" name="${key}" ${required}>${escapeHtml(product[key] || '')}</textarea>`
      : `<input type="text" maxlength="${options.maxLength || 2000}" name="${key}" value="${escapeHtml(product[key] || '')}" ${required} />`;
    return `<label class="${options.wide ? 'form-field-wide' : ''}">${label}${control}</label>`;
  };
  const fields = [
    textField('name', 'Product name', { required: true, maxLength: 120 }),
    textField('provider_name', 'Provider name', { maxLength: 160 }),
    textField('description', 'Product description', { multiline: true, wide: true }),
    textField('potential_outcomes', 'What the customer may gain or lose', { multiline: true, wide: true }),
    textField('provider_information', 'Provider information', { multiline: true, wide: true }),
    `<label>Minimum investment (ZAR; leave blank if not specified)<input type="number" name="minimum_amount" min="0" step="0.01" value="${product.minimum_amount_cents == null ? '' : (product.minimum_amount_cents / 100).toFixed(2)}" /></label>`,
    textField('fees', 'Applicable fees and charges', { multiline: true }),
    textField('time_horizon', 'How it works and time horizon', { multiline: true }),
    textField('eligibility', 'Eligibility requirements', { multiline: true }),
    textField('risk_level', 'Risk level (plain-language description)', { multiline: true }),
    textField('risk_disclosures', 'Risk disclosures', { multiline: true }),
    textField('liquidity_conditions', 'Withdrawal and liquidity conditions', { multiline: true }),
    textField('terms', 'Product terms and conditions', { multiline: true }),
    textField('provider_verification_reference', 'Provider verification evidence/reference', { multiline: true }),
    textField('legal_review_reference', 'Legal review evidence/reference', { multiline: true }),
    textField('authorization_reference', 'Authorization information and verification reference', { multiline: true }),
    textField('documented_approval_reference', 'Documented approval reference', { multiline: true }),
    textField('payment_operations_reference', 'Payment operations test evidence/reference', { multiline: true }),
    textField('transaction_operations_reference', 'Transaction operations test evidence/reference', { multiline: true })
  ];
  const checks = [
    ['provider_verified', 'Provider has been independently verified'],
    ['legal_reviewed', 'Legal and regulatory review has been completed'],
    ['authorization_verified', 'Applicable authorization has been checked against an official source'],
    ['payment_operations_verified', 'Payment process has been operationally tested'],
    ['transaction_operations_verified', 'Investment transaction and reconciliation process has been operationally tested']
  ];
  return `<div class="investment-product-form-grid">${fields.join('')}
    <fieldset class="product-verification-checks form-field-wide"><legend>Verification checklist — record evidence above</legend>
      <p>These administrator declarations do not independently verify a provider, authorization, or legal status. Confirm evidence with the relevant professional and official sources. Do not describe MYFB or a product as licensed unless independently verified.</p>
      ${checks.map(([key, label]) => `<label class="checkbox-row"><input type="checkbox" name="${key}" value="1" ${product[key] ? 'checked' : ''} /> ${label}</label>`).join('')}
    </fieldset>
  </div>`;
}

function adminInvestmentProductsBody(req) {
  const products = db.prepare('SELECT * FROM investment_products ORDER BY updated_at DESC, id DESC').all();
  const statusOptions = (selected) => INVESTMENT_PRODUCT_STATUSES.map((status) =>
    `<option value="${escapeHtml(status)}" ${status === selected ? 'selected' : ''}>${escapeHtml(status)}</option>`
  ).join('');
  const editors = products.length ? products.map((product) => `
    <details class="panel glass-panel product-editor">
      <summary><strong>${escapeHtml(product.name)}</strong> · ${escapeHtml(product.status)}</summary>
      <form method="POST" action="/admin/investment-products/${product.id}" class="stacked-form">
        ${csrfToken(req)}
        <div class="investment-product-form-grid">${investmentProductAdminFields(product)}</div>
        <label>Publication status<select name="status" required>${statusOptions(product.status)}</select></label>
        <p>Published products are visible to customers only when all required content, evidence, verification checks, and tested operations are present. Publishing does not create an investment service or order workflow.</p>
        <button class="btn btn-primary" type="submit">Save product and audit change</button>
      </form>
    </details>
  `).join('') : '<p>No proposed products have been recorded.</p>';
  return `
    <main class="container dashboard-shell">
      <section class="page-topper"><div><p class="eyebrow accent">Administrator · product catalogue</p><h1>Investment Products</h1><p>Record proposed product information and evidence. Admin publication does not enable customer investing.</p></div></section>
      <section class="payment-unavailable-card" role="note"><span class="unavailable-icon" aria-hidden="true">i</span><div>
        <h2>Real investment activity remains disabled</h2>
        <p>Before publication, obtain and document provider verification, legal and regulatory review, applicable authorization checks, product terms, eligibility, fees, and operational testing. This application has no investment order, custody, payment, or reconciliation integration. Do not present an administrator-entered product as licensed or available for real investment.</p>
      </div></section>
      <section class="panel glass-panel">
        <h2>Add a proposed product</h2>
        <p>New products always start as Draft. Saving evidence does not by itself establish that the evidence is genuine.</p>
        <form method="POST" action="/admin/investment-products" class="stacked-form">
          ${csrfToken(req)}
          ${investmentProductAdminFields()}
          <button class="btn btn-primary" type="submit">Save as draft</button>
        </form>
      </section>
      <section><h2>Recorded products and review status</h2><div class="product-admin-list">${editors}</div></section>
      <section class="panel glass-panel"><h2>Product status meanings</h2><p>Draft · Pending verification · Pending authorization · Approved for publication · Published · Suspended · Archived. Only fully complete Published products with all recorded gates satisfied appear in the public catalogue. An edit to a published product requires moving it back through review and approval.</p></section>
    </main>
  `;
}

function depositBody(user, errorMessage = '', confirmation = null, token = '') {
  const limits = wallet.getUserLimits(user.id);
  const totals = wallet.getTotals(user.id);
  const settings = wallet.getDepositSettings();
  const remainingDaily = Math.max(0, limits.dailyDepositCents - totals.dailyDepositCents);
  const remainingMonthly = Math.max(0, limits.monthlyDepositCents - totals.monthlyDepositCents);
  const quickAmounts = settings.quickAmountsCents.filter((amount) =>
    amount >= limits.minimumDepositCents &&
    (limits.singleDepositCents == null || amount <= limits.singleDepositCents) &&
    amount <= remainingDaily &&
    amount <= remainingMonthly
  );
  const notice = errorMessage ? `<div class="flash error">${escapeHtml(errorMessage)}</div>` : '';
  const nearLimitMessages = confirmation ? [
    (totals.dailyDepositCents + confirmation.amountCents) * 5 >= limits.dailyDepositCents * 4
      ? 'This deposit would bring you close to your daily deposit limit.'
      : '',
    (totals.monthlyDepositCents + confirmation.amountCents) * 5 >= limits.monthlyDepositCents * 4
      ? 'This deposit would bring you close to your monthly deposit limit.'
      : ''
  ].filter(Boolean) : [];
  const providerStatus = paymentConfiguration.realPaymentsEnabled
    ? 'Payment provider available'
    : 'Unavailable in test mode';
  const methodCards = PAYMENT_METHODS.map((method) => {
    const requested = settings.requestedPaymentMethods[method];
    const ready = paymentConfiguration.realPaymentsEnabled && paymentConfiguration.supportedMethods.includes(method) && requested;
    const status = ready ? 'Available' : requested ? 'Configured in settings · integration unavailable' : 'Unavailable';
    return `<article class="deposit-method-card ${ready ? 'is-available' : 'is-unavailable'}" aria-disabled="${!ready}">
      <span class="method-status">${escapeHtml(status)}</span>
      <strong>${escapeHtml(PAYMENT_METHOD_LABELS[method])}</strong>
      <small>${ready ? 'Secure provider flow' : 'Not connected or approved for use'}</small>
    </article>`;
  }).join('');
  const amountField = `<label class="deposit-amount-label">Deposit amount <span class="currency-badge">ZAR · South African rand</span>
    <span class="amount-input-wrap"><span aria-hidden="true">R</span><input name="amount" type="number" min="${(limits.minimumDepositCents / 100).toFixed(2)}" ${limits.singleDepositCents == null ? '' : `max="${(limits.singleDepositCents / 100).toFixed(2)}"`} step="0.01" inputmode="decimal" placeholder="0.00" value="${confirmation ? (confirmation.amountCents / 100).toFixed(2) : ''}" required ${confirmation ? 'readonly' : ''} /></span>
    <small>Minimum ${formatRand(limits.minimumDepositCents)} · Single-deposit limit ${limits.singleDepositCents == null ? 'No cap configured' : formatRand(limits.singleDepositCents)}</small>
  </label>`;
  const quickAmountButtons = !confirmation && quickAmounts.length
    ? `<div class="quick-amounts" aria-label="Quick deposit amounts"><span>Quick amounts</span>${quickAmounts.map((amount) => `<button type="submit" formnovalidate class="quick-amount" name="quickAmount" value="${(amount / 100).toFixed(2)}">${formatRand(amount)}</button>`).join('')}</div>`
    : '';
  const confirmationPanel = confirmation ? `
    <section class="deposit-review-card">
      <p class="eyebrow accent">Review deposit</p>
      <h2>Check your deposit details</h2>
      <div class="review-amount"><span>Amount</span><strong>${formatRand(confirmation.amountCents)}</strong><span>ZAR · South African rand</span></div>
      ${nearLimitMessages.length ? `<p class="warning-callout">${nearLimitMessages.map(escapeHtml).join(' ')}</p>` : ''}
      <p><strong>Payment status:</strong> Not started</p>
      <p>There is no active payment method. This is a review only; it does not create a transaction, charge you, or change your wallet balance.</p>
      <p class="essential-money-notice">Please keep money for food, transport, rent, school fees, debt repayments and emergencies separate.</p>
      <button type="button" class="btn btn-primary" disabled>Payment unavailable in test mode</button>
      <a href="/wallet/deposit" class="btn btn-secondary">Change amount</a>
    </section>
  ` : `
    <section class="deposit-form-card">
      <form method="POST" action="/wallet/deposit/prepare" class="deposit-form">
        ${token}
        ${amountField}
        ${quickAmountButtons}
        <div class="configured-limit-summary">
          <span>Daily remaining: <strong>${formatRand(remainingDaily)}</strong></span>
          <span>Monthly remaining: <strong>${formatRand(remainingMonthly)}</strong></span>
        </div>
        <button type="submit" class="btn btn-primary deposit-continue">Continue</button>
      </form>
    </section>
  `;
  const statusNotice = `<section class="payment-unavailable-card" role="status">
    <span class="unavailable-icon" aria-hidden="true">i</span>
    <div><h2>${providerStatus}</h2>
      <p>No payment provider is connected and verified. No money will be charged or credited while test mode is active.</p>
      <p>Card, EFT/bank transfer, instant EFT, OTT voucher and other methods are unavailable. Do not send card details, bank credentials, or voucher codes to support.</p>
    </div>
  </section>`;
  return `
    <main class="container dashboard-shell deposit-page">
      <nav class="deposit-breadcrumb" aria-label="Breadcrumb"><a href="/wallet">Wallet</a><span aria-hidden="true">/</span><span>Deposit</span></nav>
      <section class="deposit-heading">
        <div><p class="eyebrow accent">MYFB Investment wallet</p><h1>Deposit Money</h1><p>Choose an amount and review your deposit securely.</p></div>
        <span class="currency-badge">ZAR · South African rand</span>
      </section>
      ${notice}
      <div class="deposit-layout">
        <div class="deposit-main-column">
          ${confirmationPanel}
          ${!confirmation ? `<section class="deposit-methods-panel"><div class="section-heading"><div><h2>Payment method</h2><p>Methods are shown for transparency. Unavailable methods cannot be selected.</p></div></div><div class="deposit-method-grid">${methodCards}</div></section>` : ''}
          ${statusNotice}
          <section class="responsible-deposit-note"><strong>Deposit responsibly</strong><p>Only deposit money you can afford to lose. Keep money for essentials and emergencies separate. Investment values can fall; you may lose some or all of your money. Depositing does not guarantee a profit.</p></section>
        </div>
        <aside class="deposit-sidebar">
          <h2>Your deposit limits</h2>
          <dl class="deposit-limit-list">
            <div><dt>Minimum per deposit</dt><dd>${formatRand(limits.minimumDepositCents)}</dd></div>
            <div><dt>Maximum per deposit</dt><dd>${limits.singleDepositCents == null ? 'No cap configured' : formatRand(limits.singleDepositCents)}</dd></div>
            <div><dt>Daily limit</dt><dd>${formatRand(limits.dailyDepositCents)}</dd></div>
            <div><dt>Monthly limit</dt><dd>${formatRand(limits.monthlyDepositCents)}</dd></div>
          </dl>
          <p>Daily and monthly totals use the Africa/Johannesburg timezone. Pending deposits count toward limits.</p>
          <a href="/wallet/limits">Manage your limits</a>
          <a href="/wallet" class="wallet-back-link">Back to wallet</a>
        </aside>
      </div>
    </main>
  `;
}

function walletLimitsBody(user, req) {
  const limits = wallet.getUserLimits(user.id);
  const global = wallet.getGlobalLimits();
  const displayed = (value) => (value == null ? '' : (value / 100).toFixed(2));
  return `
    <main class="container dashboard-shell">
      <section class="page-topper"><div><p class="eyebrow accent">Financial safety</p><h1>Deposit limits and pause</h1></div></section>
      <section class="panel glass-panel responsible-money">
        <p>Only deposit money you can afford to lose. Keep money for food, transport, rent, school fees, debt repayments and emergencies separate. Depositing money does not guarantee a profit.</p>
        <p>Global configurable limits (not legal limits): minimum ${formatRand(global.minimumDepositCents)}, single ${global.singleDepositCents == null ? 'no cap configured' : formatRand(global.singleDepositCents)}, daily ${formatRand(global.dailyDepositCents)}, monthly ${formatRand(global.monthlyDepositCents)}.</p>
      </section>
      <section class="panel glass-panel">
        <h2>Your personal caps</h2>
        <p>Caps may be reduced immediately. An increase has a 7-day cooling-off period and cannot exceed global settings.</p>
        ${limits.requestedEffectiveAt ? `<p>Limit increase requested; scheduled for ${escapeHtml(new Date(limits.requestedEffectiveAt).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' }))} Johannesburg time.</p>` : ''}
        <form method="POST" action="/wallet/limits" class="stacked-form two-col-form">
          ${csrfToken(req)}
          <label>Per deposit cap (ZAR)<input name="single" type="number" min="${displayed(global.minimumDepositCents)}" ${global.singleDepositCents == null ? '' : `max="${displayed(global.singleDepositCents)}"`} step="0.01" value="${displayed(limits.singleDepositCents)}" /><small>Optional lower personal single-deposit cap. Leave blank for no personal cap.</small></label>
          <label>Per Johannesburg day (ZAR)<input name="daily" type="number" min="${displayed(global.minimumDepositCents)}" max="${displayed(global.dailyDepositCents)}" step="0.01" value="${displayed(limits.dailyDepositCents)}" required /></label>
          <label>Per Johannesburg calendar month (ZAR)<input name="monthly" type="number" min="${displayed(global.minimumDepositCents)}" max="${displayed(global.monthlyDepositCents)}" step="0.01" value="${displayed(limits.monthlyDepositCents)}" required /></label>
          <button class="btn btn-primary" type="submit">Save personal limits</button>
        </form>
      </section>
      <section class="panel glass-panel">
        <h2>Pause new deposits</h2>
        ${limits.depositsPausedUntil ? `<p>Deposits are paused until ${escapeHtml(new Date(limits.depositsPausedUntil).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' }))} Johannesburg time.</p>` : ''}
        <form method="POST" action="/wallet/pause" class="stacked-form">
          ${csrfToken(req)}
          <label>Pause duration<select name="durationDays"><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option><option value="365">365 days</option></select></label>
          <button class="btn btn-secondary" type="submit">Pause new deposits</button>
        </form>
      </section>
    </main>
  `;
}

function withdrawalBody(user) {
  const totals = wallet.getTotals(user.id);
  return `
    <main class="container dashboard-shell">
      <section class="page-topper"><div><p class="eyebrow accent">Wallet</p><h1>Withdraw money</h1></div></section>
      <section class="panel glass-panel">
        <p>Available balance: <strong>${formatRand(totals.balanceCents)}</strong>.</p>
        <p class="warning-callout">Withdrawals are unavailable. No approved payout provider, withdrawal conditions, identity checks or refund process is configured. No money has been transferred.</p>
        <p>Do not share bank passwords, card details or voucher codes. Deposit money cannot be invested or withdrawn by this website in test mode.</p>
      </section>
    </main>
  `;
}

function adminPaymentsBody(user, search, req) {
  const term = String(search || '').trim().slice(0, 100);
  const transactions = term
    ? db.prepare(`SELECT t.*, u.email FROM wallet_transactions t JOIN users u ON u.id = t.user_id WHERE t.reference LIKE ? OR t.provider_reference LIKE ? ORDER BY t.created_at DESC LIMIT 200`).all(`%${term}%`, `%${term}%`)
    : db.prepare(`SELECT t.*, u.email FROM wallet_transactions t JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC LIMIT 200`).all();
  const totals = wallet.getGlobalTotals();
  const rows = transactions.length ? transactions.map((item) => `
    <tr>
      <td>${escapeHtml(item.reference)}</td><td>${escapeHtml(item.email)}</td>
      <td>${escapeHtml(item.transaction_type)}</td><td>${formatRand(item.amount_cents)}</td>
      <td>${escapeHtml(item.payment_method)}</td><td>${escapeHtml(item.status)}</td>
      <td>${escapeHtml(new Date(item.status === 'confirmed' ? item.updated_at : item.created_at).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' }))}</td>
      <td>${escapeHtml(item.reconciliation_status)}</td><td>${escapeHtml(item.provider_reference || '—')}</td>
      <td><form method="POST" action="/admin/payments/${encodeURIComponent(item.reference)}/review" class="inline-form">
        ${csrfToken(req)}<input name="reason" minlength="8" maxlength="500" placeholder="Review note (min 8 chars)" required />
        <button class="btn btn-secondary" type="submit" name="action" value="payment_review">Review</button>
        <button class="btn btn-secondary" type="submit" name="action" value="refund_request">Queue refund review</button>
      </form></td>
    </tr>
  `).join('') : '<tr><td colspan="10">No wallet transactions found.</td></tr>';
  const global = wallet.getGlobalLimits();
  const randInput = (cents) => (cents == null ? '' : (cents / 100).toFixed(2));
  const settings = wallet.getDepositSettings();
  const requestedMethods = PAYMENT_METHODS.map((method) => `
    <label class="admin-method-option">
      <input type="checkbox" name="paymentMethods" value="${method}" ${settings.requestedPaymentMethods[method] ? 'checked' : ''} />
      <span><strong>${escapeHtml(PAYMENT_METHOD_LABELS[method])}</strong><small>Requested: ${settings.requestedPaymentMethods[method] ? 'on' : 'off'} · Effective: ${paymentConfiguration.supportedMethods.includes(method) && paymentConfiguration.realPaymentsEnabled ? 'available' : 'unavailable (no active integration)'}</small></span>
    </label>
  `).join('');
  return `
    <main class="container dashboard-shell">
      <section class="page-topper"><div><p class="eyebrow accent">Administrator · payment management</p><h1>Wallet transactions and reconciliation</h1></div><a class="btn btn-secondary" href="/admin/payments/export.csv">Export CSV</a></section>
      <p class="warning-callout">Requested provider: ${escapeHtml(paymentConfiguration.requestedProvider)} · Active adapter: ${paymentConfiguration.provider} · Mode: ${paymentConfiguration.mode} · Real-money payments disabled. Review and refund actions create audit records only; they do not alter status, credit wallets, or issue refunds.</p>
      <div class="stats-grid">${buildStatCard('Confirmed deposits today', formatRand(totals.dailyDepositCents), 'info')}${buildStatCard('Confirmed deposits this month', formatRand(totals.monthlyDepositCents), 'info')}${buildStatCard('Pending deposits', String(db.prepare("SELECT COUNT(*) AS count FROM wallet_transactions WHERE status = 'pending'").get().count), 'warning')}${buildStatCard('Review / refund cases', String(db.prepare("SELECT COUNT(*) AS count FROM wallet_transactions WHERE status = 'review' OR reconciliation_status NOT IN ('not_required', 'reconciled')").get().count), 'warning')}</div>
      <section class="panel glass-panel">
        <h2>Configurable deposit limits</h2>
        <p>Limits are operator-configured controls, not legal limits. Leave the single-deposit maximum blank when no provider, law, or approved risk policy requires one. Daily and monthly limits continue to apply regardless of a single-deposit cap.</p>
        <form method="POST" action="/admin/payments/limits" class="stacked-form two-col-form">
          ${csrfToken(req)}
          <label>Minimum (ZAR)<input type="number" name="minimum" min="0.01" step="0.01" value="${randInput(global.minimumDepositCents)}" required /></label>
          <label>Maximum per deposit (ZAR)<input type="number" name="single" min="${randInput(global.minimumDepositCents)}" step="0.01" value="${randInput(global.singleDepositCents)}" /><small>Optional. Blank means no single-deposit cap is configured.</small></label>
          <label>Maximum per day (ZAR)<input type="number" name="daily" min="${randInput(global.minimumDepositCents)}" step="0.01" value="${randInput(global.dailyDepositCents)}" required /></label>
          <label>Maximum per month (ZAR)<input type="number" name="monthly" min="${randInput(global.dailyDepositCents)}" step="0.01" value="${randInput(global.monthlyDepositCents)}" required /></label>
          <button class="btn btn-primary" type="submit">Save global limits</button>
        </form>
      </section>
      <section class="panel glass-panel">
        <h2>Deposit page settings</h2>
        <p>Provider status: <strong>${paymentConfiguration.realPaymentsEnabled ? 'Configured and enabled' : 'Not configured · test mode'}</strong>. An administrator request does not activate a method. Every method stays unavailable until a legitimate provider integration is deployed, approved, and tested.</p>
        <form method="POST" action="/admin/payments/options" class="stacked-form">
          ${csrfToken(req)}
          <label>Quick amounts in ZAR (comma-separated)<input name="quickAmounts" type="text" maxlength="120" value="${settings.quickAmountsCents.map((amount) => (amount / 100).toFixed(2)).join(', ')}" placeholder="20, 50, 100" /><small>Up to 6 values, each within minimum, daily, monthly and optional single-deposit limits. Clear the field to remove quick amounts.</small></label>
          <fieldset class="admin-method-settings"><legend>Requested payment methods</legend>${requestedMethods}</fieldset>
          <button class="btn btn-primary" type="submit">Save deposit page settings</button>
        </form>
      </section>
      <section class="panel glass-panel">
        <h2>Search wallet transactions</h2>
        <form method="GET" action="/admin/payments" class="filter-form"><label>Reference or provider reference<input type="search" name="q" maxlength="100" value="${escapeHtml(term)}" /></label><button type="submit" class="btn btn-primary">Search</button></form>
        <div class="table-scroll"><table class="data-table"><thead><tr><th>Reference</th><th>Customer</th><th>Type</th><th>Amount</th><th>Method</th><th>Status</th><th>Date and time (Johannesburg)</th><th>Reconciliation</th><th>Provider reference</th><th>Authorized actions (audit only)</th></tr></thead><tbody>${rows}</tbody></table></div>
      </section>
      <section class="panel glass-panel"><h2>Audit history</h2><div class="table-scroll"><table class="data-table"><thead><tr><th>Admin</th><th>Action</th><th>Reference</th><th>Details</th><th>Date</th></tr></thead><tbody>${db.prepare('SELECT a.*, u.email FROM wallet_admin_audit a JOIN users u ON u.id = a.admin_user_id ORDER BY a.created_at DESC LIMIT 100').all().map((item) => `<tr><td>${escapeHtml(item.email)}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml(item.transaction_reference || '—')}</td><td>${escapeHtml(item.details)}</td><td>${escapeHtml(item.created_at)}</td></tr>`).join('') || '<tr><td colspan="5">No admin actions recorded.</td></tr>'}</tbody></table></div></section>
    </main>
  `;
}

function notificationsBody(user) {
  const items = db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const cards = items.length ? items.map((item) => `
    <article class="notification-item ${item.is_read ? '' : 'unread'}">
      <div>
        <strong>${item.title}</strong>
        <p>${item.content}</p>
      </div>
      <span>${item.is_read ? 'Read' : 'New'}</span>
    </article>
  `).join('') : '<p>No notifications yet.</p>';

  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div>
          <p class="eyebrow accent">Notifications</p>
          <h1>Your latest updates</h1>
        </div>
      </section>
      <div class="panel glass-panel full-width-panel">
        ${cards}
      </div>
    </main>
  `;
}

function securityBody(user) {
  const secret = user.two_factor_secret || '';
  const mfaStatus = user.two_factor_enabled ? 'Enabled' : 'Disabled';
  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div>
          <p class="eyebrow accent">Security Centre</p>
          <h1>Protect your account</h1>
        </div>
      </section>
      <div class="card-grid two-col">
        <div class="panel glass-panel">
          <h2>Authentication settings</h2>
          <p><strong>MFA status:</strong> ${mfaStatus}</p>
          <p><strong>Verification:</strong> ${user.is_verified ? 'Verified email' : 'Email not verified'}</p>
          <p><strong>Security note:</strong> Use a unique password and keep your recovery details current.</p>
          ${user.two_factor_enabled ? `
            <form method="POST" action="/security/disable-mfa">
              <button type="submit" class="btn btn-secondary">Disable MFA</button>
            </form>
          ` : `
            <form method="POST" action="/security/setup-mfa" class="stacked-form">
              <button type="submit" class="btn btn-primary">Enable MFA</button>
            </form>
          `}
        </div>
        <div class="panel glass-panel">
          <h2>Authenticator secret</h2>
          <p>Use this secret to set up an authenticator app if you enable MFA.</p>
          <code class="secret-box">${secret || 'Not generated yet'}</code>
        </div>
      </div>
      ${user.two_factor_enabled ? '' : `
        <div class="panel glass-panel full-width-panel">
          <h2>Complete MFA setup</h2>
          <form method="POST" action="/security/confirm-mfa" class="stacked-form inline-form">
            <label>
              Enter one-time code from authenticator app
              <input type="text" name="code" maxlength="6" placeholder="123456" required />
            </label>
            <button type="submit" class="btn btn-primary">Confirm MFA</button>
          </form>
        </div>
      `}
    </main>
  `;
}

function supportBody(user, req) {
  const messages = db.prepare('SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 10').all(user.id);
  const rows = messages.length ? messages.map((item) => `
    <div class="support-message">
      <div><strong>${escapeHtml(item.name)}</strong></div>
      <p>${escapeHtml(item.message)}</p>
      <p class="support-status">Status: ${escapeHtml(item.status || 'open')}</p>
      ${item.admin_response ? `<div class="support-reply"><strong>MYFB support replied</strong><p>${escapeHtml(item.admin_response)}</p><small>${escapeHtml(item.updated_at || '')}</small></div>` : ''}
      <small>${escapeHtml(new Date(item.created_at).toLocaleString('en-GB'))}</small>
    </div>
  `).join('') : '<p>No support messages yet.</p>';

  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div>
          <p class="eyebrow accent">Help and Support</p>
          <h1>Ask for help</h1>
          <p>For a private response, sign in before submitting. Submitted requests appear below with their status and any reply.</p>
        </div>
      </section>
      <div class="card-grid two-col">
        <form method="POST" action="/support" class="panel glass-panel stacked-form">
          ${csrfToken(req)}
          <label>
            Subject
            <input type="text" name="subject" placeholder="What do you need help with?" required />
          </label>
          <label>
            Message
            <textarea name="message" rows="5" placeholder="Please describe your issue or question." required></textarea>
          </label>
          <button type="submit" class="btn btn-primary">Send request</button>
        </form>
        <div class="panel glass-panel">
          <h2>Existing support requests</h2>
          ${rows}
        </div>
      </div>
    </main>
  `;
}

function getOrCreateChatRoom(userId) {
  db.prepare('INSERT OR IGNORE INTO chat_rooms (user_id) VALUES (?)').run(userId);
  return db.prepare('SELECT * FROM chat_rooms WHERE user_id = ?').get(userId);
}

function chatMessagesHtml(roomId, currentUserId) {
  const messages = db.prepare(`SELECT m.*, u.full_name FROM chat_messages m
    JOIN users u ON u.id = m.sender_id
    WHERE m.room_id = ? ORDER BY m.id ASC LIMIT 500`).all(roomId);
  if (!messages.length) return `
    <div class="support-chat-empty">
      <strong>Your conversation starts here</strong>
      <p>Send a message when you are ready. The MYFB support team will reply in this private room.</p>
    </div>
  `;
  return messages.map((message) => `
    <article class="support-message support-chat-message ${message.sender_id === currentUserId ? 'chat-message-own' : ''}">
      <div class="support-chat-message-head">
        <strong>${escapeHtml(message.sender_id === currentUserId ? 'You' : message.full_name)}</strong>
        <span class="support-chat-role ${message.sender_role === 'admin' ? 'support-chat-role-admin' : 'support-chat-role-customer'}">
          ${escapeHtml(message.sender_role === 'admin' ? 'MYFB Support' : 'Customer')}
        </span>
      </div>
      <p class="support-chat-message-body">${escapeHtml(message.body)}</p>
      <time class="support-chat-time" datetime="${escapeHtml(new Date(`${String(message.created_at).replace(' ', 'T')}Z`).toISOString())}">
        ${escapeHtml(new Date(`${String(message.created_at).replace(' ', 'T')}Z`).toLocaleString('en-GB'))}
      </time>
    </article>
  `).join('');
}

function customerChatBody(user, room, req) {
  const roomIsOpen = room.status === 'open';
  const composer = room.status === 'open'
    ? `<form method="POST" action="/rooms" class="stacked-form support-chat-composer">
        ${csrfToken(req)}
        <label>Message to MYFB support<textarea name="message" maxlength="4000" rows="4" required placeholder="Describe how we can help"></textarea></label>
        <div class="support-chat-composer-footer">
          <small>For your safety, never share passwords or payment details.</small>
          <button type="submit" class="btn btn-primary">Send message</button>
        </div>
      </form>`
    : '<div class="alert">This room is closed by an administrator. You can still view previous messages.</div>';
  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div><p class="eyebrow accent">Private support</p><h1>Your chat room</h1>
          <p>Contact the MYFB team in a private conversation visible only to you and authorized administrators.</p></div>
      </section>
      <section class="panel glass-panel support-chat-panel">
        <header class="support-chat-header">
          <div><p class="eyebrow accent">MYFB Customer Care</p><h2>Private conversation</h2>
            <p>Room messages are not visible to other customers.</p></div>
          <span class="support-chat-status ${roomIsOpen ? 'is-open' : 'is-closed'}">${roomIsOpen ? 'Open' : 'Closed'}</span>
        </header>
        <div class="support-chat-thread" data-chat-thread role="log" aria-live="polite" aria-relevant="additions text"
          aria-label="Private conversation with MYFB support">${chatMessagesHtml(room.id, user.id)}</div>
        ${composer}
      </section>
    </main>
  `;
}

function reportUserBody(user, req, errorMessage = '') {
  const reports = db.prepare(`SELECT reported_username, reason, status, details, created_at
    FROM user_reports WHERE reporter_user_id = ? ORDER BY created_at DESC LIMIT 50`).all(user.id);
  const rows = reports.length ? reports.map((report) => `
    <article class="support-message">
      <div><strong>@${escapeHtml(report.reported_username)}</strong>
        <span>${escapeHtml(report.status)}</span></div>
      <p><strong>Reason:</strong> ${escapeHtml(report.reason)}</p>
      ${report.details ? `<p>${escapeHtml(report.details)}</p>` : ''}
      <small>${escapeHtml(report.created_at)}</small>
    </article>
  `).join('') : '<p>You have not submitted any reports.</p>';
  return `<main class="container dashboard-shell">
    <section class="page-topper"><div><p class="eyebrow accent">Trust and safety</p><h1>Report a user</h1>
      <p>Reports are private and reviewed by the administrator. The reported user cannot see who submitted the report.</p></div>
      <a href="/dashboard" class="btn btn-secondary">Back to dashboard</a></section>
    <section class="panel glass-panel">
      ${errorMessage ? `<div class="alert error">${escapeHtml(errorMessage)}</div>` : ''}
      <form method="POST" action="/report-user" class="stacked-form">
        ${csrfToken(req)}
        <label>Registered username<input name="username" minlength="3" maxlength="30" autocomplete="off" required /></label>
        <label>Reason
          <select name="reason" required>
            <option value="">Choose a reason</option>
            <option value="harassment">Harassment or threats</option>
            <option value="impersonation">Impersonation</option>
            <option value="spam">Spam or scams</option>
            <option value="other">Other concern</option>
          </select>
        </label>
        <label>Details (optional)<textarea name="details" maxlength="2000" rows="5" placeholder="Describe what happened without sharing passwords or payment details."></textarea></label>
        <button type="submit" class="btn btn-primary">Submit private report</button>
      </form>
    </section>
    <section class="panel glass-panel">
      <h2>Your reports</h2>
      <div class="support-admin-list">${rows}</div>
    </section>
  </main>`;
}

function adminReportsBody(req) {
  const reports = db.prepare(`SELECT r.*, reporter.username AS reporter_username,
    reporter.full_name AS reporter_name, target.username AS current_target_username,
    target.account_status AS target_status
    FROM user_reports r
    JOIN users reporter ON reporter.id = r.reporter_user_id
    LEFT JOIN users target ON target.id = r.reported_user_id
    ORDER BY CASE r.status WHEN 'open' THEN 0 WHEN 'reviewing' THEN 1 ELSE 2 END,
      r.created_at DESC LIMIT 200`).all();
  const cards = reports.length ? reports.map((report) => `
    <article class="panel support-admin-card">
      <div class="support-admin-heading">
        <div><h2>@${escapeHtml(report.current_target_username || report.reported_username)}</h2>
          <p>Reported by ${escapeHtml(report.reporter_name)} (@${escapeHtml(report.reporter_username)}) ·
            ${escapeHtml(report.created_at)}</p></div>
        <span class="admin-pill">${escapeHtml(report.status)}</span>
      </div>
      <p><strong>Reason:</strong> ${escapeHtml(report.reason)}</p>
      <p class="support-request-copy">${escapeHtml(report.details || 'No additional details provided.')}</p>
      <p><strong>Account status:</strong> ${escapeHtml(report.target_status || 'Account unavailable')}</p>
      ${report.admin_notes ? `<div class="support-reply"><strong>Admin note</strong><p>${escapeHtml(report.admin_notes)}</p></div>` : ''}
      <form method="POST" action="/admin/reports/${report.id}" class="stacked-form">
        ${csrfToken(req)}
        <label>Review status
          <select name="status" required>
            <option value="open" ${report.status === 'open' ? 'selected' : ''}>Open</option>
            <option value="reviewing" ${report.status === 'reviewing' ? 'selected' : ''}>Reviewing</option>
            <option value="resolved" ${report.status === 'resolved' ? 'selected' : ''}>Resolved</option>
            <option value="dismissed" ${report.status === 'dismissed' ? 'selected' : ''}>Dismissed</option>
          </select>
        </label>
        <label>Account action
          <select name="accountAction">
            <option value="none">No account change</option>
            <option value="suspend">Suspend reported user</option>
            <option value="restore">Restore suspended user</option>
          </select>
        </label>
        <label>Administrator note<textarea name="adminNotes" maxlength="2000" rows="3">${escapeHtml(report.admin_notes)}</textarea></label>
        <button type="submit" class="btn btn-primary">Save review</button>
      </form>
    </article>
  `).join('') : '<section class="panel"><p>No user reports have been submitted.</p></section>';
  return `<main class="container dashboard-shell">
    <section class="page-topper"><div><p class="eyebrow accent">Trust and safety</p><h1>User reports</h1>
      <p>Review reports, add an internal note, and suspend or restore non-administrator accounts.</p></div>
      <a href="/admin" class="btn btn-secondary">Back to admin</a></section>
    <div class="support-admin-list">${cards}</div>
  </main>`;
}

function adminChatRoomsBody() {
  const rooms = db.prepare(`SELECT r.id, r.status, r.updated_at, u.full_name, u.username,
    (SELECT body FROM chat_messages WHERE room_id = r.id ORDER BY id DESC LIMIT 1) AS latest_message,
    (SELECT created_at FROM chat_messages WHERE room_id = r.id ORDER BY id DESC LIMIT 1) AS latest_at
    FROM chat_rooms r JOIN users u ON u.id = r.user_id
    WHERE u.role != 'admin'
    ORDER BY COALESCE(latest_at, r.updated_at) DESC, r.id DESC`).all();
  const roomCards = rooms.length ? rooms.map((room) => `
    <a class="panel support-admin-card support-chat-room-card" href="/admin/rooms/${room.id}">
      <div class="support-chat-room-heading">
        <h2>${escapeHtml(room.full_name)} <small>@${escapeHtml(room.username)}</small></h2>
        <span class="support-chat-status ${room.status === 'open' ? 'is-open' : 'is-closed'}">${room.status === 'open' ? 'Open' : 'Closed'}</span>
      </div>
      <p class="support-chat-room-preview">${escapeHtml(room.latest_message || 'No messages yet')}</p>
      <small>Last activity · ${escapeHtml(room.latest_at || room.updated_at)}</small>
    </a>
  `).join('') : '<section class="panel"><p>No customer rooms are available.</p></section>';
  return `<main class="container dashboard-shell">
    <section class="page-topper"><div><p class="eyebrow accent">Customer support</p><h1>Chat rooms</h1>
      <p>Each customer has a private room. Messages are visible only to the customer and administrators.</p></div></section>
    <div class="support-admin-list">${roomCards}</div>
  </main>`;
}

function adminChatRoomBody(room, customer, req) {
  const nextStatus = room.status === 'open' ? 'closed' : 'open';
  const statusLabel = room.status === 'open' ? 'Close room' : 'Reopen room';
  const composer = room.status === 'open'
    ? `<form method="POST" action="/admin/rooms/${room.id}" class="stacked-form support-chat-composer">
        ${csrfToken(req)}
        <label>Reply to customer<textarea name="message" maxlength="4000" rows="4" required placeholder="Write a clear, helpful reply"></textarea></label>
        <div class="support-chat-composer-footer">
          <small>Replies are visible to this customer in their private room.</small>
          <button type="submit" class="btn btn-primary">Send reply</button>
        </div>
      </form>`
    : '<div class="alert">This room is closed. Reopen it before sending another message.</div>';
  return `<main class="container dashboard-shell">
    <section class="page-topper"><div><p class="eyebrow accent">Customer chat</p>
      <h1>${escapeHtml(customer.full_name)}</h1><p>@${escapeHtml(customer.username)}</p></div>
      <a href="/admin/rooms" class="btn btn-secondary">All chat rooms</a></section>
    <section class="panel glass-panel support-chat-panel">
      <header class="support-chat-header">
        <div><p class="eyebrow accent">Private customer conversation</p><h2>@${escapeHtml(customer.username)}</h2>
          <p>Only this customer and authorized administrators can view this room.</p></div>
      </header>
      <div class="room-controls">
        <p>Room status: <strong>${escapeHtml(room.status)}</strong></p>
        <form method="POST" action="/admin/rooms/${room.id}/status">
          ${csrfToken(req)}
          <input type="hidden" name="status" value="${nextStatus}" />
          <button type="submit" class="btn btn-secondary">${statusLabel}</button>
        </form>
      </div>
      <div class="support-chat-thread" data-chat-thread role="log" aria-live="polite" aria-relevant="additions text"
        aria-label="Conversation with ${escapeHtml(customer.full_name)}">${chatMessagesHtml(room.id, req.session.userId)}</div>
      ${composer}
    </section>
  </main>`;
}

function adminBody(user) {
  const users = db.prepare(`SELECT id, full_name, username, role, account_status,
    marketing_email, marketing_consent, created_at
    FROM users ORDER BY created_at DESC`).all();
  const roomCount = db.prepare(`SELECT COUNT(*) AS count FROM chat_rooms r
    JOIN users u ON u.id = r.user_id WHERE u.role != 'admin'`).get().count;
  const openReportCount = db.prepare("SELECT COUNT(*) AS count FROM user_reports WHERE status IN ('open', 'reviewing')").get().count;
  const userRows = users.map((entry) => `
    <tr>
      <td>${escapeHtml(entry.full_name)}</td>
      <td>@${escapeHtml(entry.username)}</td>
      <td>${escapeHtml(entry.role)}</td>
      <td>${escapeHtml(entry.account_status)}</td>
      <td>${entry.marketing_consent && entry.marketing_email ? escapeHtml(entry.marketing_email) : 'Not opted in'}</td>
      <td>${escapeHtml(entry.created_at)}</td>
    </tr>
  `).join('');

  return `
    <main class="container dashboard-shell">
      <section class="page-topper">
        <div>
          <p class="eyebrow accent">Administrator dashboard</p>
          <h1>System overview</h1>
        </div>
        <a href="/admin/rooms" class="btn btn-primary">Open chat rooms</a>
      </section>
      <div class="cta-row admin-shortcuts">
        <a href="/admin/rooms" class="btn btn-secondary">Chat with clients</a>
        <a href="/admin/reports" class="btn btn-secondary">User reports (${openReportCount})</a>
        <a href="/admin/settings" class="btn btn-secondary">Website settings</a>
        <a href="/security" class="btn btn-secondary">Admin security</a>
      </div>
      <section class="panel glass-panel owner-profile">
        <h2>Owner account</h2>
        <p>Sign-in username: <strong>@${escapeHtml(user.username)}</strong></p>
        <p>Contact email: <strong>${escapeHtml(user.email)}</strong> <span class="form-help">Email is not used to sign in or for email delivery.</span></p>
      </section>
      <div class="stats-grid">
        ${buildStatCard('Registered users', String(users.length), 'info')}
        ${buildStatCard('Private chat rooms', String(roomCount), 'success')}
        ${buildStatCard('Reports to review', String(openReportCount), openReportCount ? 'warning' : 'info')}
        ${buildStatCard('Online services', 'Profiles and chat', 'info')}
      </div>
      <div class="dashboard-grid vertical">
        <section class="panel glass-panel">
          <h2>Users</h2>
          <table class="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Username</th>
                <th>Role</th>
                <th>Account status</th>
                <th>Advertising email consent</th>
                <th>Joined</th>
              </tr>
            </thead>
            <tbody>${userRows}</tbody>
          </table>
        </section>
      </div>
    </main>
  `;
}

function adminSiteSettingsBody(req) {
  return `
    <main class="container dashboard-shell">
      <section class="page-topper"><div><p class="eyebrow accent">Administrator controls</p><h1>Website settings</h1></div><a href="/admin" class="btn btn-secondary">Back to admin</a></section>
      <section class="panel glass-panel">
        <h2>Customer-facing information</h2>
        <p>Changes below are saved in the database and appear on public and customer pages. Keep the announcement factual and do not promise investment returns.</p>
        <form method="POST" action="/admin/settings" class="stacked-form">
          ${csrfToken(req)}
          <label>Moving announcement / educational notice
            <textarea name="announcement" maxlength="240" rows="3" required>${escapeHtml(getSiteSetting('announcement'))}</textarea>
          </label>
          <label>WhatsApp contact number (international digits, no plus or spaces; leave blank to hide)
            <input type="tel" name="whatsappNumber" inputmode="numeric" pattern="[0-9]{10,15}" maxlength="15" value="${escapeHtml(getSiteSetting('whatsapp_number'))}" />
          </label>
          <label>Community rules shown to customers
            <textarea name="communityRules" maxlength="4000" rows="8" required>${escapeHtml(getSiteSetting('community_rules') || DEFAULT_COMMUNITY_RULES)}</textarea>
          </label>
          <button type="submit" class="btn btn-primary">Save website settings</button>
        </form>
      </section>
      <section class="panel glass-panel">
        <h2>Available services</h2>
        <p>This installation supports profiles and private customer chats. Deposits, withdrawals, and investment transactions are disabled.</p>
      </section>
    </main>
  `;
}

function adminSupportBody(req) {
  const items = db.prepare(`SELECT * FROM support_messages
    ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END, created_at DESC LIMIT 100`).all();
  const cards = items.length ? items.map((item) => `
    <article class="panel support-admin-card">
      <div class="support-admin-heading">
        <div><h2>${escapeHtml(item.name)}</h2><p>Status: <strong>${escapeHtml(item.status || 'open')}</strong> · ${escapeHtml(item.created_at)}</p></div>
      </div>
      <p class="support-request-copy">${escapeHtml(item.message)}</p>
      ${item.admin_response ? `<div class="support-reply"><strong>Previous response</strong><p>${escapeHtml(item.admin_response)}</p></div>` : ''}
      <form method="POST" action="/admin/support/${item.id}" class="stacked-form">
        ${csrfToken(req)}
        <label>Reply / internal update<textarea name="response" maxlength="4000" rows="4">${escapeHtml(item.admin_response || '')}</textarea></label>
        <label>Request status<select name="status">
          <option value="open" ${item.status === 'open' ? 'selected' : ''}>Open</option>
          <option value="in_progress" ${item.status === 'in_progress' ? 'selected' : ''}>In progress</option>
          <option value="resolved" ${item.status === 'resolved' ? 'selected' : ''}>Resolved</option>
        </select></label>
        <button class="btn btn-primary" type="submit">Save response and status</button>
      </form>
    </article>
  `).join('') : '<section class="panel"><p>No customer or contact messages have been received.</p></section>';
  return `<main class="container dashboard-shell"><section class="page-topper"><div><p class="eyebrow accent">Customer care</p><h1>Complaints and support</h1><p>Only authorized administrators can view and update these requests. Customer replies are visible only to the customer who submitted them.</p></div><a href="/admin" class="btn btn-secondary">Back to admin</a></section><div class="support-admin-list">${cards}</div></main>`;
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:']
    }
  }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-session-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' }
}));

app.use((req, res, next) => {
  if (!req.session.userId) return next();
  const user = db.prepare('SELECT session_version FROM users WHERE id = ?').get(req.session.userId);
  if (user && req.session.sessionVersion === undefined && user.session_version === 0) {
    req.session.sessionVersion = 0;
    return next();
  }
  if (user && req.session.sessionVersion === user.session_version) return next();
  req.session.destroy((error) => {
    if (error) return next(error);
    return res.redirect('/login');
  });
});

app.use((req, res, next) => {
  const flash = req.session.flash || [];
  global.__flash = flash;
  req.session.flash = [];
  res.locals.flash = flash;
  res.locals.user = getCurrentUser(req);
  res.locals.isAdmin = !!(res.locals.user && res.locals.user.role === 'admin');
  next();
});

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests. Please try again later.'
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    setFlash(req, 'Please sign in to access that page.', 'error');
    return res.redirect('/login');
  }
  const user = db.prepare('SELECT session_version FROM users WHERE id = ?').get(req.session.userId);
  if (!user || (req.session.sessionVersion !== undefined && req.session.sessionVersion !== user.session_version)) {
    req.session.destroy(() => res.redirect('/login'));
    return;
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    setFlash(req, 'Please sign in to access that page.', 'error');
    return res.redirect('/login');
  }
  const user = getCurrentUser(req);
  if (!user || (req.session.sessionVersion !== undefined && req.session.sessionVersion !== user.session_version)) {
    req.session.destroy(() => res.redirect('/login'));
    return;
  }
  if (user.role !== 'admin') {
    setFlash(req, 'You do not have permission to access that resource.', 'error');
    return res.redirect('/dashboard');
  }
  next();
}

function requireFinancialEligibility(req, res, next) {
  const user = getCurrentUser(req);
  if (!user || !user.is_verified || !user.phone_verified || user.identity_status !== 'verified') {
    return res.status(403).send(renderPage({
      title: 'Financial features restricted',
      user,
      pageClass: 'dashboard-page',
      body: `<main class="container dashboard-shell"><h1>Financial features are restricted</h1><p>Verify your email and mobile number, then complete an approved identity review. A valid ID-number format alone is not identity verification. No deposit can be started until these checks are complete.</p>${user && !user.phone_verified ? '<p><a class="btn btn-primary" href="/verify-phone">Verify mobile number</a></p>' : ''}<p>Contact support for the secure identity-review process.</p><a href="/wallet">Return to wallet</a></main>`
    }));
  }
  next();
}

app.get('/', (req, res) => {
  res.send(renderPage({ title: 'Home', user: getCurrentUser(req), pageClass: 'home-page', body: homePageBody(getCurrentUser(req)) }));
});

app.get('/about', (req, res) => {
  res.send(aboutPage(getCurrentUser(req))); 
});

app.get('/how-it-works', (req, res) => {
  res.send(renderStaticPage({
    title: 'How It Works',
    user: getCurrentUser(req),
    html: `
      <p class="eyebrow accent">How it works</p>
      <h1>Five simple steps to use MYFB.</h1>
      <div class="timeline-grid compact-grid">
        <div class="timeline-item"><span class="step-num">1</span><h3>Create an Account</h3><p>Choose a username and password. Email is optional and used only for advertising if you opt in.</p></div>
        <div class="timeline-item"><span class="step-num">2</span><h3>Set up your profile</h3><p>Add or update your display name and optional advertising preference.</p></div>
        <div class="timeline-item"><span class="step-num">3</span><h3>Secure Your Account</h3><p>Use a strong, unique password and update it from your account when needed.</p></div>
        <div class="timeline-item"><span class="step-num">4</span><h3>Chat privately</h3><p>Use your private room to contact an administrator. Only you and administrators can see it.</p></div>
        <div class="timeline-item"><span class="step-num">5</span><h3>Read educational information</h3><p>Public information is available to everyone; no deposits, withdrawals, or investment transactions are available.</p></div>
      </div>
    `
  }));
});

app.get('/community-rules', (req, res) => {
  const rules = getSiteSetting('community_rules') || DEFAULT_COMMUNITY_RULES;
  return res.send(renderStaticPage({
    title: 'Community Rules',
    user: getCurrentUser(req),
    html: `<p class="eyebrow accent">Community standards</p>
      <h1>Community Rules</h1>
      <p>These rules apply to account profiles and private support conversations.</p>
      <div class="rules-copy">${escapeHtml(rules)}</div>`
  }));
});

app.get('/investment-information', (req, res) => {
  const user = getCurrentUser(req);
  const products = publishedInvestmentProducts();
  const catalogue = products.length
    ? `<div class="investment-product-grid">${products.map(investmentProductCard).join('')}</div>`
    : `<section class="payment-unavailable-card" role="status">
        <span class="unavailable-icon" aria-hidden="true">i</span>
        <div><h2>No products currently available</h2>
          <p>No investment products are currently available. Investment services will become available only after the relevant provider, product terms, fees, eligibility requirements, and necessary authorizations have been verified.</p>
        </div>
      </section>`;
  res.send(renderStaticPage({
    title: 'Investment Information',
    user,
    html: `
      <p class="eyebrow accent">Investment information</p>
      <h1>Investment opportunities and product information</h1>
      <p class="product-lead">Use this page to understand a product before making a decision. Product details are shown only after publication checks; an empty catalogue means there is no investment offer through this website.</p>
      <section aria-labelledby="product-catalogue-heading">
        <h2 id="product-catalogue-heading">Available investment products</h2>
        ${catalogue}
      </section>
      <div class="investment-product-grid investment-education-grid">
        <article class="info-card"><h2>Product and provider</h2><p>Check what the product does, who provides it, how it works, and what official records support the provider and authorization information. Verify claims independently.</p></article>
        <article class="info-card"><h2>Minimums, fees, and time</h2><p>A genuine offer should state any minimum investment, every applicable fee or charge, and the expected time horizon. Do not assume blank or missing information means there is no fee.</p></article>
        <article class="info-card"><h2>Eligibility</h2><p>Eligibility may depend on identity checks, location, age, financial circumstances, and legal requirements. Reading a page does not establish eligibility or suitability.</p></article>
        <article class="info-card"><h2>Risk and possible loss</h2><p>Investment values can rise or fall. You may lose some or all of the capital you invest. Returns are never guaranteed by this information page.</p></article>
        <article class="info-card"><h2>Withdrawals and liquidity</h2><p>Some products may restrict access, delay withdrawals, or have no ready buyer. Read the actual terms for withdrawal windows, notice periods, and charges.</p></article>
        <article class="info-card"><h2>Terms and support</h2><p>Read the full product terms and risk disclosures before proceeding. Contact support if information is unclear; never send money based only on an informal message.</p></article>
      </div>
      <section class="note-box">
        <strong>Important risk notice:</strong> Market volatility, fees, liquidity limits, operational failure, and fraud can all cause loss. Past performance does not guarantee future results. Check provider authorization with relevant official sources and seek qualified independent advice if needed.
      </section>
      <p><a href="/trading-risks">Review trading risks</a> · <a href="/risk-disclosure">Read the risk disclosure</a> · <a href="/support">Contact support</a></p>
    `
  }));
});

app.get('/investment-information/:slug', (req, res) => {
  const product = publishedInvestmentProducts().find((entry) => entry.slug === req.params.slug);
  if (!product) {
    return res.status(404).send(renderStaticPage({
      title: 'Product information unavailable',
      user: getCurrentUser(req),
      html: '<p class="eyebrow accent">Investment information</p><h1>Product information unavailable</h1><p>This product is not currently published or has not passed all required publication checks.</p><p><a href="/investment-information">Return to investment information</a></p>'
    }));
  }
  return res.send(investmentProductDetails(product, getCurrentUser(req)));
});

app.get('/trading-risks', (req, res) => {
  res.send(renderStaticPage({
    title: 'Trading Risks',
    user: getCurrentUser(req),
    html: `
      <p class="eyebrow accent">Trading risks</p>
      <h1>Understand the risks before investing</h1>
      <p>Investment risk means that the outcome can differ from what you expect. You could receive less than you invested, or lose all of it. Do not invest money needed for rent, food, debt payments, or emergencies.</p>
      <div class="risk-information-grid">
        <section class="info-card"><h2>Loss and market volatility</h2><p>Prices can change quickly because of economic events, markets, interest rates, currency movements, or company performance. A product can fall in value and may not recover.</p></section>
        <section class="info-card"><h2>Liquidity and access</h2><p>Liquidity is how easily an investment can be sold or withdrawn. Some products have lock-in periods, notice periods, delays, or no active buyer when you need your money.</p></section>
        <section class="info-card"><h2>Fees and charges</h2><p>Entry, management, performance, withdrawal, transaction, and other charges can reduce what you receive. Read every fee and ask for clarification before deciding.</p></section>
        <section class="info-card"><h2>Fraud and provider risk</h2><p>Fraudsters may impersonate legitimate businesses or promise unusually high or guaranteed returns. Independently check the provider and any claimed authorization using official contact details and registers.</p></section>
        <section class="info-card"><h2>Past performance</h2><p>Past results do not predict or guarantee future returns. Historical charts can omit costs and do not show what will happen next.</p></section>
        <section class="info-card"><h2>Operational and concentration risk</h2><p>Technology, custody, service-provider, or record-keeping problems can affect access to funds. Putting too much money into one product can increase the impact of a loss.</p></section>
      </div>
      <div class="note-box"><strong>Beginner reminder:</strong> If you do not understand how a product works, how you can lose money, or how to withdraw, do not proceed until you have independently clarified it.</div>
      <p><a href="/risk-disclosure">Read the full risk disclosure</a> · <a href="/investment-information">Investment information</a> · <a href="/support">Contact support</a></p>
    `
  }));
});

app.get('/faq', (req, res) => {
  res.send(faqPage(getCurrentUser(req)));
});

app.get('/contact', (req, res) => {
  res.send(contactPage(getCurrentUser(req), req));
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many messages. Please wait before contacting us again.'
});

app.post('/contact', contactLimiter, requireCsrf, (req, res) => {
  return res.status(410).send('Use your private chat room to contact an administrator.');
});

app.get('/privacy-policy', (req, res) => {
  res.send(staticLegalPage({
    title: 'Privacy Policy',
    user: getCurrentUser(req),
    heading: 'Your privacy matters.',
    body: `
      <p>Accounts use a username and password. Email is optional; when you explicitly opt in, it is stored only for advertising. It is not used to sign in, verify an account, or send support replies. You can withdraw advertising consent and remove your email from your profile.</p>
      <p>The public contact form collects your name and message, not your email address. Private chat messages are visible to the account owner and authorized administrators. We do not collect identity numbers through this website.</p>
      <p>The operator must document and implement applicable POPIA purposes, retention periods, data-subject processes, and authorized staff access.</p>
    `
  }));
});

app.get('/terms-and-conditions', (req, res) => {
  res.send(staticLegalPage({
    title: 'Terms and Conditions',
    user: getCurrentUser(req),
    heading: 'Account terms and usage conditions.',
    body: `
      <p>Users must provide accurate information, maintain secure credentials, and comply with our policies when using the platform.</p>
      <p>MYFB Investment provides digital account access and educational content. It does not guarantee financial results or outcomes.</p>
    `
  }));
});

app.get('/risk-disclosure', (req, res) => {
  res.send(staticLegalPage({
    title: 'Risk Disclosure',
    user: getCurrentUser(req),
    heading: 'Investment risk disclosure.',
    body: `
      <p>You may lose some or all of the capital you invest. No product, provider, or information on this site guarantees a profit or protects you against every loss.</p>
      <p><strong>Market risk:</strong> Prices and values can move quickly or remain below the amount invested. Past performance is not a reliable indicator of future results and does not guarantee future returns.</p>
      <p><strong>Liquidity risk:</strong> You may not be able to sell or withdraw when you want. A product may impose lock-ins, notice periods, delays, or conditions, and a buyer may not be available.</p>
      <p><strong>Fees and charges:</strong> Fees, taxes, and other charges reduce returns and can apply even when an investment loses value. Read the complete fee schedule and product terms.</p>
      <p><strong>Provider and fraud risk:</strong> A convincing website or claimed registration is not proof of authorization. Check the provider, the exact service, and any claimed authorization independently through relevant official sources. Be cautious of pressure, secrecy, requests to pay personal accounts, or guaranteed-return claims.</p>
      <p><strong>Operational risk:</strong> Provider, custody, technology, and record-keeping failures can delay access or cause losses. Only use a service with clear, tested payment, transaction, reconciliation, and complaint processes.</p>
      <p>This disclosure is general educational information, not individual financial, legal, or tax advice, a suitability assessment, or an offer to invest. Consider qualified independent advice and never invest money you cannot afford to lose.</p>
      <p><a href="/trading-risks">Read the beginner-friendly trading risk guide</a> · <a href="/investment-information">Review investment information</a> · <a href="/support">Contact support</a></p>
    `
  }));
});

app.get('/complaints-procedure', (req, res) => {
  res.send(staticLegalPage({
    title: 'Complaints Procedure',
    user: getCurrentUser(req),
    heading: 'How to raise a concern.',
    body: `
      <p>Contact our support team with details of your concern, including dates, account details, and any relevant documents.</p>
      <p>Signed-in customers can use their private chat room to contact an administrator. The public contact form does not request an email address.</p>
    `
  }));
});

app.get('/account-security', (req, res) => {
  res.send(staticLegalPage({
    title: 'Account Security',
    user: getCurrentUser(req),
    heading: 'Keep your account secure.',
    body: `
      <p>Use a strong, unique password and change it from your account if you think it may have been exposed.</p>
      <p>Sign out when using a shared device, and contact the admin team through your private chat room if you need account help.</p>
    `
  }));
});

const loginAttemptLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => {
    recordSecurityEvent(req, 'sign_in_rate_limited', String(req.body.identifier || req.body.email || ''));
    res.status(429).send('Too many sign-in attempts. Please wait before trying again.');
  },
  message: 'Too many sign-in attempts. Please wait before trying again.'
});
const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => {
    recordSecurityEvent(req, 'registration_rate_limited', String(req.body.email || ''));
    res.status(429).send('Too many registration attempts. Please wait before trying again.');
  },
  message: 'Too many registration attempts. Please wait before trying again.'
});
const recoveryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => {
    recordSecurityEvent(req, 'recovery_rate_limited', String(req.body.identifier || req.body.email || ''));
    res.status(429).send('Too many recovery attempts. Please wait before trying again.');
  },
  message: 'Too many recovery attempts. Please wait before trying again.'
});

app.get('/login', (req, res) => {
  res.send(loginPage(getCurrentUser(req), req.query.error || '', csrfToken(req)));
});

app.post('/login', loginAttemptLimiter, requireCsrf, (req, res, next) => {
  const username = normalizeUsername(req.body.username || req.body.identifier);
  const password = String(req.body.password || '');

  if (!username || !password) {
    setFlash(req, 'Please provide your username and password.', 'error');
    return res.redirect('/login');
  }

  const user = db.prepare('SELECT * FROM users WHERE lower(username) = ?').get(username);
  if (!user || user.account_status !== 'active' || !bcrypt.compareSync(password, user.password_hash)) {
    setFlash(req, 'The username or password is incorrect.', 'error');
    return res.redirect('/login');
  }

  if (user.two_factor_enabled) {
    return req.session.regenerate((error) => {
      if (error) return next(error);
      req.session.pendingLoginUserId = user.id;
      req.session.pendingLoginEmail = user.email;
      return res.redirect('/two-factor');
    });
  }

  return req.session.regenerate((error) => {
    if (error) return next(error);
    req.session.userId = user.id;
    req.session.sessionVersion = user.session_version || 0;
    setFlash(req, 'Welcome back to MYFB Investment.', 'success');
    return res.redirect('/dashboard');
  });
});

app.get('/two-factor', (req, res) => {
  if (!req.session.pendingLoginUserId) return res.redirect('/login');
  const user = getCurrentUser(req) || db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.pendingLoginUserId);
  res.send(twoFactorPage(user, '', csrfToken(req)));
});

app.post('/two-factor', requireCsrf, (req, res, next) => {
  const code = String(req.body.code || '').trim();
  const userId = req.session.pendingLoginUserId;
  if (!userId) {
    setFlash(req, 'Your sign-in session expired. Please log in again.', 'error');
    return res.redirect('/login');
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user || !user.two_factor_secret) {
    setFlash(req, 'Two-factor configuration is missing. Please sign in again.', 'error');
    return res.redirect('/login');
  }

  const isValid = authenticator.check(code, user.two_factor_secret);
  if (!isValid) {
    return res.send(twoFactorPage(user, 'The authentication code is invalid. Please try again.', csrfToken(req)));
  }

  return req.session.regenerate((error) => {
    if (error) return next(error);
    req.session.userId = user.id;
    req.session.sessionVersion = user.session_version || 0;
    setFlash(req, 'Two-factor verification succeeded.', 'success');
    return res.redirect('/dashboard');
  });
});

app.get('/verify-email/:token', (req, res) => {
  return res.status(410).send('Email verification is not used. Sign in with your username instead.');
});

app.use('/verify-phone', requireAuth, (req, res) => res.redirect('/dashboard'));

app.use(['/forgot-username', '/forgot-password', '/resend-verification', '/reset-password'], (req, res) => {
  return res.redirect('/login');
});

app.get('/register', (req, res) => res.send(registerPage(getCurrentUser(req), '', csrfToken(req))));

app.post('/register', registrationLimiter, requireCsrf, async (req, res) => {
  const firstName = String(req.body.firstName || '').trim();
  const lastName = String(req.body.lastName || '').trim();
  const fullName = `${firstName} ${lastName}`.trim();
  const username = normalizeUsername(req.body.username);
  const marketingConsent = req.body.marketingConsent === 'on';
  const marketingEmail = marketingConsent ? normalizeEmail(req.body.email || '') : null;
  const password = String(req.body.password || '');
  const confirmPassword = String(req.body.confirmPassword || '');
  const formError = (message, status = 400) => res.status(status).send(registerPage(getCurrentUser(req), message, csrfToken(req)));

  if (!firstName || !lastName || !username || !password || !confirmPassword) {
    return formError('Please complete your name, username, and password.');
  }

  if (req.body.termsAccepted !== 'on') {
    return formError('You must accept the Terms and Conditions and acknowledge the Privacy Notice.');
  }

  if (marketingConsent && !isValidEmail(marketingEmail)) {
    return formError('Enter a valid email address to opt in to advertising emails.');
  }

  if (!/^[a-z0-9][a-z0-9._-]{2,29}$/.test(username)) {
    return formError('Choose a username of 3–30 letters, numbers, dots, underscores or hyphens.');
  }

  if (!isValidAccountPassword(password)) {
    return formError('Use a password with at least 6 characters.');
  }

  if (password !== confirmPassword) {
    return formError('Passwords do not match.');
  }

  const internalEmail = `account-${crypto.randomBytes(16).toString('hex')}@myfb.invalid`;
  const passwordHash = await hashPassword(password);
  try {
    const createAccount = db.transaction(() => {
      const duplicate = db.prepare('SELECT id FROM users WHERE lower(username) = ?').get(username);
      if (duplicate) throw new Error('ACCOUNT_DETAILS_UNAVAILABLE');
      const result = db.prepare(`
        INSERT INTO users (first_name, last_name, full_name, username, email, password_hash,
          is_verified, role, account_status, identity_status, identity_method,
          marketing_email, marketing_consent, marketing_consent_at,
          terms_accepted_at, privacy_notice_version)
        VALUES (?, ?, ?, ?, ?, ?, 1, 'user', 'active', 'unverified', 'not_collected',
          ?, ?, CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END, CURRENT_TIMESTAMP, '2026-01')
      `).run(
        firstName, lastName, fullName, username, internalEmail, passwordHash,
        marketingEmail, marketingConsent ? 1 : 0, marketingConsent ? 1 : 0
      );
      const newId = Number(result.lastInsertRowid);
      db.prepare(`INSERT INTO transactions (user_id, type, amount, description, status, reference)
        VALUES (?, 'account', 0, 'Account created', 'completed', ?)`).run(newId, `ACC-${newId}`);
      db.prepare(`INSERT INTO notifications (user_id, title, content) VALUES (?, ?, ?)`)
        .run(newId, 'Account created', 'Your account is ready. Use your username to sign in and message an administrator in your private chat room.');
      db.prepare('INSERT INTO chat_rooms (user_id) VALUES (?)').run(newId);
      return newId;
    });
    createAccount();
  } catch (error) {
    if (error.message === 'ACCOUNT_DETAILS_UNAVAILABLE' || String(error.code || '').startsWith('SQLITE_CONSTRAINT')) {
      recordSecurityEvent(req, 'registration_details_conflict', username);
      return formError('That username is unavailable. If you already have an account, sign in with your username.');
    }
    console.error('Account registration failed.');
    return formError('We could not complete registration right now. Please try again later.', 500);
  }
  setFlash(req, 'Your account is ready. Sign in with your username and password.', 'success');
  return res.redirect('/login');
});

app.get('/verify-phone', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  if (!user.is_verified) return res.status(403).send(phoneVerificationPage(user, 'Verify your email address before verifying your phone.', csrfToken(req)));
  res.send(phoneVerificationPage(user, '', csrfToken(req), Boolean(user.phone_otp_requested_at)));
});

const phoneVerificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    recordSecurityEvent(req, 'phone_verification_rate_limited');
    res.status(429).send('Too many SMS verification attempts. Please wait before trying again.');
  },
  message: 'Too many SMS verification attempts. Please wait before trying again.'
});

app.post('/verify-phone/send', requireAuth, phoneVerificationLimiter, requireCsrf, async (req, res) => {
  const user = getCurrentUser(req);
  const messaging = app.locals.accountMessaging || defaultAccountMessaging;
  if (!user.is_verified) return res.status(403).send(phoneVerificationPage(user, 'Verify your email address before verifying your phone.', csrfToken(req)));
  if (user.phone_verified) return res.redirect('/dashboard');
  const now = Date.now();
  if (!messaging.twilioConfigured()) {
    return res.status(503).send(phoneVerificationPage(user, 'SMS verification is not configured. No code has been sent.', csrfToken(req)));
  }
  const windowExpired = !user.phone_otp_window_started_at || now - user.phone_otp_window_started_at > 24 * 60 * 60 * 1000;
  const reserved = db.prepare(`UPDATE users SET phone_otp_requested_at = ?, phone_otp_attempts = 0,
    phone_otp_window_started_at = CASE WHEN ? = 1 THEN ? ELSE phone_otp_window_started_at END,
    phone_otp_requests = CASE WHEN ? = 1 THEN 1 ELSE phone_otp_requests + 1 END
    WHERE id = ? AND (phone_otp_requested_at IS NULL OR phone_otp_requested_at <= ?)
      AND (? = 1 OR phone_otp_requests < 5)`).run(
    now, windowExpired ? 1 : 0, now, windowExpired ? 1 : 0, user.id,
    now - 60 * 1000, windowExpired ? 1 : 0
  );
  if (!reserved.changes) {
    recordSecurityEvent(req, 'phone_verification_resend_limited', user.email);
    return res.status(429).send(phoneVerificationPage(user, 'SMS resend is limited. Wait one minute between requests and no more than five per day.', csrfToken(req)));
  }
  try {
    const sent = await messaging.sendSmsOtp(user.phone);
    if (!sent) return res.status(503).send(phoneVerificationPage(user, 'SMS verification is not configured. No code has been sent.', csrfToken(req)));
    return res.send(phoneVerificationPage({ ...user, phone_otp_requested_at: now }, 'A verification code was sent to your mobile number.', csrfToken(req), true));
  } catch {
    console.error('SMS verification delivery failed.');
    return res.status(502).send(phoneVerificationPage(user, 'The SMS provider could not send a code. Please try again later.', csrfToken(req)));
  }
});

app.post('/verify-phone', requireAuth, phoneVerificationLimiter, requireCsrf, async (req, res) => {
  const user = getCurrentUser(req);
  const code = String(req.body.code || '').trim();
  if (!user.is_verified || !user.phone_otp_requested_at || Date.now() - user.phone_otp_requested_at > 10 * 60 * 1000) {
    return res.status(400).send(phoneVerificationPage(user, 'The code is missing or expired. Request a new code.', csrfToken(req)));
  }
  if (!/^\d{4,10}$/.test(code) || user.phone_otp_attempts >= 5) {
    recordSecurityEvent(req, 'phone_verification_attempt_limited', user.email);
    return res.status(429).send(phoneVerificationPage(user, 'The code is invalid or the attempt limit was reached. Request a new code.', csrfToken(req)));
  }
  db.prepare('UPDATE users SET phone_otp_attempts = phone_otp_attempts + 1 WHERE id = ?').run(user.id);
  const messaging = app.locals.accountMessaging || defaultAccountMessaging;
  try {
    const valid = await messaging.verifySmsOtp(user.phone, code);
    if (!valid) {
      recordSecurityEvent(req, 'phone_verification_code_rejected', user.email);
      return res.status(400).send(phoneVerificationPage(user, 'The SMS code was not accepted. Check it and try again.', csrfToken(req), true));
    }
    try {
      db.prepare(`UPDATE users SET phone_verified = 1, phone_otp_requested_at = NULL,
        phone_otp_attempts = 0, account_status = CASE WHEN is_verified = 1 THEN 'active' ELSE 'pending_verification' END,
        updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(user.id);
    } catch (error) {
      if (String(error.code || '').startsWith('SQLITE_CONSTRAINT')) {
        recordSecurityEvent(req, 'verified_phone_conflict', user.email);
        return res.status(400).send(phoneVerificationPage(user, 'We could not complete verification for this account. Use account recovery or contact support.', csrfToken(req), true));
      }
      console.error('Phone verification status update failed.');
      return res.status(500).send(phoneVerificationPage(user, 'We could not complete verification. Please try again later.', csrfToken(req), true));
    }
    setFlash(req, 'Your mobile number is verified. Identity review is still required before financial features can be enabled.');
    return res.redirect('/dashboard');
  } catch {
    console.error('SMS verification check failed.');
    return res.status(502).send(phoneVerificationPage(user, 'The SMS provider could not verify this code. Please try again later.', csrfToken(req), true));
  }
});

app.get('/forgot-username', (req, res) => res.send(recoveryPage('username', '', csrfToken(req))));
app.post('/forgot-username', recoveryLimiter, requireCsrf, async (req, res) => {
  const identifier = String(req.body.identifier || '').trim();
  const email = normalizeEmail(identifier);
  const phone = normalizePhone(identifier);
  const messaging = app.locals.accountMessaging || defaultAccountMessaging;
  const user = email ? db.prepare('SELECT * FROM users WHERE lower(email) = ? AND is_verified = 1').get(email)
    : (phone ? db.prepare('SELECT * FROM users WHERE phone = ? AND phone_verified = 1').get(phone) : null);
  try {
    if (user && email && messaging.emailConfigured()) {
      await messaging.sendEmail({ to: user.email, subject: 'MYFB Investment username recovery', text: `Your MYFB username is: ${user.username}` });
    } else if (user && phone && messaging.twilioConfigured({ messaging: true })) {
      await messaging.sendRecoverySms(user.phone, `Your MYFB Investment username is: ${user.username}`);
    }
  } catch {
    console.error('Username recovery delivery failed.');
  }
  const emailStatus = messaging.emailConfigured() ? 'configured' : 'not configured';
  const smsStatus = messaging.twilioConfigured({ messaging: true }) ? 'configured' : 'not configured';
  return res.send(recoveryPage('username', `If a matching verified account has an available provider, recovery will be sent. Current delivery configuration: email ${emailStatus}; SMS ${smsStatus}.`, csrfToken(req)));
});

app.get('/forgot-password', (req, res) => res.send(recoveryPage('password', '', csrfToken(req))));
app.post('/forgot-password', recoveryLimiter, requireCsrf, async (req, res) => {
  const email = normalizeEmail(req.body.identifier);
  const user = db.prepare('SELECT * FROM users WHERE lower(email) = ? AND is_verified = 1').get(email);
  const messaging = app.locals.accountMessaging || defaultAccountMessaging;
  if (user && messaging.emailConfigured()) {
    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const windowExpired = !user.password_reset_request_window_started_at || now - user.password_reset_request_window_started_at > 60 * 60 * 1000;
    const reserved = db.prepare(`UPDATE users SET password_reset_token_hash = ?, password_reset_expires_at = ?,
      password_reset_used_at = NULL, password_reset_requested_at = ?,
      password_reset_request_window_started_at = CASE WHEN ? = 1 THEN ? ELSE password_reset_request_window_started_at END,
      password_reset_requests = CASE WHEN ? = 1 THEN 1 ELSE password_reset_requests + 1 END
      WHERE id = ? AND (? = 1 OR password_reset_requests < 3)`).run(
      hashRecoveryToken(token), now + 30 * 60 * 1000, now,
      windowExpired ? 1 : 0, now, windowExpired ? 1 : 0, user.id, windowExpired ? 1 : 0
    );
    if (!reserved.changes) {
      recordSecurityEvent(req, 'password_recovery_rate_limited', user.email);
      const deliveryStatus = messaging.emailConfigured() ? 'configured' : 'not configured';
      return res.send(recoveryPage('password', `If an email-verified account matches, reset instructions will be sent only if the email provider accepts the message. Email delivery is ${deliveryStatus}.`, csrfToken(req)));
    }
    try {
      const sent = await messaging.sendEmail({
        to: user.email,
        subject: 'Reset your MYFB Investment password',
        text: `Use this single-use link within 30 minutes to set a new password: ${baseUrl}/reset-password/${token}`
      });
      if (!sent) {
        db.prepare('UPDATE users SET password_reset_token_hash = NULL, password_reset_expires_at = NULL WHERE id = ?').run(user.id);
      }
    } catch {
      db.prepare('UPDATE users SET password_reset_token_hash = NULL, password_reset_expires_at = NULL WHERE id = ?').run(user.id);
      console.error('Password recovery email delivery failed.');
    }
  }
  const deliveryStatus = messaging.emailConfigured() ? 'configured' : 'not configured';
  return res.send(recoveryPage('password', `If an email-verified account matches, reset instructions will be sent only if the email provider accepts the message. Email delivery is ${deliveryStatus}.`, csrfToken(req)));
});

app.get('/resend-verification', (req, res) => res.send(renderPage({
  title: 'Resend verification email',
  user: null,
  pageClass: 'auth-page',
  body: `<main class="container auth-wrap"><div class="auth-card"><p class="eyebrow accent">Account verification</p><h1>Resend verification email</h1><form method="POST" action="/resend-verification" class="stacked-form">${csrfToken(req)}<label>Email address<input type="email" name="email" autocomplete="email" required /></label><button class="btn btn-primary full-width" type="submit">Request verification email</button></form><p class="auth-links"><a href="/login">Return to sign in</a></p></div></main>`
})));
app.post('/resend-verification', recoveryLimiter, requireCsrf, async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const user = db.prepare('SELECT id, email, verification_token FROM users WHERE lower(email) = ? AND is_verified = 0').get(email);
  const messaging = app.locals.accountMessaging || defaultAccountMessaging;
  if (user && messaging.emailConfigured()) {
    try {
      await messaging.sendEmail({
        to: user.email,
        subject: 'Verify your MYFB Investment email',
        text: `Use this link to verify your email address: ${baseUrl}/verify-email/${user.verification_token}`
      });
    } catch {
      console.error('Account verification email delivery failed.');
    }
  }
  return res.send(renderPage({
    title: 'Resend verification email',
    user: null,
    pageClass: 'auth-page',
    body: `<main class="container auth-wrap"><div class="auth-card"><p class="eyebrow accent">Account verification</p><h1>Request received</h1><p>If an unverified account matches, an email will be sent when delivery is configured.</p>${messaging.emailConfigured() ? '' : '<div class="alert">Email delivery is not configured. No verification email was sent.</div>'}<p class="auth-links"><a href="/login">Return to sign in</a></p></div></main>`
  }));
});

app.get('/reset-password/:token', (req, res) => {
  const token = String(req.params.token || '');
  const user = db.prepare(`SELECT id, role FROM users WHERE password_reset_token_hash = ?
    AND password_reset_expires_at > ? AND password_reset_used_at IS NULL`).get(hashRecoveryToken(token), Date.now());
  if (!user) return res.status(400).send(recoveryPage('reset', 'This password-reset link is invalid, expired, or already used.', csrfToken(req)));
  return res.send(recoveryPage('reset', '', csrfToken(req), token, user.role === 'admin'));
});

app.post('/reset-password/:token', recoveryLimiter, requireCsrf, async (req, res) => {
  const token = String(req.params.token || '');
  const password = String(req.body.password || '');
  const confirmation = String(req.body.confirmPassword || '');
  const tokenHash = hashRecoveryToken(token);
  const user = db.prepare(`SELECT * FROM users WHERE password_reset_token_hash = ?
    AND password_reset_expires_at > ? AND password_reset_used_at IS NULL`).get(tokenHash, Date.now());
  if (!user) return res.status(400).send(recoveryPage('reset', 'This password-reset link is invalid, expired, or already used.', csrfToken(req)));
  if (!isValidPasswordForUser(password, user)) {
    return res.status(400).send(recoveryPage('reset', passwordRequirementMessage(user), csrfToken(req), token, user.role === 'admin'));
  }
  if (password !== confirmation) return res.status(400).send(recoveryPage('reset', 'Passwords do not match.', csrfToken(req), token, user.role === 'admin'));
  const updated = db.prepare(`UPDATE users SET password_hash = ?, password_reset_used_at = ?,
    password_reset_token_hash = NULL, password_reset_expires_at = NULL,
    session_version = session_version + 1, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND password_reset_token_hash = ? AND password_reset_expires_at > ?
      AND password_reset_used_at IS NULL`).run(await hashPassword(password), Date.now(), user.id, tokenHash, Date.now());
  if (!updated.changes) return res.status(400).send(recoveryPage('reset', 'This password-reset link is invalid, expired, or already used.', csrfToken(req)));
  const messaging = app.locals.accountMessaging || defaultAccountMessaging;
  let notificationSent = false;
  try {
    notificationSent = await messaging.sendEmail({ to: user.email, subject: 'Your MYFB Investment password changed', text: 'Your password has been changed. If you did not make this change, contact support immediately.' });
  } catch {
    console.error('Password-change notification delivery failed.');
  }
  const confirmationMessage = notificationSent
    ? 'Your password has been changed and a notification was sent to your registered email.'
    : 'Your password has been changed, but the notification email could not be delivered. Contact support if you did not make this change.';
  return res.send(loginPage(null, confirmationMessage, csrfToken(req)));
});

app.get('/dashboard', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Dashboard', user, pageClass: 'dashboard-page', body: dashboardBody(user) }));
});

app.get('/rooms', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  const room = getOrCreateChatRoom(user.id);
  res.send(renderPage({
    title: 'Your chat room',
    user,
    pageClass: 'dashboard-page',
    body: customerChatBody(user, room, req)
  }));
});

const chatMessageLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many chat messages. Please wait before sending another.'
});

app.post('/rooms', requireAuth, chatMessageLimiter, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const room = getOrCreateChatRoom(user.id);
  if (room.status !== 'open') {
    setFlash(req, 'This room is closed by an administrator. You can still read previous messages.', 'error');
    return res.redirect('/rooms');
  }
  const message = String(req.body.message || '').trim();
  if (!message || message.length > 4000) {
    setFlash(req, 'Messages must contain between 1 and 4,000 characters.', 'error');
    return res.redirect('/rooms');
  }
  db.prepare(`INSERT INTO chat_messages (room_id, sender_id, sender_role, body)
    VALUES (?, ?, 'user', ?)`).run(room.id, user.id, message);
  db.prepare("UPDATE chat_rooms SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(room.id);
  return res.redirect('/rooms');
});

app.get('/report-user', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  return res.send(renderPage({
    title: 'Report a user',
    user,
    pageClass: 'dashboard-page',
    body: reportUserBody(user, req)
  }));
});

const userReportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many reports were submitted. Please wait before trying again.'
});

app.post('/report-user', requireAuth, userReportLimiter, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const username = normalizeUsername(req.body.username);
  const reason = String(req.body.reason || '');
  const details = String(req.body.details || '').trim();
  const formError = (message) => res.status(400).send(renderPage({
    title: 'Report a user',
    user,
    pageClass: 'dashboard-page',
    body: reportUserBody(user, req, message)
  }));

  if (!/^[a-z0-9][a-z0-9._-]{2,29}$/.test(username)) {
    return formError('Enter the username of a registered customer.');
  }
  if (!['harassment', 'impersonation', 'spam', 'other'].includes(reason)) {
    return formError('Choose a valid reason for the report.');
  }
  if (details.length > 2000) {
    return formError('Report details must be 2,000 characters or fewer.');
  }

  const reportedUser = db.prepare(`SELECT id, username, role FROM users
    WHERE lower(username) = ?`).get(username);
  if (!reportedUser || reportedUser.role !== 'user' || reportedUser.id === user.id) {
    return formError('That registered customer could not be reported. Check the username and make sure it is not your own.');
  }

  db.prepare(`INSERT INTO user_reports
    (reporter_user_id, reported_user_id, reported_username, reason, details)
    VALUES (?, ?, ?, ?, ?)`).run(user.id, reportedUser.id, reportedUser.username, reason, details);
  setFlash(req, 'Your private report has been sent to the administrator for review.', 'success');
  return res.redirect('/report-user');
});

app.get('/healthz', (req, res, next) => {
  try {
    db.prepare('SELECT 1').get();
    return res.json({ status: 'ok' });
  } catch (error) {
    return next(error);
  }
});

app.use(['/wallet', '/investments', '/transactions'], requireAuth, (req, res) => res.status(410).send(renderPage({
  title: 'Unavailable',
  user: getCurrentUser(req),
  pageClass: 'dashboard-page',
  body: '<main class="container dashboard-shell"><h1>This service is unavailable</h1><p>MYFB currently provides profiles and private support chat only. Deposits, withdrawals, wallet activity, and investment transactions are disabled.</p><a href="/dashboard" class="btn btn-primary">Return to dashboard</a></main>'
})));

app.get('/wallet', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Wallet', user, pageClass: 'dashboard-page', body: walletBody(user) }));
});

app.get('/investments', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({
    title: 'Investment activity',
    user,
    pageClass: 'dashboard-page',
    body: investmentActivityBody(user)
  }));
});

app.get('/wallet/deposit', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Deposit money', user, pageClass: 'dashboard-page', body: depositBody(user, '', req.session.depositConfirmation || null, csrfToken(req)) }));
});

const depositRequestLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many deposit preparation attempts. Please wait before trying again.'
});

app.post('/wallet/deposit/prepare', requireAuth, requireFinancialEligibility, depositRequestLimiter, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  if (!user.is_verified) {
    return res.status(403).send(renderPage({
      title: 'Deposit unavailable',
      user,
      pageClass: 'dashboard-page',
      body: '<main class="container dashboard-shell"><h1>Email verification required</h1><p>Verify your account before attempting payment.</p></main>'
    }));
  }
  const amountCents = parseRandToCents(req.body.quickAmount || req.body.amount);
  const validation = wallet.validateDeposit(user.id, amountCents);
  if (!validation.valid) {
    return res.status(400).send(renderPage({
      title: 'Deposit money',
      user,
      pageClass: 'dashboard-page',
      body: depositBody(user, validation.reason, null, csrfToken(req))
    }));
  }
  req.session.depositConfirmation = { amountCents, key: crypto.randomBytes(24).toString('hex') };
  return res.send(renderPage({
    title: 'Confirm deposit request',
    user,
    pageClass: 'dashboard-page',
    body: depositBody(user, '', req.session.depositConfirmation, csrfToken(req))
  }));
});

app.post('/wallet/deposit/confirm', requireAuth, requireFinancialEligibility, depositRequestLimiter, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const confirmation = req.session.depositConfirmation;
  const amountCents = Number(req.body.amountCents);
  if (!confirmation || confirmation.key !== req.body.confirmationKey || confirmation.amountCents !== amountCents || req.body.acknowledge !== 'yes') {
    delete req.session.depositConfirmation;
    return res.status(400).send(renderPage({
      title: 'Deposit confirmation expired',
      user,
      pageClass: 'dashboard-page',
      body: depositBody(user, 'Confirmation expired or did not match. Review the deposit again.', null, csrfToken(req))
    }));
  }
  delete req.session.depositConfirmation;
  const validation = wallet.validateDeposit(user.id, amountCents);
  if (!validation.valid) {
    return res.status(400).send(renderPage({
      title: 'Deposit money',
      user,
      pageClass: 'dashboard-page',
      body: depositBody(user, validation.reason, null, csrfToken(req))
    }));
  }
  return res.status(503).send(renderPage({
    title: 'Payments unavailable',
    user,
    pageClass: 'dashboard-page',
    body: depositBody(user, 'Payment processing is disabled in test mode. No payment was started and no wallet balance was changed.', null, csrfToken(req))
  }));
});

app.get('/wallet/withdraw', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Withdraw money', user, pageClass: 'dashboard-page', body: withdrawalBody(user) }));
});

app.get('/wallet/limits', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Deposit limits', user, pageClass: 'dashboard-page', body: walletLimitsBody(user, req) }));
});

app.post('/wallet/limits', requireAuth, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const singleRaw = String(req.body.single ?? '').trim();
  const single = parseOptionalRandToCents(singleRaw);
  if (singleRaw && single === null) {
    setFlash(req, 'Enter a valid personal single-deposit cap, or leave it blank for no additional personal cap.', 'error');
    return res.redirect('/wallet/limits');
  }
  const daily = parseRandToCents(req.body.daily);
  const monthly = parseRandToCents(req.body.monthly);
  try {
    const result = wallet.saveUserLimits(user.id, { single, daily, monthly });
    const message = result.scheduled
      ? `Your requested limit increase is scheduled after a 7-day cooling-off period ending ${new Date(result.effectiveAt).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' })}.`
      : 'Your lower personal deposit limits were saved immediately.';
    setFlash(req, message, 'success');
  } catch (error) {
    setFlash(req, error.message, 'error');
  }
  res.redirect('/wallet/limits');
});

app.post('/wallet/pause', requireAuth, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const durationDays = Number(req.body.durationDays);
  try {
    const until = wallet.pauseDeposits(user.id, durationDays);
    setFlash(req, `New deposits are paused until ${new Date(until).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' })}.`, 'success');
  } catch (error) {
    setFlash(req, error.message, 'error');
  }
  res.redirect('/wallet/limits');
});

app.get('/account', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Account', user, pageClass: 'dashboard-page', body: accountBody(user, req) }));
});

app.post('/account', requireAuth, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const fullName = String(req.body.fullName || '').trim();
  const marketingConsent = req.body.marketingConsent === 'on';
  const marketingEmail = marketingConsent ? normalizeEmail(req.body.marketingEmail) : null;

  if (!fullName || fullName.length > 120 || (marketingConsent && !isValidEmail(marketingEmail))) {
    setFlash(req, 'Enter a display name and, if opting into advertising, a valid email address.', 'error');
    return res.redirect('/account');
  }

  db.prepare(`
    UPDATE users
    SET full_name = ?, marketing_email = ?, marketing_consent = ?,
      marketing_consent_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(fullName, marketingEmail, marketingConsent ? 1 : 0, marketingConsent ? 1 : 0, user.id);

  setFlash(req, 'Your account details were updated successfully.', 'success');
  res.redirect('/account');
});

const passwordChangeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many password change attempts. Please wait before trying again.'
});

app.post('/account/password', requireAuth, passwordChangeLimiter, requireCsrf, async (req, res, next) => {
  const user = getCurrentUser(req);
  const currentPassword = String(req.body.currentPassword || '');
  const password = String(req.body.password || '');
  const confirmation = String(req.body.confirmPassword || '');
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    setFlash(req, 'The current password is incorrect.', 'error');
    return res.redirect('/account');
  }
  if (!isValidPasswordForUser(password, user)) {
    setFlash(req, passwordRequirementMessage(user), 'error');
    return res.redirect('/account');
  }
  if (password !== confirmation) {
    setFlash(req, 'The new passwords do not match.', 'error');
    return res.redirect('/account');
  }
  db.prepare(`UPDATE users SET password_hash = ?, session_version = session_version + 1,
    updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(await hashPassword(password), user.id);
  const sessionVersion = db.prepare('SELECT session_version FROM users WHERE id = ?').get(user.id).session_version;
  return req.session.regenerate((error) => {
    if (error) return next(error);
    req.session.userId = user.id;
    req.session.sessionVersion = sessionVersion;
    setFlash(req, 'Your password has been updated. Other active sessions have been signed out.', 'success');
    return res.redirect('/account');
  });
});

app.get('/transactions', requireAuth, (req, res) => {
  const user = { ...getCurrentUser(req), transactionSearch: req.query.q, transactionStatus: req.query.status };
  res.send(renderPage({ title: 'Transactions', user, pageClass: 'dashboard-page', body: transactionsBody(user) }));
});

app.get('/transactions/:reference/receipt', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  const payment = db.prepare(`
    SELECT * FROM wallet_transactions
    WHERE user_id = ? AND reference = ? AND transaction_type = 'deposit' AND status = 'confirmed'
  `).get(user.id, req.params.reference);
  if (!payment) return res.status(404).send('Confirmed deposit receipt not found.');
  const receipt = `<!doctype html><html lang="en"><meta charset="utf-8"><title>MYFB deposit receipt</title><body><main><h1>MYFB Investment — Deposit receipt</h1><dl><dt>Reference</dt><dd>${escapeHtml(payment.reference)}</dd><dt>Confirmed date and time (Africa/Johannesburg)</dt><dd>${escapeHtml(new Date(payment.updated_at).toLocaleString('en-ZA', { timeZone: 'Africa/Johannesburg' }))}</dd><dt>Type</dt><dd>Confirmed deposit</dd><dt>Amount</dt><dd>${formatRand(payment.amount_cents)}</dd><dt>Currency</dt><dd>${escapeHtml(payment.currency)}</dd><dt>Payment method</dt><dd>${escapeHtml(payment.payment_method)}</dd><dt>Provider reference</dt><dd>${escapeHtml(payment.provider_reference || '—')}</dd></dl></main></body></html>`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="MYFB-${payment.reference}-receipt.html"`);
  return res.send(receipt);
});

app.get('/notifications', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(user.id);
  res.send(renderPage({ title: 'Notifications', user, pageClass: 'dashboard-page', body: notificationsBody(user) }));
});

app.get('/security', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Security Centre', user, pageClass: 'dashboard-page', body: securityBody(user) }));
});

app.post('/security/setup-mfa', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  const secret = authenticator.generateSecret();
  db.prepare('UPDATE users SET two_factor_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(secret, user.id);
  req.session.pendingMfaSecret = secret;
  setFlash(req, 'Multi-factor authentication has been configured. Enter the verification code to confirm.', 'success');
  res.redirect('/security');
});

app.post('/security/confirm-mfa', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  const secret = user.two_factor_secret || req.session.pendingMfaSecret;
  const code = String(req.body.code || '').trim();
  const valid = secret && authenticator.check(code, secret);

  if (!valid) {
    setFlash(req, 'The MFA code is invalid. Please try again.', 'error');
    return res.redirect('/security');
  }

  db.prepare('UPDATE users SET two_factor_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  delete req.session.pendingMfaSecret;
  setFlash(req, 'Multi-factor authentication is now enabled.', 'success');
  res.redirect('/security');
});

app.post('/security/disable-mfa', requireAuth, (req, res) => {
  const user = getCurrentUser(req);
  db.prepare('UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  setFlash(req, 'Multi-factor authentication has been turned off for your account.', 'success');
  res.redirect('/security');
});

app.use('/support', requireAuth, (req, res) => res.redirect('/rooms'));

app.get('/admin', requireAdmin, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({ title: 'Admin Dashboard', user, pageClass: 'dashboard-page', body: adminBody(user) }));
});

app.get('/admin/reports', requireAdmin, (req, res) => {
  const user = getCurrentUser(req);
  return res.send(renderPage({
    title: 'User reports',
    user,
    pageClass: 'dashboard-page',
    body: adminReportsBody(req)
  }));
});

app.post('/admin/reports/:id', requireAdmin, requireCsrf, (req, res) => {
  const admin = getCurrentUser(req);
  const reportId = Number(req.params.id);
  const report = Number.isSafeInteger(reportId) && reportId > 0
    ? db.prepare('SELECT * FROM user_reports WHERE id = ?').get(reportId)
    : null;
  if (!report) return res.status(404).send('User report not found.');

  const status = String(req.body.status || '');
  const accountAction = String(req.body.accountAction || 'none');
  const adminNotes = String(req.body.adminNotes || '').trim();
  if (!['open', 'reviewing', 'resolved', 'dismissed'].includes(status)
      || !['none', 'suspend', 'restore'].includes(accountAction)
      || adminNotes.length > 2000) {
    setFlash(req, 'Choose a valid report status and account action. Administrator notes must be 2,000 characters or fewer.', 'error');
    return res.redirect('/admin/reports');
  }

  const target = report.reported_user_id
    ? db.prepare('SELECT id, role, account_status FROM users WHERE id = ?').get(report.reported_user_id)
    : null;
  if (accountAction !== 'none' && (!target || target.role !== 'user')) {
    setFlash(req, 'This report no longer has an eligible customer account to change.', 'error');
    return res.redirect('/admin/reports');
  }

  const review = db.transaction(() => {
    db.prepare(`UPDATE user_reports SET status = ?, admin_notes = ?, reviewed_by = ?,
      reviewed_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .run(status, adminNotes, admin.id, report.id);

    if (accountAction === 'suspend' && target.account_status === 'active') {
      db.prepare(`UPDATE users SET account_status = 'suspended',
        session_version = session_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(target.id);
      db.prepare(`INSERT INTO moderation_actions
        (report_id, admin_user_id, target_user_id, action, previous_account_status, new_account_status, details)
        VALUES (?, ?, ?, 'suspend', ?, 'suspended', ?)`)
        .run(report.id, admin.id, target.id, target.account_status, adminNotes);
    } else if (accountAction === 'restore' && target.account_status === 'suspended') {
      db.prepare(`UPDATE users SET account_status = 'active',
        session_version = session_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(target.id);
      db.prepare(`INSERT INTO moderation_actions
        (report_id, admin_user_id, target_user_id, action, previous_account_status, new_account_status, details)
        VALUES (?, ?, ?, 'restore', 'suspended', 'active', ?)`)
        .run(report.id, admin.id, target.id, adminNotes);
    }
  });
  review();
  setFlash(req, 'The report review was saved.', 'success');
  return res.redirect('/admin/reports');
});

app.use(['/admin/payments', '/admin/investments', '/admin/investment-products'], requireAdmin, (req, res) => res.status(410).send(renderPage({
  title: 'Unavailable',
  user: getCurrentUser(req),
  pageClass: 'dashboard-page',
  body: '<main class="container dashboard-shell"><h1>Financial administration is disabled</h1><p>This installation supports profiles and private chat only.</p><a href="/admin" class="btn btn-primary">Return to admin</a></main>'
})));

app.get('/admin/rooms', requireAdmin, (req, res) => {
  const user = getCurrentUser(req);
  return res.send(renderPage({
    title: 'Chat rooms',
    user,
    pageClass: 'dashboard-page',
    body: adminChatRoomsBody()
  }));
});

app.get('/admin/rooms/:id', requireAdmin, (req, res) => {
  const roomId = Number(req.params.id);
  const room = Number.isSafeInteger(roomId) && roomId > 0
    ? db.prepare('SELECT * FROM chat_rooms WHERE id = ?').get(roomId)
    : null;
  const customer = room ? db.prepare("SELECT * FROM users WHERE id = ? AND role != 'admin'").get(room.user_id) : null;
  if (!room || !customer) return res.status(404).send('Chat room not found.');
  return res.send(renderPage({
    title: 'Customer chat',
    user: getCurrentUser(req),
    pageClass: 'dashboard-page',
    body: adminChatRoomBody(room, customer, req)
  }));
});

app.post('/admin/rooms/:id/status', requireAdmin, requireCsrf, (req, res) => {
  const roomId = Number(req.params.id);
  const room = Number.isSafeInteger(roomId) && roomId > 0
    ? db.prepare(`SELECT r.id FROM chat_rooms r
        JOIN users u ON u.id = r.user_id WHERE r.id = ? AND u.role = 'user'`).get(roomId)
    : null;
  const status = String(req.body.status || '');
  if (!room) return res.status(404).send('Chat room not found.');
  if (!['open', 'closed'].includes(status)) {
    setFlash(req, 'Choose a valid room status.', 'error');
    return res.redirect(`/admin/rooms/${roomId}`);
  }
  db.prepare('UPDATE chat_rooms SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
    .run(status, roomId);
  setFlash(req, `The room was ${status === 'closed' ? 'closed' : 'reopened'}.`, 'success');
  return res.redirect(`/admin/rooms/${roomId}`);
});

app.post('/admin/rooms/:id', requireAdmin, chatMessageLimiter, requireCsrf, (req, res) => {
  const roomId = Number(req.params.id);
  const room = Number.isSafeInteger(roomId) && roomId > 0
    ? db.prepare('SELECT * FROM chat_rooms WHERE id = ?').get(roomId)
    : null;
  const customer = room ? db.prepare("SELECT id FROM users WHERE id = ? AND role != 'admin'").get(room.user_id) : null;
  if (!room || !customer) return res.status(404).send('Chat room not found.');
  if (room.status !== 'open') {
    setFlash(req, 'Reopen this room before sending a reply.', 'error');
    return res.redirect(`/admin/rooms/${room.id}`);
  }
  const message = String(req.body.message || '').trim();
  if (!message || message.length > 4000) {
    setFlash(req, 'Messages must contain between 1 and 4,000 characters.', 'error');
    return res.redirect(`/admin/rooms/${room.id}`);
  }
  db.prepare(`INSERT INTO chat_messages (room_id, sender_id, sender_role, body)
    VALUES (?, ?, 'admin', ?)`).run(room.id, req.session.userId, message);
  db.prepare("UPDATE chat_rooms SET updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(room.id);
  return res.redirect(`/admin/rooms/${room.id}`);
});

app.get('/admin/settings', requireAdmin, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({
    title: 'Website settings',
    user,
    pageClass: 'dashboard-page',
    body: adminSiteSettingsBody(req)
  }));
});

app.post('/admin/settings', requireAdmin, requireCsrf, (req, res) => {
  const admin = getCurrentUser(req);
  const announcement = String(req.body.announcement || '').trim().slice(0, 240);
  const whatsappRaw = String(req.body.whatsappNumber || '').trim();
  const whatsappNumber = whatsappRaw.replace(/\D/g, '');
  const communityRules = String(req.body.communityRules || '').trim();
  if (announcement.length < 12 || communityRules.length < 20 || communityRules.length > 4000
      || (whatsappRaw && !/^\+?[\d\s()-]{10,20}$/.test(whatsappRaw))
      || (whatsappNumber && (whatsappNumber.length < 10 || whatsappNumber.length > 15))) {
    setFlash(req, 'Enter an announcement of at least 12 characters, community rules of 20–4,000 characters, and a valid international WhatsApp number, or leave the number blank.', 'error');
    return res.redirect('/admin/settings');
  }
  const settings = { announcement, whatsapp_number: whatsappNumber, community_rules: communityRules };
  const update = db.prepare(`INSERT INTO site_settings (setting_key, setting_value, updated_by, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value,
      updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`);
  const audit = db.prepare('INSERT INTO site_settings_audit (admin_user_id, setting_key, previous_value, new_value) VALUES (?, ?, ?, ?)');
  const saveSettings = db.transaction(() => {
    for (const [key, value] of Object.entries(settings)) {
      const previous = getSiteSetting(key);
      update.run(key, value, admin.id);
      if (previous !== value) audit.run(admin.id, key, previous, value);
    }
  });
  saveSettings();
  setFlash(req, 'Website announcement, community rules, and contact settings were saved.', 'success');
  return res.redirect('/admin/settings');
});

app.post('/admin/settings/email-test', requireAdmin, (req, res) => {
  return res.status(410).send('Email delivery is disabled. Email is only used for opted-in advertising.');
});

app.use('/admin/support', requireAdmin, (req, res) => res.redirect('/admin/rooms'));

app.get('/admin/support', requireAdmin, (req, res) => {
  const admin = getCurrentUser(req);
  return res.send(renderPage({
    title: 'Complaints and support',
    user: admin,
    pageClass: 'dashboard-page',
    body: adminSupportBody(req)
  }));
});

app.get('/admin/investment-products', requireAdmin, (req, res) => {
  const user = getCurrentUser(req);
  return res.send(renderPage({
    title: 'Investment Products',
    user,
    pageClass: 'dashboard-page',
    body: adminInvestmentProductsBody(req)
  }));
});

function saveInvestmentProduct(req, res, productId = null) {
  const admin = getCurrentUser(req);
  const values = {};
  for (const field of INVESTMENT_PRODUCT_TEXT_FIELDS) {
    values[field] = String(req.body[field] || '').trim();
    const maxLength = field === 'name' ? 120 : 5000;
    if (values[field].length > maxLength) {
      setFlash(req, `The ${field.replaceAll('_', ' ')} field is too long.`, 'error');
      return res.redirect('/admin/investment-products');
    }
  }
  if (!values.name) {
    setFlash(req, 'Enter a product name before saving.', 'error');
    return res.redirect('/admin/investment-products');
  }
  let minimumAmountCents = null;
  const minimumRaw = String(req.body.minimum_amount || '').trim();
  try {
    minimumAmountCents = minimumRaw ? parseRandToCents(minimumRaw) : null;
    if (minimumAmountCents != null && minimumAmountCents < 0) throw new Error('Invalid minimum');
  } catch {
    setFlash(req, 'Enter a valid non-negative minimum investment amount in rand, or leave it blank if not specified.', 'error');
    return res.redirect('/admin/investment-products');
  }

  const flags = {
    provider_verified: req.body.provider_verified === '1' ? 1 : 0,
    legal_reviewed: req.body.legal_reviewed === '1' ? 1 : 0,
    authorization_verified: req.body.authorization_verified === '1' ? 1 : 0,
    payment_operations_verified: req.body.payment_operations_verified === '1' ? 1 : 0,
    transaction_operations_verified: req.body.transaction_operations_verified === '1' ? 1 : 0
  };
  const status = productId ? String(req.body.status || '') : 'Draft';
  if (!INVESTMENT_PRODUCT_STATUSES.includes(status)) {
    setFlash(req, 'Choose a valid product review status.', 'error');
    return res.redirect('/admin/investment-products');
  }
  const approvedStatuses = ['Approved for publication', 'Published'];
  const evidenceFields = [
    'provider_verification_reference',
    'legal_review_reference',
    'authorization_reference',
    'documented_approval_reference',
    'payment_operations_reference',
    'transaction_operations_reference'
  ];
  const requiredForApproval = [
    'description', 'potential_outcomes', 'provider_name', 'provider_information', 'fees', 'time_horizon',
    'eligibility', 'risk_level', 'risk_disclosures', 'liquidity_conditions', 'terms',
    ...evidenceFields
  ];
  if (approvedStatuses.includes(status)) {
    const missing = requiredForApproval.filter((field) => !values[field]);
    const unchecked = Object.keys(flags).filter((field) => !flags[field]);
    if (missing.length || unchecked.length) {
      setFlash(req, 'Approval requires complete product terms, fees, eligibility, risk and liquidity information, documented verification evidence, and every provider, legal, authorization and operations check.', 'error');
      return res.redirect('/admin/investment-products');
    }
  }

  const fields = { ...values, minimum_amount_cents: minimumAmountCents, ...flags };
  const dbColumns = [...INVESTMENT_PRODUCT_TEXT_FIELDS, 'minimum_amount_cents', ...Object.keys(flags)];
  const contentHash = crypto.createHash('sha256')
    .update(JSON.stringify(dbColumns.map((field) => fields[field])))
    .digest('hex');
  try {
    const save = db.transaction(() => {
      const previous = productId
        ? db.prepare('SELECT * FROM investment_products WHERE id = ?').get(productId)
        : null;
      if (productId && !previous) throw new Error('not_found');
      if (status === 'Published' && previous && previous.status !== 'Published'
          && previous.status !== 'Approved for publication') {
        throw new Error('approval_required');
      }
      if (status === 'Published' && previous
          && previous.approved_content_hash !== contentHash) {
        throw new Error('approval_content_changed');
      }
      const changedContent = previous && dbColumns.some((field) => previous[field] !== fields[field]);
      if (previous && previous.status === 'Published' && status === 'Published' && changedContent) {
        throw new Error('reapproval_required');
      }
      const valuesForSave = dbColumns.map((field) => fields[field]);
      if (!previous) {
        const placeholders = dbColumns.map(() => '?').join(', ');
        const insert = db.prepare(`INSERT INTO investment_products
          (${dbColumns.join(', ')}, status, created_by, updated_by, updated_at)
          VALUES (${placeholders}, 'Draft', ?, ?, CURRENT_TIMESTAMP)`);
        const result = insert.run(...valuesForSave, admin.id, admin.id);
        const slugBase = values.name.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
          .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50) || 'product';
        const slug = `${slugBase}-${result.lastInsertRowid}`;
        db.prepare('UPDATE investment_products SET slug = ? WHERE id = ?').run(slug, result.lastInsertRowid);
        db.prepare(`INSERT INTO investment_product_audit
          (product_id, admin_user_id, action, previous_status, new_status, details)
          VALUES (?, ?, 'created', NULL, 'Draft', ?)`)
          .run(result.lastInsertRowid, admin.id, JSON.stringify({ createdFields: fields }));
        return;
      }
      const assignments = dbColumns.map((field) => `${field} = ?`).join(', ');
      const approvedHash = status === 'Approved for publication' ? contentHash : previous.approved_content_hash;
      db.prepare(`UPDATE investment_products SET ${assignments}, status = ?, approved_content_hash = ?, updated_by = ?,
        updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
        .run(...valuesForSave, status, approvedHash, admin.id, productId);
      const changedFields = Object.fromEntries(dbColumns
        .filter((field) => previous[field] !== fields[field])
        .map((field) => [field, { before: previous[field], after: fields[field] }]));
      db.prepare(`INSERT INTO investment_product_audit
        (product_id, admin_user_id, action, previous_status, new_status, details)
        VALUES (?, ?, 'updated', ?, ?, ?)`)
        .run(productId, admin.id, previous.status, status, JSON.stringify({
          changedFields
        }));
    });
    save();
  } catch (error) {
    const expectedErrors = {
      not_found: 'That proposed product was not found.',
      approval_required: 'A product must first reach Approved for publication before it can be published.',
      approval_content_changed: 'The product changed after approval. Save it as Approved for publication again so that this exact version is reviewed before publication.',
      reapproval_required: 'Changes to a published product require it to move through review and approval again before republication.'
    };
    const message = expectedErrors[error.message]
      || 'The product could not be saved. Review the product information and try again.';
    if (!expectedErrors[error.message]) console.error('Investment product save failed.', error.code || error.message);
    setFlash(req, message, 'error');
    return res.redirect('/admin/investment-products');
  }
  setFlash(req, 'Product details and the administrator action were saved to the audit log. This does not create an investment order service.', 'success');
  return res.redirect('/admin/investment-products');
}

app.post('/admin/investment-products', requireAdmin, requireCsrf, (req, res) => saveInvestmentProduct(req, res));
app.post('/admin/investment-products/:id', requireAdmin, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) {
    setFlash(req, 'Choose a valid proposed product.', 'error');
    return res.redirect('/admin/investment-products');
  }
  return saveInvestmentProduct(req, res, id);
});

app.post('/admin/support/:id', requireAdmin, requireCsrf, (req, res) => {
  const admin = getCurrentUser(req);
  const id = Number(req.params.id);
  const response = String(req.body.response || '').trim().slice(0, 4000);
  const status = String(req.body.status || '');
  if (!Number.isSafeInteger(id) || id < 1 || !['open', 'in_progress', 'resolved'].includes(status)) {
    setFlash(req, 'Choose a valid support request and status.', 'error');
    return res.redirect('/admin/support');
  }
  const request = db.prepare('SELECT s.id, s.user_id, s.name, s.status FROM support_messages s WHERE s.id = ?').get(id);
  if (!request) {
    setFlash(req, 'That support request could not be found.', 'error');
    return res.redirect('/admin/support');
  }
  db.prepare(`UPDATE support_messages SET admin_response = ?, status = ?, responded_by = ?,
    updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(response || null, status, admin.id, id);
  db.prepare('INSERT INTO wallet_admin_audit (admin_user_id, action, details) VALUES (?, ?, ?)')
    .run(admin.id, 'support_request_updated', `Updated request ${id} status to ${status}.`);
  setFlash(req, 'Support request updated. Replies are available in the private chat room.', 'success');
  return res.redirect('/admin/support');
});

app.get('/admin/payments', requireAdmin, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({
    title: 'Payment management',
    user,
    pageClass: 'dashboard-page',
    body: adminPaymentsBody(user, req.query.q, req)
  }));
});

app.get('/admin/investments', requireAdmin, (req, res) => {
  const user = getCurrentUser(req);
  res.send(renderPage({
    title: 'Investment service status',
    user,
    pageClass: 'dashboard-page',
    body: adminInvestmentBody()
  }));
});

app.post('/admin/payments/limits', requireAdmin, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const singleRaw = String(req.body.single ?? '').trim();
  const singleDepositCents = parseOptionalRandToCents(singleRaw);
  if (singleRaw && singleDepositCents === null) {
    setFlash(req, 'Enter a valid maximum amount, or leave it blank for no single-deposit cap.', 'error');
    return res.redirect('/admin/payments');
  }
  try {
    wallet.setGlobalLimits({
      minimumDepositCents: parseRandToCents(req.body.minimum),
      singleDepositCents,
      dailyDepositCents: parseRandToCents(req.body.daily),
      monthlyDepositCents: parseRandToCents(req.body.monthly)
    }, user.id);
    setFlash(req, 'Global configurable deposit limits were updated and recorded in the audit log.', 'success');
  } catch (error) {
    setFlash(req, error.message, 'error');
  }
  res.redirect('/admin/payments');
});

app.post('/admin/payments/options', requireAdmin, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const quickText = String(req.body.quickAmounts || '').trim();
  const quickAmountsCents = quickText
    ? quickText.split(',').map((value) => parseRandToCents(value.trim()))
    : [];
  if (quickAmountsCents.some((amount) => amount === null)) {
    setFlash(req, 'Quick amounts must be valid comma-separated ZAR amounts with no more than two decimal places.', 'error');
    return res.redirect('/admin/payments');
  }
  const selected = new Set(Array.isArray(req.body.paymentMethods)
    ? req.body.paymentMethods.map(String)
    : req.body.paymentMethods
      ? [String(req.body.paymentMethods)]
      : []);
  try {
    wallet.saveDepositSettings({
      quickAmountsCents,
      requestedPaymentMethods: Object.fromEntries(PAYMENT_METHODS.map((method) => [method, selected.has(method)]))
    }, user.id);
    setFlash(req, 'Deposit-page settings saved. No payment methods were activated because a provider integration is not configured.', 'success');
  } catch (error) {
    setFlash(req, error.message, 'error');
  }
  res.redirect('/admin/payments');
});

app.post('/admin/payments/:reference/review', requireAdmin, requireCsrf, (req, res) => {
  const user = getCurrentUser(req);
  const action = req.body.action;
  if (!['payment_review', 'refund_request'].includes(action)) {
    setFlash(req, 'Unsupported administrative action.', 'error');
    return res.redirect('/admin/payments');
  }
  try {
    wallet.queueReview({
      adminUserId: user.id,
      reference: req.params.reference,
      reason: req.body.reason,
      action
    });
    setFlash(req, 'The review request was recorded in the audit log. No transaction status, balance or payment was changed.', 'success');
  } catch (error) {
    setFlash(req, error.message, 'error');
  }
  return res.redirect('/admin/payments');
});

app.get('/admin/payments/export.csv', requireAdmin, (req, res) => {
  const admin = getCurrentUser(req);
  const transactions = db.prepare(`
    SELECT t.reference, u.email, t.transaction_type, t.amount_cents, t.currency,
           t.payment_method, t.status, t.provider_reference, t.reconciliation_status, t.created_at
    FROM wallet_transactions t JOIN users u ON u.id = t.user_id
    ORDER BY t.created_at DESC LIMIT 10000
  `).all();
  db.prepare('INSERT INTO wallet_admin_audit (admin_user_id, action, details) VALUES (?, ?, ?)')
    .run(admin.id, 'transactions_exported', `Exported ${transactions.length} wallet transaction rows.`);
  const csvValue = (value) => {
    const safe = String(value ?? '').replace(/^[=+\-@]/, "'$&");
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const lines = [
    ['Reference', 'Customer email', 'Type', 'Amount cents', 'Currency', 'Payment method', 'Status', 'Provider reference', 'Reconciliation status', 'Created at'].map(csvValue).join(','),
    ...transactions.map((item) => [
      item.reference, item.email, item.transaction_type, item.amount_cents, item.currency,
      item.payment_method, item.status, item.provider_reference, item.reconciliation_status, item.created_at
    ].map(csvValue).join(','))
  ];
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="myfb-wallet-transactions.csv"');
  return res.send(lines.join('\r\n'));
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.use((req, res) => {
  res.status(404).send(renderPage({
    title: 'Page not found',
    user: getCurrentUser(req),
    pageClass: 'error-page',
    body: `<main class="container page-layout"><div class="content-panel"><p class="eyebrow accent">404</p><h1>Page not found</h1><p>The page you requested could not be found.</p><a href="/" class="btn btn-primary">Return home</a></div></main>`
  }));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`MYFB Investment app running at ${baseUrl}`);
  });
}

module.exports = { app, db, baseUrl };
