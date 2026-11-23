const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const testDataDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'myfb-app-test-'));
process.env.MYFB_DATA_DIR = testDataDirectory;
process.env.ADMIN_USERNAME = 'testadmin';
process.env.ADMIN_PASSWORD = 'TestAdminPassword123!';
process.env.ADMIN_EMAIL = 'test-admin@example.test';
process.env.SESSION_SECRET = 'test-session-secret-with-more-than-thirty-two-characters';

const { app, db } = require('../server');
const root = 'http://127.0.0.1';
let server;
const registeredUserIds = [];
let cachedAdminCookie;
let emailDeliveries = 0;
const previousMessaging = app.locals.accountMessaging;

async function getPage(pathname, cookie = '') {
  const response = await fetch(`${root}:${server.address().port}${pathname}`, {
    headers: cookie ? { Cookie: cookie } : {}
  });
  const html = await response.text();
  const match = html.match(/name="_csrf" value="([^"]+)"/);
  return {
    response,
    html,
    cookie: response.headers.get('set-cookie')?.split(';')[0] || cookie,
    csrf: match ? match[1] : ''
  };
}

async function postForm(pathname, cookie, csrf, values = {}) {
  return fetch(`${root}:${server.address().port}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie },
    redirect: 'manual',
    body: new URLSearchParams({ _csrf: csrf, ...values })
  });
}

async function registerUser(username, email = '', consent = false, password = 'CustomerPassword123!') {
  const form = await getPage('/register');
  const registration = await postForm('/register', form.cookie, form.csrf, {
    firstName: 'Test',
    lastName: 'Customer',
    username,
    email,
    marketingConsent: consent ? 'on' : '',
    password,
    confirmPassword: password,
    termsAccepted: 'on'
  });
  assert.equal(registration.status, 302);
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  assert.ok(user, 'registered user should be persisted');
  registeredUserIds.push(user.id);

  const loginForm = await getPage('/login', form.cookie);
  const login = await postForm('/login', loginForm.cookie, loginForm.csrf, { username, password });
  assert.equal(login.status, 302);
  return { username, password, cookie: login.headers.get('set-cookie').split(';')[0], email };
}

async function loginAdmin() {
  if (cachedAdminCookie) return cachedAdminCookie;
  const form = await getPage('/login');
  const login = await postForm('/login', form.cookie, form.csrf, {
    username: 'testadmin',
    password: process.env.ADMIN_PASSWORD
  });
  assert.equal(login.status, 302);
  cachedAdminCookie = login.headers.get('set-cookie').split(';')[0];
  return cachedAdminCookie;
}

test.before(async () => {
  app.locals.accountMessaging = {
    emailConfigured: () => true,
    sendEmail: async () => { emailDeliveries += 1; return true; },
    twilioConfigured: () => false,
    sendSmsOtp: async () => false,
    verifySmsOtp: async () => false,
    sendRecoverySms: async () => false
  };
  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
});

test.after(async () => {
  if (server) await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  for (const userId of registeredUserIds) {
    db.prepare('DELETE FROM moderation_actions WHERE target_user_id = ?').run(userId);
    db.prepare('DELETE FROM user_reports WHERE reporter_user_id = ? OR reported_user_id = ?').run(userId, userId);
    db.prepare('DELETE FROM chat_messages WHERE room_id IN (SELECT id FROM chat_rooms WHERE user_id = ?) OR sender_id = ?')
      .run(userId, userId);
    db.prepare('DELETE FROM chat_rooms WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM notifications WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM transactions WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM support_messages WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  }
  if (previousMessaging === undefined) delete app.locals.accountMessaging;
  else app.locals.accountMessaging = previousMessaging;
  db.close();
  fs.rmSync(testDataDirectory, { recursive: true, force: true });
});

test('health endpoint and public branding are available', async () => {
  const health = await fetch(`${root}:${server.address().port}/healthz`);
  assert.deepEqual(await health.json(), { status: 'ok' });
  const home = await getPage('/');
  assert.equal(home.response.status, 200);
  assert.match(home.html, /MYFB/i);
  assert.match(home.html, /Private customer support rooms/i);
  assert.match(home.html, /No deposits or financial transactions/i);
  assert.doesNotMatch(home.html, /transaction records|Transaction Tracking|wallet currency|Portfolio review/i);
  assert.match(home.html, /class="developer-credit-bar"/);
  assert.match(home.html, /Developed by <strong>Sahil Phakathwayo<\/strong>/);
  const registration = await getPage('/register');
  assert.match(registration.html, /data-password-strength-for="register-password"/);
  assert.match(registration.html, /minlength="6"/);
  const rules = await getPage('/community-rules');
  assert.equal(rules.response.status, 200);
  assert.match(rules.html, /Community Rules/);
});

test('email verification and recovery endpoints do not send email', async () => {
  const verification = await fetch(`${root}:${server.address().port}/verify-email/old-token`);
  assert.equal(verification.status, 410);
  const recovery = await fetch(`${root}:${server.address().port}/forgot-password`, { redirect: 'manual' });
  assert.equal(recovery.status, 302);
  assert.equal(recovery.headers.get('location'), '/login');
  const contact = await getPage('/contact');
  assert.doesNotMatch(contact.html, /name="email"/);
  assert.equal(emailDeliveries, 0);
});

test('registration works without email and does not send verification messages', async () => {
  const customer = await registerUser(`customer-${Date.now()}`);
  const row = db.prepare(`SELECT email, marketing_email, marketing_consent, is_verified, account_status
    FROM users WHERE username = ?`).get(customer.username);
  assert.equal(row.marketing_email, null);
  assert.equal(row.marketing_consent, 0);
  assert.equal(row.is_verified, 1);
  assert.equal(row.account_status, 'active');
  assert.match(row.email, /@myfb\.invalid$/);
  assert.equal(emailDeliveries, 0);

  const profile = await getPage('/account', customer.cookie);
  assert.equal(profile.response.status, 200);
  assert.match(profile.html, /Optional email for advertising/);
  assert.match(profile.html, /Username/);
  assert.match(profile.html, /data-password-strength-for="account-new-password"/);
});

test('customer registration accepts six-character passwords and rejects shorter ones', async () => {
  const customer = await registerUser(`minpass-${Date.now()}`, '', false, 'abc123');
  assert.equal(customer.password, 'abc123');

  const form = await getPage('/register');
  const username = `shortpass-${Date.now()}`;
  const rejected = await postForm('/register', form.cookie, form.csrf, {
    firstName: 'Test',
    lastName: 'Customer',
    username,
    password: 'abc12',
    confirmPassword: 'abc12',
    termsAccepted: 'on'
  });
  assert.equal(rejected.status, 400);
  assert.match(await rejected.text(), /at least 6 characters/i);
  assert.equal(db.prepare('SELECT id FROM users WHERE username = ?').get(username), undefined);
});

test('email is optional, requires advertising consent, and cannot be used to sign in', async () => {
  const email = `ads-${Date.now()}@example.test`;
  const customer = await registerUser(`ads-${Date.now()}`, email, true);
  const row = db.prepare('SELECT marketing_email, marketing_consent FROM users WHERE username = ?').get(customer.username);
  assert.equal(row.marketing_email, email);
  assert.equal(row.marketing_consent, 1);
  assert.equal(emailDeliveries, 0);

  const loginForm = await getPage('/login');
  const emailLogin = await postForm('/login', loginForm.cookie, loginForm.csrf, {
    username: email,
    password: customer.password
  });
  assert.equal(emailLogin.status, 302);
  assert.equal(emailLogin.headers.get('location'), '/login');

  const profile = await getPage('/account', customer.cookie);
  const update = await postForm('/account', customer.cookie, profile.csrf, {
    fullName: 'Test Customer',
    marketingEmail: email,
    marketingConsent: ''
  });
  assert.equal(update.status, 302);
  const withdrawn = db.prepare('SELECT marketing_email, marketing_consent FROM users WHERE username = ?').get(customer.username);
  assert.equal(withdrawn.marketing_email, null);
  assert.equal(withdrawn.marketing_consent, 0);
});

test('signed-in users can change passwords without email and old sessions are invalidated', async () => {
  const customer = await registerUser(`password-${Date.now()}`);
  const profile = await getPage('/account', customer.cookie);
  const newPassword = 'NewCustomerPassword456!';
  const change = await postForm('/account/password', customer.cookie, profile.csrf, {
    currentPassword: customer.password,
    password: newPassword,
    confirmPassword: newPassword
  });
  assert.equal(change.status, 302);
  const updatedCookie = change.headers.get('set-cookie').split(';')[0];

  const staleSession = await fetch(`${root}:${server.address().port}/account`, {
    headers: { Cookie: customer.cookie },
    redirect: 'manual'
  });
  assert.equal(staleSession.status, 302);
  assert.equal(staleSession.headers.get('location'), '/login');
  assert.equal((await getPage('/account', updatedCookie)).response.status, 200);

  const loginForm = await getPage('/login');
  const login = await postForm('/login', loginForm.cookie, loginForm.csrf, {
    username: customer.username,
    password: newPassword
  });
  assert.equal(login.status, 302);
  assert.equal(login.headers.get('location'), '/dashboard');
});

test('administrator password changes keep the stronger policy', async () => {
  const adminCookie = await loginAdmin();
  const profile = await getPage('/account', adminCookie);
  assert.match(profile.html, /id="account-new-password"[^>]*minlength="12"/);
  const rejected = await postForm('/account/password', adminCookie, profile.csrf, {
    currentPassword: process.env.ADMIN_PASSWORD,
    password: 'abc123',
    confirmPassword: 'abc123'
  });
  assert.equal(rejected.status, 302);
  const refreshed = await getPage('/account', adminCookie);
  assert.match(refreshed.html, /Administrator passwords must have at least 12 characters/);
});

test('customer chat is private and administrators can reply', async () => {
  const suffix = Date.now();
  const customer = await registerUser(`client-${suffix}`);
  const otherCustomer = await registerUser(`other-${suffix}`);
  const privateMessage = '<script>alert("private")</script>';

  const room = await getPage('/rooms', customer.cookie);
  assert.match(room.html, /class="support-chat-thread" data-chat-thread role="log"/);
  assert.match(room.html, /Your conversation starts here/);
  const send = await postForm('/rooms', customer.cookie, room.csrf, { message: privateMessage });
  assert.equal(send.status, 302);

  const otherRoom = await getPage('/rooms', otherCustomer.cookie);
  assert.equal(otherRoom.html.includes(privateMessage), false);
  assert.doesNotMatch(otherRoom.html, /&lt;script&gt;alert/);

  const adminCookie = await loginAdmin();
  const adminRooms = await getPage('/admin/rooms', adminCookie);
  assert.match(adminRooms.html, new RegExp(customer.username));
  const roomId = db.prepare('SELECT id FROM chat_rooms WHERE user_id = ?').get(registeredUserIds[registeredUserIds.length - 2]).id;
  const deniedAdminPage = await fetch(`${root}:${server.address().port}/admin/rooms/${roomId}`, {
    headers: { Cookie: customer.cookie },
    redirect: 'manual'
  });
  assert.equal(deniedAdminPage.status, 302);
  const adminRoom = await getPage(`/admin/rooms/${roomId}`, adminCookie);
  assert.match(adminRoom.html, /class="support-chat-message/);
  assert.match(adminRoom.html, /&lt;script&gt;/);
  assert.doesNotMatch(adminRoom.html, /<script>alert/);

  const reply = await postForm(`/admin/rooms/${roomId}`, adminCookie, adminRoom.csrf, { message: 'We received your message.' });
  assert.equal(reply.status, 302);
  const refreshedRoom = await getPage('/rooms', customer.cookie);
  assert.match(refreshedRoom.html, /We received your message/);

  const details = await getPage(`/admin/rooms/${roomId}`, adminCookie);
  const close = await postForm(`/admin/rooms/${roomId}/status`, adminCookie, details.csrf, { status: 'closed' });
  assert.equal(close.status, 302);
  assert.equal(db.prepare('SELECT status FROM chat_rooms WHERE id = ?').get(roomId).status, 'closed');

  const closedCustomerRoom = await getPage('/rooms', customer.cookie);
  assert.match(closedCustomerRoom.html, /closed by an administrator/i);
  assert.doesNotMatch(closedCustomerRoom.html, /<form method="POST" action="\/rooms"/);
  const before = db.prepare('SELECT COUNT(*) AS count FROM chat_messages WHERE room_id = ?').get(roomId).count;
  const rejectedMessage = await postForm('/rooms', customer.cookie, room.csrf, { message: 'A message after closure' });
  assert.equal(rejectedMessage.status, 302);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM chat_messages WHERE room_id = ?').get(roomId).count, before);

  const closedAdminRoom = await getPage(`/admin/rooms/${roomId}`, adminCookie);
  const reopen = await postForm(`/admin/rooms/${roomId}/status`, adminCookie, closedAdminRoom.csrf, { status: 'open' });
  assert.equal(reopen.status, 302);
  assert.equal(db.prepare('SELECT status FROM chat_rooms WHERE id = ?').get(roomId).status, 'open');
  assert.match((await getPage('/rooms', customer.cookie)).html, /Send message/);
});

test('users can report accounts and administrators can suspend and restore them', async () => {
  const suffix = Date.now();
  const reporter = await registerUser(`reporter-${suffix}`);
  const reported = await registerUser(`reported-${suffix}`);
  const reportPage = await getPage('/report-user', reporter.cookie);
  const submission = await postForm('/report-user', reporter.cookie, reportPage.csrf, {
    username: reported.username,
    reason: 'harassment',
    details: 'Repeated abusive messages.'
  });
  assert.equal(submission.status, 302);

  const report = db.prepare('SELECT * FROM user_reports WHERE reporter_user_id = ?').get(
    db.prepare('SELECT id FROM users WHERE username = ?').get(reporter.username).id
  );
  assert.equal(report.reported_user_id, db.prepare('SELECT id FROM users WHERE username = ?').get(reported.username).id);
  assert.equal((await getPage('/report-user', reporter.cookie)).html.includes(reported.username), true);
  assert.equal((await getPage('/report-user', reported.cookie)).html.includes(reporter.username), false);

  const adminCookie = await loginAdmin();
  const adminReports = await getPage('/admin/reports', adminCookie);
  assert.match(adminReports.html, new RegExp(reported.username));
  assert.match(adminReports.html, new RegExp(reporter.username));
  const suspend = await postForm(`/admin/reports/${report.id}`, adminCookie, adminReports.csrf, {
    status: 'reviewing',
    accountAction: 'suspend',
    adminNotes: 'Reviewing the reported conduct.'
  });
  assert.equal(suspend.status, 302);
  assert.equal(db.prepare('SELECT account_status FROM users WHERE username = ?').get(reported.username).account_status, 'suspended');
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM moderation_actions WHERE report_id = ?').get(report.id).count, 1);

  const loginForm = await getPage('/login');
  const blockedLogin = await postForm('/login', loginForm.cookie, loginForm.csrf, {
    username: reported.username,
    password: reported.password
  });
  assert.equal(blockedLogin.headers.get('location'), '/login');

  const reviewPage = await getPage('/admin/reports', adminCookie);
  const restore = await postForm(`/admin/reports/${report.id}`, adminCookie, reviewPage.csrf, {
    status: 'resolved',
    accountAction: 'restore',
    adminNotes: 'Reviewed and restored.'
  });
  assert.equal(restore.status, 302);
  assert.equal(db.prepare('SELECT account_status FROM users WHERE username = ?').get(reported.username).account_status, 'active');
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM moderation_actions WHERE report_id = ?').get(report.id).count, 2);
});

test('administrators can update public community rules and retain their contact email', async () => {
  const adminCookie = await loginAdmin();
  const dashboard = await getPage('/admin', adminCookie);
  assert.match(dashboard.html, /test-admin@example\.test/);
  const settings = await getPage('/admin/settings', adminCookie);
  const updatedRules = "Be respectful and protect every customer's private information.";
  const save = await postForm('/admin/settings', adminCookie, settings.csrf, {
    announcement: 'Profiles and private support chat are available.',
    whatsappNumber: '',
    communityRules: updatedRules
  });
  assert.equal(save.status, 302);
  const rules = await getPage('/community-rules');
  assert.match(rules.html, /Be respectful and protect every customer&#39;s private information\./);
});

test('wallet, deposit, withdrawal, investment, and transaction routes are disabled', async () => {
  const customer = await registerUser(`no-money-${Date.now()}`);
  for (const pathname of ['/wallet', '/wallet/deposit', '/wallet/withdraw', '/investments', '/transactions']) {
    const response = await fetch(`${root}:${server.address().port}${pathname}`, { headers: { Cookie: customer.cookie } });
    assert.equal(response.status, 410, pathname);
  }
  const deposit = await postForm('/wallet/deposit/prepare', customer.cookie, 'unused', { amount: '100' });
  assert.equal(deposit.status, 410);
});
