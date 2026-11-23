const nodemailer = require('nodemailer');

function emailTransport() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASSWORD) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASSWORD }
  });
}

function emailConfigured() {
  return Boolean(emailTransport() && process.env.EMAIL_FROM);
}

async function sendEmail({ to, subject, text }) {
  const transport = emailTransport();
  if (!transport || !process.env.EMAIL_FROM) return false;
  await transport.sendMail({ from: process.env.EMAIL_FROM, to, subject, text });
  return true;
}

function twilioConfigured({ messaging = false } = {}) {
  return Boolean(
    process.env.TWILIO_ACCOUNT_SID
    && process.env.TWILIO_AUTH_TOKEN
    && (messaging ? process.env.TWILIO_MESSAGING_SERVICE_SID : process.env.TWILIO_VERIFY_SERVICE_SID)
  );
}

async function twilioRequest(path, body) {
  const credentials = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
  const response = await fetch(`https://verify.twilio.com/v2${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams(body),
    signal: AbortSignal.timeout(10000)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(`SMS provider rejected the request (${response.status}).`);
  return result;
}

async function sendSmsOtp(phone) {
  if (!twilioConfigured()) return false;
  await twilioRequest(`/Services/${encodeURIComponent(process.env.TWILIO_VERIFY_SERVICE_SID)}/Verifications`, {
    To: phone,
    Channel: 'sms'
  });
  return true;
}

async function verifySmsOtp(phone, code) {
  if (!twilioConfigured()) return false;
  const result = await twilioRequest(`/Services/${encodeURIComponent(process.env.TWILIO_VERIFY_SERVICE_SID)}/VerificationCheck`, {
    To: phone,
    Code: code
  });
  return result.status === 'approved';
}

async function sendRecoverySms(phone, text) {
  if (!twilioConfigured({ messaging: true })) return false;
  const credentials = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(process.env.TWILIO_ACCOUNT_SID)}/Messages.json`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({ To: phone, MessagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID, Body: text }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`SMS provider rejected the message (${response.status}).`);
  return true;
}

module.exports = { emailConfigured, sendEmail, twilioConfigured, sendSmsOtp, verifySmsOtp, sendRecoverySms };
