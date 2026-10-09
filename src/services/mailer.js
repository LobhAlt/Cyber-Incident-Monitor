'use strict';

const config = require('../config');

/**
 * Outgoing mail. Uses SMTP when SMTP_HOST is set; otherwise prints the
 * message to the server console so a local install can still verify accounts
 * without a mail server. In the test environment messages are also kept in
 * `outbox` so the smoke suite can follow verification links.
 */

let transport = null;
const outbox = [];

function isConfigured() {
  return Boolean(config.mail.host);
}

function getTransport() {
  if (transport) return transport;
  // Required lazily so the app still boots if the package is missing and mail is unused.
  // eslint-disable-next-line global-require
  const nodemailer = require('nodemailer');
  transport = nodemailer.createTransport({
    host: config.mail.host,
    port: config.mail.port,
    secure: config.mail.secure,
    auth: config.mail.user ? { user: config.mail.user, pass: config.mail.pass } : undefined,
  });
  return transport;
}

async function send({ to, subject, text, html }) {
  if (config.env === 'test') {
    outbox.push({ to, subject, text });
    if (outbox.length > 20) outbox.shift();
    return { delivery: 'test' };
  }

  if (!isConfigured()) {
    /* eslint-disable no-console */
    console.log('');
    console.log('  ┌─ Email (SMTP not configured, printed here instead) ───────────');
    console.log(`  │ To:      ${to}`);
    console.log(`  │ Subject: ${subject}`);
    text.split('\n').forEach((line) => console.log(`  │ ${line}`));
    console.log('  └───────────────────────────────────────────────────────────────');
    console.log('');
    /* eslint-enable no-console */
    return { delivery: 'console' };
  }

  await getTransport().sendMail({
    from: config.mail.from || config.mail.user,
    to,
    subject,
    text,
    html,
  });
  return { delivery: 'email' };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Shared black-and-red layout for every CIMI email. */
function layout({ heading, intro, buttonText, link, notes = [] }) {
  const button = link
    ? `<p style="margin:0 0 20px"><a href="${escapeHtml(link)}" style="display:inline-block;background:#e5192d;color:#fff;text-decoration:none;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase;padding:12px 20px">${escapeHtml(buttonText)}</a></p>
      <p style="margin:0 0 8px;font-size:12px;line-height:1.6;color:#787878">If the button does not work, paste this into your browser:</p>
      <p style="margin:0 0 20px;font-size:12px;word-break:break-all;color:#ff4552">${escapeHtml(link)}</p>`
    : '';
  const extra = notes.map((n) => `<p style="margin:0 0 8px;font-size:12px;line-height:1.6;color:#787878">${escapeHtml(n)}</p>`).join('');
  return `<!doctype html><html><body style="margin:0;background:#000;padding:32px 16px;font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;color:#ededed">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
  <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;background:#080808;border:1px solid #222;border-top:3px solid #e5192d">
    <tr><td style="padding:28px">
      <p style="margin:0 0 4px;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#787878">CIMI</p>
      <h1 style="margin:0 0 16px;font-size:20px;color:#fff">${escapeHtml(heading)}</h1>
      <p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#cdcdcd">${escapeHtml(intro)}</p>
      ${button}${extra}
    </td></tr>
  </table></td></tr></table></body></html>`;
}

function verificationEmail({ username, link, hours }) {
  const notes = [
    `The link works once and expires in ${hours} hours.`,
    'If you did not create this account, ignore this email and nothing will happen.',
  ];
  const text = [
    `Hi ${username},`, '',
    'Confirm the email address for your CIMI account by opening this link:', '',
    link, '', ...notes,
  ].join('\n');
  const html = layout({
    heading: 'Confirm your email',
    intro: `Hi ${username}, confirm this address to finish setting up your account.`,
    buttonText: 'Confirm email',
    link,
    notes,
  });
  return { subject: 'Confirm your CIMI account', text, html };
}

function passwordResetEmail({ username, link, minutes }) {
  const notes = [
    `The link works once and expires in ${minutes} minutes. Using it signs out every device on the account.`,
    'If you did not ask for this, ignore this email. Your password stays the same.',
  ];
  const text = [
    `Hi ${username},`, '',
    'Someone asked to reset the password for your CIMI account. To choose a new one, open this link:', '',
    link, '', ...notes,
  ].join('\n');
  const html = layout({
    heading: 'Reset your password',
    intro: `Hi ${username}, someone asked to reset the password for your CIMI account.`,
    buttonText: 'Choose a new password',
    link,
    notes,
  });
  return { subject: 'Reset your CIMI password', text, html };
}

function watchlistAlertEmail({ username, indicator, from, to, score, link }) {
  const intro = `${indicator} on your watchlist changed from ${from} to ${to} (score ${score}/100).`;
  const notes = ['You get this because alerts are on for this indicator. Turn them off on the Watchlist page.'];
  const text = [`Hi ${username},`, '', intro, '', `Open CIMI: ${link}`, '', ...notes].join('\n');
  const html = layout({ heading: `Watchlist alert: ${to}`, intro, buttonText: 'Open watchlist', link, notes });
  return { subject: `CIMI alert: ${indicator} is now ${to}`, text, html };
}

module.exports = { send, verificationEmail, passwordResetEmail, watchlistAlertEmail, isConfigured, outbox };
