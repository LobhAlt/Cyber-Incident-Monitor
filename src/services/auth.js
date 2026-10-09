'use strict';

const crypto = require('crypto');
const config = require('../config');
const store = require('./store');
const jwt = require('../utils/jwt');
const totp = require('../utils/totp');
const mailer = require('./mailer');
const passwordPolicy = require('../utils/password');

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function hashPassword(password, saltHex) {
  const salt = saltHex || crypto.randomBytes(16).toString('hex');
  const derived = crypto
    .scryptSync(String(password), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p })
    .toString('hex');
  return { salt, hash: derived };
}

function verifyPassword(password, saltHex, expectedHex) {
  const { hash } = hashPassword(password, saltHex);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(String(expectedHex || ''), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    email: user.email || null,
    // Accounts created before email verification existed have no flag and count as verified.
    emailVerified: user.emailVerified !== false,
    mfaEnabled: Boolean(user.mfaEnabled),
    disabled: Boolean(user.disabled),
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null,
    passwordChangedAt: user.passwordChangedAt || null,
  };
}

function httpError(message, status, code) {
  return Object.assign(new Error(message), { status, code });
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function normaliseEmail(email) {
  return String(email || '').trim().toLowerCase();
}

/** Only the SHA-256 of a verification token is stored, so a leaked users.json cannot verify anything. */
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function newVerification() {
  const token = crypto.randomBytes(32).toString('base64url');
  return {
    token,
    hash: hashToken(token),
    expiresAt: new Date(Date.now() + config.emailVerifyTtlMs).toISOString(),
  };
}

const RESET_TTL_MS = 30 * 60 * 1000;

function newResetToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  return { token, hash: hashToken(token), expiresAt: new Date(Date.now() + RESET_TTL_MS).toISOString() };
}

function requireStrongPassword(password, user) {
  const problem = passwordPolicy.check(password, { username: user.username, email: user.email });
  if (problem) throw httpError(problem, 400, 'WEAK_PASSWORD');
}

function verificationLink(baseUrl, token) {
  return `${baseUrl}/verify.html#token=${encodeURIComponent(token)}`;
}

async function sendVerification(user, token, baseUrl) {
  const hours = Math.round(config.emailVerifyTtlMs / 3600000);
  const message = mailer.verificationEmail({ username: user.username, link: verificationLink(baseUrl, token), hours });
  return mailer.send({ to: user.email, ...message });
}

async function ensureDefaultUser() {
  const users = await store.read('users');
  if (users.length > 0) return publicUser(users[0]);

  const { salt, hash } = hashPassword(config.defaultAdmin.password);
  const user = {
    id: crypto.randomUUID(),
    username: config.defaultAdmin.username,
    role: 'admin',
    salt,
    hash,
    mfaEnabled: false,
    mfaSecret: null,
    // The default password is published in the README, so it must be replaced on first sign-in.
    mustChangePassword: true,
    sessionVersion: 0,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  };
  await store.update('users', (list) => {
    list.push(user);
    return list;
  });
  return publicUser(user);
}

async function findByUsername(username) {
  const users = await store.read('users');
  const needle = String(username || '').trim().toLowerCase();
  return users.find((u) => u.username.toLowerCase() === needle) || null;
}

/** Sign-in accepts either the username or the account's email address. */
async function findByLogin(login) {
  const users = await store.read('users');
  const needle = String(login || '').trim().toLowerCase();
  if (!needle) return null;
  return users.find((u) => u.username.toLowerCase() === needle || (u.email && u.email === needle)) || null;
}

/**
 * Creates an unverified account and emails a one-time confirmation link.
 * The account cannot sign in until the link is used.
 */
async function register({ username, email, password, role = 'analyst' }, { baseUrl }) {
  const name = String(username || '').trim();
  const address = normaliseEmail(email);
  if (name.length < 3) throw httpError('Username must be at least 3 characters', 400);
  if (!/^[A-Za-z0-9._-]+$/.test(name)) throw httpError('Username may contain letters, numbers, dots, hyphens and underscores only', 400);
  if (!EMAIL_RE.test(address) || address.length > 254) throw httpError('Enter a valid email address', 400);
  requireStrongPassword(password, { username: name, email: address });

  const { salt, hash } = hashPassword(password);
  const verification = newVerification();
  const user = {
    id: crypto.randomUUID(),
    username: name,
    email: address,
    emailVerified: false,
    emailVerifyHash: verification.hash,
    emailVerifyExpiresAt: verification.expiresAt,
    emailVerifySentAt: new Date().toISOString(),
    role: role === 'admin' ? 'admin' : 'analyst',
    salt,
    hash,
    mfaEnabled: false,
    mfaSecret: null,
    sessionVersion: 0,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  };

  // Uniqueness is checked inside the serialised update so two signups cannot race.
  await store.update('users', (list) => {
    if (list.some((u) => u.username.toLowerCase() === name.toLowerCase())) {
      throw httpError('Username already exists', 409);
    }
    if (list.some((u) => u.email === address)) {
      throw httpError('An account with this email already exists', 409);
    }
    list.push(user);
    return list;
  });

  let delivery;
  try {
    ({ delivery } = await sendVerification(user, verification.token, baseUrl));
  } catch (err) {
    // Roll back so the person can try again instead of being stuck with an unverifiable account.
    await store.update('users', (list) => list.filter((u) => u.id !== user.id));
    // eslint-disable-next-line no-console
    console.error('[CIMI] Verification email failed:', err.message);
    throw Object.assign(httpError('Could not send the verification email. Try again later.', 502), { expose: true });
  }

  return { user: publicUser(user), delivery };
}

/** Consumes a verification token. Tokens are single-use and expire. */
async function verifyEmail(token) {
  const tokenHash = hashToken(token || '');
  let verified = null;
  await store.update('users', (list) => {
    const target = list.find((u) => u.emailVerifyHash && u.emailVerifyHash === tokenHash);
    if (!target) throw httpError('This verification link is invalid or has already been used', 400, 'BAD_VERIFY_TOKEN');
    if (Date.parse(target.emailVerifyExpiresAt) < Date.now()) {
      throw httpError('This verification link has expired. Request a new one from the sign-in page.', 400, 'VERIFY_TOKEN_EXPIRED');
    }
    target.emailVerified = true;
    target.emailVerifiedAt = new Date().toISOString();
    delete target.emailVerifyHash;
    delete target.emailVerifyExpiresAt;
    delete target.emailVerifySentAt;
    verified = target;
    return list;
  });
  return { user: publicUser(verified) };
}

/**
 * Sends a fresh link to an unverified account. Always resolves the same way
 * whether or not the account exists, so it cannot be used to discover emails.
 */
async function resendVerification(login, { baseUrl }) {
  const user = await findByLogin(login);
  if (!user || user.emailVerified !== false) return { ok: true };

  // At most one email per minute per account.
  if (user.emailVerifySentAt && Date.now() - Date.parse(user.emailVerifySentAt) < 60 * 1000) return { ok: true };

  const verification = newVerification();
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === user.id);
    if (target) {
      target.emailVerifyHash = verification.hash;
      target.emailVerifyExpiresAt = verification.expiresAt;
      target.emailVerifySentAt = new Date().toISOString();
    }
    return list;
  });
  try {
    await sendVerification(user, verification.token, baseUrl);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[CIMI] Verification email failed:', err.message);
  }
  return { ok: true };
}

/**
 * Session tokens carry the account's session version (sv): bumping it on the
 * server ends every session at once. Each token also has its own id (jti) so a
 * single sign-out can revoke just that one. `pwc` marks a session that may only
 * change its password.
 */
function issueToken(user, { mustChangePassword = false } = {}) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role,
      sv: user.sessionVersion || 0,
      jti: crypto.randomUUID(),
      ...(mustChangePassword ? { pwc: true } : {}),
    },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

// --- brute-force lockout -----------------------------------------------------
// Tracked per login name (not per IP) and kept in memory. Unknown names are
// tracked the same way as real ones, so a lockout never reveals that an
// account exists.
const LOCK_AFTER = 5;
const LOCK_MS = 15 * 60 * 1000;
const failures = new Map();

function lockKey(login) {
  return String(login || '').trim().toLowerCase();
}

function lockedFor(login) {
  const entry = failures.get(lockKey(login));
  if (!entry || !entry.lockedUntil) return 0;
  const left = entry.lockedUntil - Date.now();
  if (left <= 0) {
    failures.delete(lockKey(login));
    return 0;
  }
  return left;
}

function recordFailure(login) {
  const key = lockKey(login);
  const entry = failures.get(key) || { count: 0, lockedUntil: 0 };
  entry.count += 1;
  if (entry.count >= LOCK_AFTER) {
    entry.lockedUntil = Date.now() + LOCK_MS;
    entry.count = 0;
  }
  failures.set(key, entry);
  // Keep the map bounded if someone sprays random names.
  if (failures.size > 10000) failures.delete(failures.keys().next().value);
  return Boolean(entry.lockedUntil);
}

function clearFailures(login) {
  failures.delete(lockKey(login));
}

function isDefaultCredential(user, password) {
  return user.username.toLowerCase() === String(config.defaultAdmin.username).toLowerCase()
    && password === config.defaultAdmin.password;
}

async function login({ username, password, mfaToken }) {
  const remaining = lockedFor(username);
  if (remaining) {
    throw httpError(`Too many failed sign-in attempts. Try again in ${Math.ceil(remaining / 60000)} minutes, or reset your password.`, 429, 'ACCOUNT_LOCKED');
  }

  const user = await findByLogin(username);
  // Constant-ish work factor even for unknown users, to avoid user enumeration.
  const reference = user || { salt: 'aa'.repeat(16), hash: '00'.repeat(64) };
  const passwordOk = verifyPassword(password || '', reference.salt, reference.hash);

  if (!user || !passwordOk) {
    const nowLocked = recordFailure(username);
    throw httpError(
      nowLocked ? 'Too many failed sign-in attempts. Sign-in is paused for 15 minutes.' : 'Invalid username or password',
      nowLocked ? 429 : 401,
      nowLocked ? 'ACCOUNT_LOCKED' : 'BAD_CREDENTIALS'
    );
  }

  // Checked only after the password, so account status is never revealed to a guesser.
  if (user.disabled) {
    throw httpError('This account has been disabled. Contact your CIMI administrator.', 403, 'ACCOUNT_DISABLED');
  }
  if (user.emailVerified === false) {
    throw httpError('Confirm your email before signing in. Check your inbox for the link.', 403, 'EMAIL_UNVERIFIED');
  }

  if (user.mfaEnabled) {
    if (!mfaToken) {
      return { mfaRequired: true };
    }
    if (!totp.verify(user.mfaSecret, mfaToken)) {
      recordFailure(username);
      throw httpError('Invalid MFA code', 401, 'BAD_MFA');
    }
  }

  clearFailures(username);
  const mustChangePassword = Boolean(user.mustChangePassword) || isDefaultCredential(user, password);
  const now = new Date().toISOString();
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === user.id);
    if (target) target.lastLoginAt = now;
    return list;
  });

  return {
    token: issueToken(user, { mustChangePassword }),
    user: { ...publicUser({ ...user, lastLoginAt: now }), mustChangePassword },
    mustChangePassword,
  };
}

/** Changes the password for a signed-in user and ends every other session. */
async function changePassword(userId, currentPassword, newPassword) {
  const users = await store.read('users');
  const user = users.find((u) => u.id === userId);
  if (!user) throw httpError('User not found', 404);
  if (!verifyPassword(currentPassword || '', user.salt, user.hash)) {
    throw httpError('Current password is incorrect', 401, 'BAD_CREDENTIALS');
  }
  if (verifyPassword(newPassword || '', user.salt, user.hash) || newPassword === config.defaultAdmin.password) {
    throw httpError('Choose a password you have not used here before', 400, 'WEAK_PASSWORD');
  }
  requireStrongPassword(newPassword, user);

  const { salt, hash } = hashPassword(newPassword);
  let updated;
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === userId);
    if (target) {
      target.salt = salt;
      target.hash = hash;
      target.mustChangePassword = false;
      target.passwordChangedAt = new Date().toISOString();
      target.sessionVersion = (target.sessionVersion || 0) + 1;
      updated = target;
    }
    return list;
  });
  clearFailures(user.username);
  return { token: issueToken(updated), user: publicUser(updated) };
}

/**
 * Emails a password-reset link. Same reply whether or not the account
 * exists, and at most one email per minute per account.
 */
async function requestPasswordReset(login, { baseUrl }) {
  const user = await findByLogin(login);
  if (!user || !user.email || user.disabled) return { ok: true, user: null };
  if (user.passwordResetSentAt && Date.now() - Date.parse(user.passwordResetSentAt) < 60 * 1000) return { ok: true, user: null };

  const reset = newResetToken();
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === user.id);
    if (target) {
      target.passwordResetHash = reset.hash;
      target.passwordResetExpiresAt = reset.expiresAt;
      target.passwordResetSentAt = new Date().toISOString();
    }
    return list;
  });
  try {
    const message = mailer.passwordResetEmail({
      username: user.username,
      link: `${baseUrl}/reset.html#token=${encodeURIComponent(reset.token)}`,
      minutes: Math.round(RESET_TTL_MS / 60000),
    });
    await mailer.send({ to: user.email, ...message });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[CIMI] Password reset email failed:', err.message);
  }
  return { ok: true, user: publicUser(user) };
}

/** Consumes a reset token, sets the new password and signs out every device. */
async function resetPassword(token, newPassword) {
  const tokenHash = hashToken(token || '');
  const users = await store.read('users');
  const user = users.find((u) => u.passwordResetHash && u.passwordResetHash === tokenHash);
  if (!user) throw httpError('This reset link is invalid or has already been used', 400, 'BAD_RESET_TOKEN');
  if (Date.parse(user.passwordResetExpiresAt) < Date.now()) {
    throw httpError('This reset link has expired. Request a new one from the sign-in page.', 400, 'RESET_TOKEN_EXPIRED');
  }
  if (newPassword === config.defaultAdmin.password) throw httpError('Choose a different password', 400, 'WEAK_PASSWORD');
  requireStrongPassword(newPassword, user);

  const { salt, hash } = hashPassword(newPassword);
  let updated;
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === user.id);
    // Re-check inside the serialised update so a token can only ever be used once.
    if (!target || target.passwordResetHash !== tokenHash) {
      throw httpError('This reset link is invalid or has already been used', 400, 'BAD_RESET_TOKEN');
    }
    target.salt = salt;
    target.hash = hash;
    target.mustChangePassword = false;
    target.passwordChangedAt = new Date().toISOString();
    target.sessionVersion = (target.sessionVersion || 0) + 1;
    // Opening the emailed link proves the person controls the mailbox.
    if (target.emailVerified === false) {
      target.emailVerified = true;
      target.emailVerifiedAt = new Date().toISOString();
      delete target.emailVerifyHash;
      delete target.emailVerifyExpiresAt;
      delete target.emailVerifySentAt;
    }
    delete target.passwordResetHash;
    delete target.passwordResetExpiresAt;
    delete target.passwordResetSentAt;
    updated = target;
    return list;
  });
  clearFailures(user.username);
  if (user.email) clearFailures(user.email);
  return { user: publicUser(updated) };
}

/** Ends every session for the account by moving its session version on. */
async function endAllSessions(userId) {
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === userId);
    if (target) target.sessionVersion = (target.sessionVersion || 0) + 1;
    return list;
  });
}

/** Revokes one session (used by sign-out). Entries are dropped once the token would have expired anyway. */
async function revokeSession(payload) {
  if (!payload || !payload.jti) return;
  const now = Math.floor(Date.now() / 1000);
  await store.update('revokedSessions', (list) => {
    const live = list.filter((r) => r.exp > now);
    live.push({ jti: payload.jti, exp: payload.exp || now + 86400 });
    return live;
  });
}

/**
 * Called on every authenticated request: the token signature alone is not
 * enough, the account must still exist, be enabled, match the session
 * version, and the token must not have been signed out.
 */
async function validateSession(payload) {
  const users = await store.read('users');
  const user = users.find((u) => u.id === payload.sub);
  if (!user) return { ok: false, reason: 'Account no longer exists' };
  if (user.disabled) return { ok: false, reason: 'This account has been disabled' };
  if ((user.sessionVersion || 0) !== (payload.sv || 0)) return { ok: false, reason: 'Session ended, please sign in again' };
  if (payload.jti) {
    const revoked = await store.read('revokedSessions');
    if (revoked.some((r) => r.jti === payload.jti)) return { ok: false, reason: 'Session ended, please sign in again' };
  }
  return { ok: true, user };
}

// --- administration ----------------------------------------------------------

async function listUsers() {
  const users = await store.read('users');
  return users.map(publicUser);
}

async function setDisabled(actorId, userId, disabled) {
  if (actorId === userId) throw httpError('You cannot disable your own account', 400);
  let updated;
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === userId);
    if (!target) throw httpError('User not found', 404);
    if (disabled && target.role === 'admin' && list.filter((u) => u.role === 'admin' && !u.disabled).length <= 1) {
      throw httpError('At least one admin account must stay enabled', 400);
    }
    target.disabled = Boolean(disabled);
    // Disabling ends any sessions that account has open.
    if (disabled) target.sessionVersion = (target.sessionVersion || 0) + 1;
    updated = target;
    return list;
  });
  return publicUser(updated);
}

async function deleteUser(actorId, userId) {
  if (actorId === userId) throw httpError('You cannot delete your own account', 400);
  let removed;
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === userId);
    if (!target) throw httpError('User not found', 404);
    if (target.role === 'admin' && list.filter((u) => u.role === 'admin').length <= 1) {
      throw httpError('The last admin account cannot be deleted', 400);
    }
    removed = target;
    return list.filter((u) => u.id !== userId);
  });
  return publicUser(removed);
}

async function beginMfaSetup(userId) {
  const users = await store.read('users');
  const user = users.find((u) => u.id === userId);
  if (!user) throw Object.assign(new Error('User not found'), { status: 404 });

  const secret = totp.generateSecret();
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === userId);
    if (target) {
      target.mfaSecret = secret;
      target.mfaEnabled = false;
    }
    return list;
  });

  return { secret, otpauthUrl: totp.otpauthUrl(secret, user.username) };
}

async function confirmMfa(userId, token) {
  const users = await store.read('users');
  const user = users.find((u) => u.id === userId);
  if (!user || !user.mfaSecret) {
    throw Object.assign(new Error('Start MFA setup first'), { status: 400 });
  }
  if (!totp.verify(user.mfaSecret, token)) {
    throw Object.assign(new Error('Invalid MFA code'), { status: 400 });
  }
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === userId);
    if (target) target.mfaEnabled = true;
    return list;
  });
  return { mfaEnabled: true };
}

async function disableMfa(userId, password) {
  const users = await store.read('users');
  const user = users.find((u) => u.id === userId);
  if (!user) throw Object.assign(new Error('User not found'), { status: 404 });
  if (!verifyPassword(password || '', user.salt, user.hash)) {
    throw Object.assign(new Error('Password incorrect'), { status: 401 });
  }
  await store.update('users', (list) => {
    const target = list.find((u) => u.id === userId);
    if (target) {
      target.mfaEnabled = false;
      target.mfaSecret = null;
    }
    return list;
  });
  return { mfaEnabled: false };
}

async function getById(userId) {
  const users = await store.read('users');
  return publicUser(users.find((u) => u.id === userId));
}

module.exports = {
  ensureDefaultUser,
  register,
  verifyEmail,
  resendVerification,
  login,
  changePassword,
  requestPasswordReset,
  resetPassword,
  endAllSessions,
  revokeSession,
  validateSession,
  listUsers,
  setDisabled,
  deleteUser,
  findByLogin,
  getById,
  beginMfaSetup,
  confirmMfa,
  disableMfa,
  hashPassword,
  verifyPassword,
  publicUser,
  sessionMaxAgeMs: () => jwt.parseExpiry(config.jwtExpiresIn) * 1000,
};
