'use strict';

const crypto = require('crypto');
const config = require('../config');
const store = require('./store');
const jwt = require('../utils/jwt');
const totp = require('../utils/totp');

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
    mfaEnabled: Boolean(user.mfaEnabled),
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null,
  };
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

async function register({ username, password, role = 'analyst' }) {
  const name = String(username || '').trim();
  if (name.length < 3) throw Object.assign(new Error('Username must be at least 3 characters'), { status: 400 });
  if (String(password || '').length < 8) {
    throw Object.assign(new Error('Password must be at least 8 characters'), { status: 400 });
  }
  if (await findByUsername(name)) {
    throw Object.assign(new Error('Username already exists'), { status: 409 });
  }

  const { salt, hash } = hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    username: name,
    role: role === 'admin' ? 'admin' : 'analyst',
    salt,
    hash,
    mfaEnabled: false,
    mfaSecret: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  };
  await store.update('users', (list) => {
    list.push(user);
    return list;
  });
  return publicUser(user);
}

function issueToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

async function login({ username, password, mfaToken }) {
  const user = await findByUsername(username);
  // Constant-ish work factor even for unknown users, to avoid user enumeration.
  const reference = user || { salt: 'aa'.repeat(16), hash: '00'.repeat(64) };
  const passwordOk = verifyPassword(password || '', reference.salt, reference.hash);

  if (!user || !passwordOk) {
    throw Object.assign(new Error('Invalid username or password'), { status: 401 });
  }

  if (user.mfaEnabled) {
    if (!mfaToken) {
      return { mfaRequired: true, user: publicUser(user) };
    }
    if (!totp.verify(user.mfaSecret, mfaToken)) {
      throw Object.assign(new Error('Invalid MFA code'), { status: 401 });
    }
  }

  await store.update('users', (list) => {
    const target = list.find((u) => u.id === user.id);
    if (target) target.lastLoginAt = new Date().toISOString();
    return list;
  });

  return { token: issueToken(user), user: publicUser({ ...user, lastLoginAt: new Date().toISOString() }) };
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
  login,
  getById,
  beginMfaSetup,
  confirmMfa,
  disableMfa,
  hashPassword,
  verifyPassword,
  publicUser,
};
