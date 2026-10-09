'use strict';

const config = require('../config');
const jwt = require('../utils/jwt');

function readCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1 && part.slice(0, idx).trim() === name) {
      try { return decodeURIComponent(part.slice(idx + 1).trim()); } catch (e) { return null; }
    }
  }
  return null;
}

/**
 * The browser app authenticates with the HttpOnly session cookie. A Bearer
 * header is still accepted for scripted API clients. Tokens in the query
 * string are not accepted, because URLs end up in logs and history.
 */
function extractToken(req) {
  const fromCookie = readCookie(req, config.sessionCookie);
  if (fromCookie) return fromCookie;
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim();
  return null;
}

// While a password change is pending, a session may only reach these endpoints.
const PASSWORD_CHANGE_ALLOWED = ['/api/auth/me', '/api/auth/change-password', '/api/auth/logout'];

function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }
  let payload;
  try {
    payload = jwt.verify(token, config.jwtSecret);
  } catch (err) {
    return res.status(401).json({
      error: err.message === 'token expired' ? 'Session expired, please sign in again' : 'Invalid session token',
      code: err.message === 'token expired' ? 'TOKEN_EXPIRED' : 'BAD_TOKEN',
    });
  }

  // Lazy require: the auth service depends on the store, which this module should not load at import time.
  // eslint-disable-next-line global-require
  const authService = require('../services/auth');
  return authService.validateSession(payload).then((check) => {
    if (!check.ok) return res.status(401).json({ error: check.reason, code: 'SESSION_ENDED' });
    // Role comes from the stored account, so a demoted admin loses access straight away.
    req.user = { ...payload, role: check.user.role, username: check.user.username };
    if (payload.pwc && !PASSWORD_CHANGE_ALLOWED.includes(req.originalUrl.split('?')[0])) {
      return res.status(403).json({ error: 'Change your password to continue', code: 'PASSWORD_CHANGE_REQUIRED' });
    }
    return next();
  }).catch(next);
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    return next();
  };
}

module.exports = { requireAuth, requireRole, extractToken };
