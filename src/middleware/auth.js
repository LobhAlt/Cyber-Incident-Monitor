'use strict';

const config = require('../config');
const jwt = require('../utils/jwt');

function extractToken(req) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim();
  if (req.query && typeof req.query.token === 'string') return req.query.token;
  return null;
}

function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }
  try {
    req.user = jwt.verify(token, config.jwtSecret);
    return next();
  } catch (err) {
    return res.status(401).json({
      error: err.message === 'token expired' ? 'Session expired, please sign in again' : 'Invalid session token',
      code: err.message === 'token expired' ? 'TOKEN_EXPIRED' : 'BAD_TOKEN',
    });
  }
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
