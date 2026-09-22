'use strict';

const crypto = require('crypto');

/**
 * Minimal, dependency-free HS256 JWT implementation.
 * Signing/verification uses only node:crypto (timing-safe comparison).
 */

function b64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlDecode(input) {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8');
}

function parseExpiry(expiresIn) {
  if (typeof expiresIn === 'number') return expiresIn;
  const match = /^(\d+)\s*([smhd])?$/.exec(String(expiresIn).trim());
  if (!match) return 8 * 3600;
  const value = Number(match[1]);
  const unit = match[2] || 's';
  return value * { s: 1, m: 60, h: 3600, d: 86400 }[unit];
}

function sign(payload, secret, options = {}) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const nowSec = Math.floor(Date.now() / 1000);
  const body = {
    ...payload,
    iat: nowSec,
    exp: nowSec + parseExpiry(options.expiresIn || '8h'),
  };
  const encoded = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(body))}`;
  const signature = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verify(token, secret) {
  if (typeof token !== 'string') throw new Error('token missing');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');

  const [headerPart, payloadPart, signaturePart] = parts;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${headerPart}.${payloadPart}`)
    .digest('base64url');

  const a = Buffer.from(signaturePart);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('invalid signature');
  }

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(payloadPart));
  } catch {
    throw new Error('malformed payload');
  }

  if (typeof payload.exp === 'number' && Math.floor(Date.now() / 1000) >= payload.exp) {
    throw new Error('token expired');
  }
  return payload;
}

module.exports = { sign, verify, parseExpiry };
