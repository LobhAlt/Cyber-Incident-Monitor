'use strict';

const crypto = require('crypto');
const store = require('./store');

/**
 * Append-only activity log for security-relevant events (sign-ins, sign-ups,
 * password changes, admin actions, lookups). Newest first, capped so the flat
 * file stays small. Never records passwords, tokens or codes.
 */

const MAX_ENTRIES = 5000;

function clientIp(req) {
  if (!req) return null;
  return req.ip || (req.socket && req.socket.remoteAddress) || null;
}

async function log(event, { req, actor, target, detail, outcome = 'success' } = {}) {
  const who = actor || (req && req.user) || null;
  const entry = {
    id: crypto.randomUUID(),
    at: new Date().toISOString(),
    event,
    outcome,
    actorId: who ? who.sub || who.id || null : null,
    actor: who ? who.username || null : null,
    ip: clientIp(req),
    target: target || null,
    detail: detail || null,
  };
  try {
    await store.update('audit', (list) => {
      list.unshift(entry);
      return list.slice(0, MAX_ENTRIES);
    });
  } catch (err) {
    // Logging must never break the request it describes.
    // eslint-disable-next-line no-console
    console.error('[CIMI] audit log write failed:', err.message);
  }
  return entry;
}

async function list({ limit = 200, event, actor } = {}) {
  const entries = await store.read('audit');
  return entries
    .filter((e) => (!event || e.event.startsWith(event)) && (!actor || e.actor === actor))
    .slice(0, Math.min(Number(limit) || 200, 1000));
}

module.exports = { log, list };
