'use strict';

const crypto = require('crypto');
const config = require('../config');
const store = require('./store');
const aggregator = require('./aggregator');
const mailer = require('./mailer');
const audit = require('./audit');
const indicators = require('../utils/indicators');

/**
 * Per-analyst watchlist. Each saved indicator is re-screened on the scheduler
 * interval; when its verdict gets worse (clean → suspicious → malicious) the
 * owner is emailed, if alerts are on for that entry.
 */

const MAX_PER_USER = 50;
const HISTORY_POINTS = 20;
const RANK = { unknown: 0, clean: 0, suspicious: 1, malicious: 2 };

function httpError(message, status) {
  return Object.assign(new Error(message), { status });
}

function shape(entry) {
  return {
    id: entry.id,
    indicator: entry.indicator,
    type: entry.type,
    note: entry.note || '',
    alerts: entry.alerts !== false,
    verdict: entry.verdict || 'unknown',
    score: entry.score || 0,
    simulated: Boolean(entry.simulated),
    lastCheckedAt: entry.lastCheckedAt || null,
    lastAlertAt: entry.lastAlertAt || null,
    lastError: entry.lastError || null,
    history: entry.history || [],
    createdAt: entry.createdAt,
  };
}

async function listFor(userId) {
  const all = await store.read('watchlist');
  return all.filter((e) => e.userId === userId).map(shape);
}

async function add(user, { indicator, note }) {
  const raw = String(indicator || '').trim();
  if (!raw) throw httpError('Enter an indicator to watch', 400);
  if (raw.length > 2048) throw httpError('Indicator is too long', 400);
  const type = indicators.detectType(raw);
  if (type === 'unknown') throw httpError(`Unrecognised indicator format: "${raw.slice(0, 80)}"`, 400);
  const value = indicators.normalise(raw, type);

  const entry = {
    id: crypto.randomUUID(),
    userId: user.sub,
    username: user.username,
    indicator: value,
    type,
    note: String(note || '').slice(0, 200),
    alerts: true,
    verdict: 'unknown',
    score: 0,
    history: [],
    createdAt: new Date().toISOString(),
  };

  await store.update('watchlist', (list) => {
    const mine = list.filter((e) => e.userId === user.sub);
    if (mine.length >= MAX_PER_USER) throw httpError(`A watchlist holds up to ${MAX_PER_USER} indicators`, 400);
    if (mine.some((e) => e.indicator === value)) throw httpError('That indicator is already on your watchlist', 409);
    list.push(entry);
    return list;
  });

  // First screening sets the baseline, so no alert is sent for it.
  return check(entry.id, { notify: false });
}

async function remove(userId, id) {
  let found = false;
  await store.update('watchlist', (list) => list.filter((e) => {
    if (e.id === id && e.userId === userId) { found = true; return false; }
    return true;
  }));
  if (!found) throw httpError('Watchlist entry not found', 404);
}

async function setAlerts(userId, id, alerts) {
  let updated;
  await store.update('watchlist', (list) => {
    const target = list.find((e) => e.id === id && e.userId === userId);
    if (!target) throw httpError('Watchlist entry not found', 404);
    target.alerts = Boolean(alerts);
    updated = target;
    return list;
  });
  return shape(updated);
}

async function notifyOwner(entry, previous, result) {
  const users = await store.read('users');
  const owner = users.find((u) => u.id === entry.userId);
  if (!owner || !owner.email || owner.disabled) return false;
  const base = config.publicUrl || `http://localhost:${config.port}`;
  const message = mailer.watchlistAlertEmail({
    username: owner.username,
    indicator: entry.indicator,
    from: previous,
    to: result.verdict,
    score: result.score,
    link: `${base}/#watchlist`,
  });
  await mailer.send({ to: owner.email, ...message });
  return true;
}

/** Re-screens one entry. Returns the updated entry. */
async function check(id, { userId, notify = true } = {}) {
  const all = await store.read('watchlist');
  const entry = all.find((e) => e.id === id && (!userId || e.userId === userId));
  if (!entry) throw httpError('Watchlist entry not found', 404);

  let result = null;
  let error = null;
  try {
    result = await aggregator.lookupIndicator(entry.indicator, { type: entry.type });
  } catch (err) {
    error = err.message;
  }

  const previous = entry.verdict || 'unknown';
  const worsened = result && entry.lastCheckedAt && RANK[result.verdict] > RANK[previous];
  let alerted = false;
  if (worsened && notify && entry.alerts !== false) {
    try {
      alerted = await notifyOwner(entry, previous, result);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[CIMI] Watchlist alert email failed:', err.message);
    }
  }
  if (worsened) {
    await audit.log('watchlist.verdict_worsened', {
      actor: { id: entry.userId, username: entry.username },
      target: entry.indicator,
      detail: `${previous} -> ${result.verdict} (score ${result.score})${alerted ? ', owner emailed' : ''}`,
    });
  }

  let updated;
  await store.update('watchlist', (list) => {
    const target = list.find((e) => e.id === id);
    if (!target) return list;
    target.lastCheckedAt = new Date().toISOString();
    if (result) {
      target.verdict = result.verdict;
      target.score = result.score;
      target.simulated = result.simulated;
      target.lastError = null;
      target.history = [...(target.history || []), { at: target.lastCheckedAt, verdict: result.verdict, score: result.score }]
        .slice(-HISTORY_POINTS);
    } else {
      target.lastError = error;
    }
    if (alerted) target.lastAlertAt = target.lastCheckedAt;
    updated = target;
    return list;
  });
  return updated ? shape(updated) : null;
}

/** Scheduler entry point: re-screens every entry, one at a time to stay inside provider rate limits. */
async function checkAll() {
  const all = await store.read('watchlist');
  let checked = 0;
  for (const entry of all) {
    try {
      // eslint-disable-next-line no-await-in-loop
      await check(entry.id);
      checked += 1;
    } catch (e) { /* entry removed mid-run */ }
  }
  return checked;
}

module.exports = { listFor, add, remove, setAlerts, check, checkAll, MAX_PER_USER };
