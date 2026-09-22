'use strict';

const config = require('../config');

/**
 * Tiny in-memory TTL cache.
 * Keeps stale entries around after expiry so providers that are rate-limited
 * can still serve a "stale-if-error" response instead of failing outright.
 */
const store = new Map();
const stats = { hits: 0, misses: 0, staleServes: 0, sets: 0 };

function get(key) {
  const entry = store.get(key);
  if (!entry) {
    stats.misses += 1;
    return undefined;
  }
  if (Date.now() > entry.expiresAt) {
    stats.misses += 1;
    return undefined;
  }
  stats.hits += 1;
  return entry.value;
}

function getStale(key) {
  const entry = store.get(key);
  if (!entry) return undefined;
  stats.staleServes += 1;
  return entry.value;
}

function set(key, value, ttlMs) {
  stats.sets += 1;
  store.set(key, {
    value,
    storedAt: Date.now(),
    expiresAt: Date.now() + (ttlMs || config.cache.defaultTtl),
  });
  return value;
}

function has(key) {
  return get(key) !== undefined;
}

function del(key) {
  return store.delete(key);
}

function clear() {
  store.clear();
}

/** get-or-populate helper with stale-on-error semantics. */
async function wrap(key, ttlMs, producer) {
  const cached = get(key);
  if (cached !== undefined) return { value: cached, cached: true };

  try {
    const value = await producer();
    set(key, value, ttlMs);
    return { value, cached: false };
  } catch (err) {
    const stale = getStale(key);
    if (stale !== undefined) return { value: stale, cached: true, stale: true };
    throw err;
  }
}

function snapshot() {
  const now = Date.now();
  return {
    entries: store.size,
    ...stats,
    hitRate:
      stats.hits + stats.misses === 0
        ? 0
        : Math.round((stats.hits / (stats.hits + stats.misses)) * 100),
    keys: Array.from(store.entries())
      .slice(0, 50)
      .map(([key, entry]) => ({
        key,
        ageSeconds: Math.round((now - entry.storedAt) / 1000),
        expiresInSeconds: Math.round((entry.expiresAt - now) / 1000),
      })),
  };
}

// Periodic eviction of entries expired for more than 24h (keeps memory bounded).
const sweeper = setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [key, entry] of store.entries()) {
    if (entry.expiresAt < cutoff) store.delete(key);
  }
}, 60 * 60 * 1000);
if (sweeper.unref) sweeper.unref();

module.exports = { get, getStale, set, has, del, clear, wrap, snapshot };
