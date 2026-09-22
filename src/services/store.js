'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const config = require('../config');

/**
 * Flat-file JSON persistence layer (no database server required).
 * Writes are serialised per-file and performed atomically (tmp file + rename)
 * so a crash mid-write can never corrupt the store.
 */

const FILES = {
  users: 'users.json',
  iocHistory: 'ioc_history.json',
  logReports: 'log_reports.json',
  advisories: 'advisories.json',
};

const DEFAULTS = {
  users: [],
  iocHistory: [],
  logReports: [],
  advisories: [],
};

const queues = new Map();

function filePath(name) {
  return path.join(config.dataDir, FILES[name] || name);
}

function ensureDataDir() {
  if (!fs.existsSync(config.dataDir)) {
    fs.mkdirSync(config.dataDir, { recursive: true });
  }
}

async function read(name) {
  ensureDataDir();
  const file = filePath(name);
  try {
    const raw = await fsp.readFile(file, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed;
  } catch (err) {
    if (err.code === 'ENOENT') {
      const fallback = structuredClone(DEFAULTS[name] ?? []);
      await write(name, fallback);
      return fallback;
    }
    if (err instanceof SyntaxError) {
      // Corrupt file: preserve it for forensics and start clean.
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      const fallback = structuredClone(DEFAULTS[name] ?? []);
      await write(name, fallback);
      return fallback;
    }
    throw err;
  }
}

async function write(name, value) {
  ensureDataDir();
  const file = filePath(name);
  const tmp = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(value, null, 2), 'utf8');
  await fsp.rename(tmp, file);
  return value;
}

/** Serialised read-modify-write so concurrent requests cannot clobber each other. */
function update(name, mutator) {
  const previous = queues.get(name) || Promise.resolve();
  const next = previous
    .catch(() => {})
    .then(async () => {
      const current = await read(name);
      const result = await mutator(current);
      const toPersist = result === undefined ? current : result;
      await write(name, toPersist);
      return toPersist;
    });
  queues.set(name, next);
  return next;
}

module.exports = { read, write, update, FILES, filePath, ensureDataDir };
