'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');

/**
 * Persistence layer with two backends behind one interface (read / write /
 * update by collection name):
 *
 *  - Files (default): one JSON file per collection under data/. Writes are
 *    serialised per file and atomic (tmp file + rename).
 *  - MongoDB (when MONGODB_URI is set, e.g. Atlas): one document per
 *    collection in the `cimi_store` collection. Values are cached in memory
 *    after the first read and every write goes to the database before the
 *    cache is updated. That is safe because a single server process owns the
 *    data (one Render instance); run only one instance against a database.
 */

const FILES = {
  users: 'users.json',
  iocHistory: 'ioc_history.json',
  logReports: 'log_reports.json',
  advisories: 'advisories.json',
  audit: 'audit_log.json',
  watchlist: 'watchlist.json',
  settings: 'settings.json',
  revokedSessions: 'revoked_sessions.json',
};

const DEFAULTS = {
  users: [],
  iocHistory: [],
  logReports: [],
  advisories: [],
  audit: [],
  watchlist: [],
  settings: {},
  revokedSessions: [],
};

const MONGO_COLLECTION = 'cimi_store';

const queues = new Map();
let mongo = null; // { client, collection, cache: Map } once connected

function fallbackFor(name) {
  return structuredClone(DEFAULTS[name] ?? []);
}

// --- file backend --------------------------------------------------------------

function filePath(name) {
  return path.join(config.dataDir, FILES[name] || name);
}

function ensureDataDir() {
  if (mongo) return;
  if (!fs.existsSync(config.dataDir)) {
    fs.mkdirSync(config.dataDir, { recursive: true });
  }
}

async function readFile(name) {
  ensureDataDir();
  const file = filePath(name);
  try {
    const raw = await fsp.readFile(file, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {
      const fallback = fallbackFor(name);
      await writeFile(name, fallback);
      return fallback;
    }
    if (err instanceof SyntaxError) {
      // Corrupt file: preserve it for forensics and start clean.
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      const fallback = fallbackFor(name);
      await writeFile(name, fallback);
      return fallback;
    }
    throw err;
  }
}

async function writeFile(name, value) {
  ensureDataDir();
  const file = filePath(name);
  const tmp = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(value, null, 2), 'utf8');
  await fsp.rename(tmp, file);
  return value;
}

// --- MongoDB backend -----------------------------------------------------------

async function readMongo(name) {
  if (!mongo.cache.has(name)) {
    const doc = await mongo.collection.findOne({ _id: name });
    mongo.cache.set(name, doc ? doc.value : fallbackFor(name));
  }
  // Hand out a copy so callers can never mutate the cache by accident.
  return structuredClone(mongo.cache.get(name));
}

async function writeMongo(name, value) {
  await mongo.collection.replaceOne(
    { _id: name },
    { _id: name, value, updatedAt: new Date() },
    { upsert: true }
  );
  mongo.cache.set(name, structuredClone(value));
  return value;
}

/**
 * Uses an already-open collection (anything with findOne / replaceOne).
 * Exposed so tests can exercise the MongoDB code path without a server.
 */
function useMongoCollection(collection, client = null) {
  mongo = { client, collection, cache: new Map() };
}

/**
 * Connects to MongoDB when MONGODB_URI is set. Call once at startup, before
 * anything reads data. Also keeps the session-signing secret in the database
 * when JWT_SECRET is not set, so sessions survive restarts.
 */
async function init() {
  if (!config.mongodb.uri || mongo) return { backend: mongo ? 'mongodb' : 'files' };
  // eslint-disable-next-line global-require
  const { MongoClient } = require('mongodb');
  const client = new MongoClient(config.mongodb.uri, {
    serverSelectionTimeoutMS: 15000,
    appName: 'cimi',
  });
  await client.connect();
  const collection = client.db(config.mongodb.dbName).collection(MONGO_COLLECTION);
  useMongoCollection(collection, client);

  if (!config.jwtSecretFromEnv) {
    const doc = await collection.findOne({ _id: 'jwtSecret' });
    if (doc && typeof doc.value === 'string' && doc.value.length >= 32) {
      config.jwtSecret = doc.value;
    } else {
      const secret = crypto.randomBytes(48).toString('hex');
      await collection.updateOne({ _id: 'jwtSecret' }, { $setOnInsert: { value: secret } }, { upsert: true });
      const stored = await collection.findOne({ _id: 'jwtSecret' });
      config.jwtSecret = stored.value;
    }
  }
  return { backend: 'mongodb' };
}

async function close() {
  if (mongo && mongo.client) await mongo.client.close();
  mongo = null;
}

function backend() {
  return mongo ? 'mongodb' : 'files';
}

// --- public interface ------------------------------------------------------------

async function read(name) {
  return mongo ? readMongo(name) : readFile(name);
}

async function write(name, value) {
  return mongo ? writeMongo(name, value) : writeFile(name, value);
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

module.exports = {
  read, write, update, init, close, backend, useMongoCollection,
  FILES, filePath, ensureDataDir, MONGO_COLLECTION,
};
