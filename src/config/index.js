'use strict';

const path = require('path');
const crypto = require('crypto');

require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

function bool(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return String(value).toLowerCase() === 'true' || String(value) === '1';
}

function int(value, fallback) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const ROOT = path.join(__dirname, '..', '..');

const config = {
  root: ROOT,
  dataDir: path.join(ROOT, 'data'),
  publicDir: path.join(ROOT, 'public'),
  port: int(process.env.PORT, 3000),
  env: process.env.NODE_ENV || 'development',

  jwtSecret:
    process.env.JWT_SECRET && process.env.JWT_SECRET !== 'change-me-to-a-long-random-string'
      ? process.env.JWT_SECRET
      : crypto.randomBytes(48).toString('hex'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '8h',

  defaultAdmin: {
    username: process.env.DEFAULT_ADMIN_USER || 'analyst',
    password: process.env.DEFAULT_ADMIN_PASSWORD || 'Cimi@2026',
  },

  keys: {
    virustotal: (process.env.VIRUSTOTAL_API_KEY || '').trim(),
    abuseipdb: (process.env.ABUSEIPDB_API_KEY || '').trim(),
    otx: (process.env.OTX_API_KEY || '').trim(),
  },

  cache: {
    defaultTtl: int(process.env.CACHE_TTL_MS, 15 * 60 * 1000),
    cisaTtl: int(process.env.CISA_CACHE_TTL_MS, 6 * 60 * 60 * 1000),
    certinTtl: int(process.env.CERTIN_CACHE_TTL_MS, 6 * 60 * 60 * 1000),
  },

  rateLimit: {
    windowMs: int(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    max: int(process.env.RATE_LIMIT_MAX, 300),
    authMax: int(process.env.AUTH_RATE_LIMIT_MAX, 20),
  },

  forceDemoMode: bool(process.env.FORCE_DEMO_MODE, false),
  scheduler: {
    enabled: bool(process.env.ENABLE_SCHEDULER, true),
    intervalMs: int(process.env.SCHEDULER_INTERVAL_MS, 60 * 60 * 1000),
  },

  limits: {
    bulkMax: 25,
    logIndicatorScreenMax: 15,
    logMaxBytes: 2 * 1024 * 1024,
  },

  endpoints: {
    virustotal: 'https://www.virustotal.com/api/v3',
    abuseipdb: 'https://api.abuseipdb.com/api/v2',
    otx: 'https://otx.alienvault.com/api/v1',
    cisaKev:
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    certin: 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01',
  },

  httpTimeoutMs: 12000,
};

config.providerEnabled = {
  virustotal: !config.forceDemoMode && Boolean(config.keys.virustotal),
  abuseipdb: !config.forceDemoMode && Boolean(config.keys.abuseipdb),
  otx: !config.forceDemoMode && Boolean(config.keys.otx),
};

module.exports = config;
