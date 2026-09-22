'use strict';

const config = require('../../config');
const cache = require('../cache');
const { request } = require('../../utils/http');
const simulator = require('../simulator');

const CATEGORY_NAMES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH Bruteforce', 23: 'IoT Targeted',
};

function verdictFromScore(score) {
  if (score >= 70) return 'malicious';
  if (score >= 25) return 'suspicious';
  return 'clean';
}

function normalise(value, body) {
  const d = (body && body.data) || {};
  const score = d.abuseConfidenceScore || 0;
  const categories = Array.from(
    new Set((d.reports || []).flatMap((r) => r.categories || []))
  )
    .map((c) => CATEGORY_NAMES[c] || `Category ${c}`)
    .slice(0, 6);

  return {
    source: 'AbuseIPDB',
    available: true,
    simulated: false,
    score,
    verdict: verdictFromScore(score),
    stats: {
      abuseConfidenceScore: score,
      totalReports: d.totalReports || 0,
      distinctReporters: d.numDistinctUsers || 0,
    },
    details: {
      countryCode: d.countryCode || null,
      countryName: d.countryName || null,
      isp: d.isp || null,
      usageType: d.usageType || null,
      isPublic: d.isPublic ?? null,
      isWhitelisted: d.isWhitelisted ?? false,
      domain: d.domain || null,
      lastReportedAt: d.lastReportedAt || null,
      categories,
    },
    link: `https://www.abuseipdb.com/check/${value}`,
  };
}

async function lookup(value, type) {
  if (type !== 'ip') {
    return {
      source: 'AbuseIPDB', available: false, simulated: false, score: 0, verdict: 'unknown',
      reason: 'AbuseIPDB only scores IP addresses',
    };
  }

  if (!config.providerEnabled.abuseipdb) {
    return simulator.abuseipdb(value);
  }

  const key = `abuse:${value}`;
  const cached = cache.get(key);
  if (cached) return { ...cached, cached: true };

  const url = `${config.endpoints.abuseipdb}/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose=true`;
  const res = await request(url, {
    headers: { Key: config.keys.abuseipdb, Accept: 'application/json' },
  });

  if (!res.ok) {
    const stale = cache.getStale(key);
    if (stale) return { ...stale, cached: true, stale: true };
    return {
      source: 'AbuseIPDB', available: false, simulated: false, score: 0, verdict: 'unknown',
      reason: res.status === 429 ? 'daily quota exhausted (free tier: 1,000 checks/day)' : res.error,
    };
  }

  return cache.set(key, normalise(value, res.data), config.cache.defaultTtl);
}

module.exports = { lookup, normalise, CATEGORY_NAMES };
