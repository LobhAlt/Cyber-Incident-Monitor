'use strict';

const crypto = require('crypto');
const config = require('../config');
const indicators = require('../utils/indicators');
const store = require('./store');
const stix = require('./stix');
const attack = require('./attack');

const virustotal = require('./providers/virustotal');
const abuseipdb = require('./providers/abuseipdb');
const otx = require('./providers/otx');
const cisakev = require('./providers/cisakev');

/**
 * Weighted blend of independent reputation sources.
 * Weights are normalised over the sources that actually answered, so a
 * rate-limited provider lowers confidence instead of dragging the score to 0.
 */
const WEIGHTS = {
  VirusTotal: 0.45,
  AbuseIPDB: 0.3,
  'AlienVault OTX': 0.25,
  'CISA KEV': 1.0,
};

function verdictFromScore(score) {
  if (score >= 65) return 'malicious';
  if (score >= 30) return 'suspicious';
  return 'clean';
}

function severityFromScore(score) {
  if (score >= 80) return 'Critical';
  if (score >= 65) return 'High';
  if (score >= 30) return 'Medium';
  if (score > 0) return 'Low';
  return 'Informational';
}

function blend(sources) {
  const answered = sources.filter((s) => s && s.available && typeof s.score === 'number');
  if (answered.length === 0) {
    return { score: 0, verdict: 'unknown', confidence: 0, contributing: 0 };
  }

  const totalWeight = answered.reduce((sum, s) => sum + (WEIGHTS[s.source] || 0.2), 0);
  const weighted = answered.reduce(
    (sum, s) => sum + s.score * (WEIGHTS[s.source] || 0.2),
    0
  );
  let score = Math.round(weighted / totalWeight);

  // Corroboration bonus: two or more independent sources calling it malicious.
  const maliciousVotes = answered.filter((s) => s.verdict === 'malicious').length;
  if (maliciousVotes >= 2) score = Math.min(100, score + 12);
  if (maliciousVotes >= 3) score = Math.min(100, score + 8);

  // A KEV hit is authoritative — exploited in the wild.
  if (answered.some((s) => s.source === 'CISA KEV' && s.stats && s.stats.inKevCatalog)) {
    score = Math.max(score, 85);
  }

  const confidence = Math.round(
    (answered.length / Math.max(sources.length, 1)) * 60 +
      (maliciousVotes > 0 ? Math.min(40, maliciousVotes * 18) : 30)
  );

  return {
    score: Math.max(0, Math.min(100, score)),
    verdict: verdictFromScore(score),
    confidence: Math.max(0, Math.min(100, confidence)),
    contributing: answered.length,
  };
}

/** Collect every free-text signal a source produced, for ATT&CK mapping. */
function collectTags(sources) {
  const tags = [];
  sources.forEach((s) => {
    if (!s || !s.details) return;
    if (Array.isArray(s.details.tags)) tags.push(...s.details.tags);
    if (Array.isArray(s.details.categories)) tags.push(...s.details.categories);
    if (Array.isArray(s.details.malwareFamilies)) tags.push(...s.details.malwareFamilies);
    if (Array.isArray(s.details.detectedFamilies)) tags.push(...s.details.detectedFamilies);
    if (Array.isArray(s.details.pulses)) {
      s.details.pulses.forEach((p) => {
        tags.push(p.name || '');
        if (Array.isArray(p.tags)) tags.push(...p.tags);
        if (p.adversary) tags.push(p.adversary);
      });
    }
    if (s.details.usageType) tags.push(s.details.usageType);
    if (s.details.vulnerabilityName) tags.push(s.details.vulnerabilityName);
    if (s.details.product) tags.push(s.details.product);
  });
  return Array.from(new Set(tags.filter(Boolean).map((t) => String(t))));
}

function geoFrom(sources) {
  for (const s of sources) {
    if (!s || !s.details) continue;
    if (s.details.countryCode) {
      return { countryCode: s.details.countryCode, countryName: s.details.countryName || s.details.countryCode };
    }
    if (s.details.country) {
      return { countryCode: s.details.country, countryName: s.details.country };
    }
  }
  return { countryCode: null, countryName: null };
}

/** Synthesised reputation timeline for the UI sparkline. */
function reputationTimeline(indicator, score, days = 14) {
  const seed = crypto.createHash('sha256').update(`timeline:${indicator}`).digest();
  const out = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const jitter = ((seed[i % seed.length] / 255) - 0.5) * 22;
    const drift = ((days - i) / days) * (score * 0.25);
    out.push({
      date: new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10),
      score: Math.max(0, Math.min(100, Math.round(score - score * 0.25 + drift + jitter))),
    });
  }
  if (out.length) out[out.length - 1].score = score;
  return out;
}

/**
 * Aggregate one indicator across every applicable source, in parallel.
 * Never throws for a provider failure — a failed source is reported as
 * `available: false` with a reason.
 */
async function lookupIndicator(rawValue, options = {}) {
  const startedAt = Date.now();
  const detectedType = options.type && options.type !== 'auto'
    ? options.type
    : indicators.detectType(rawValue);
  const value = indicators.normalise(rawValue, detectedType);

  if (detectedType === 'unknown') {
    const error = new Error(`Unrecognised indicator format: "${String(rawValue).slice(0, 80)}"`);
    error.status = 400;
    throw error;
  }

  const tasks =
    detectedType === 'cve'
      ? [cisakev.lookupCve(value)]
      : [
          virustotal.lookup(value, detectedType),
          abuseipdb.lookup(value, detectedType),
          otx.lookup(value, detectedType),
        ];

  const settled = await Promise.allSettled(tasks);
  const sources = settled.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    const names = detectedType === 'cve' ? ['CISA KEV'] : ['VirusTotal', 'AbuseIPDB', 'AlienVault OTX'];
    return {
      source: names[i],
      available: false,
      simulated: false,
      score: 0,
      verdict: 'unknown',
      reason: (r.reason && r.reason.message) || 'provider error',
    };
  });

  const blended = blend(sources);
  const tags = collectTags(sources);
  const techniques = attack.mapTechniques({
    type: detectedType,
    verdict: blended.verdict,
    tags,
  });
  const geo = geoFrom(sources);

  const result = {
    indicator: value,
    type: detectedType,
    verdict: blended.verdict,
    score: blended.score,
    confidence: blended.confidence,
    severity: severityFromScore(blended.score),
    sourcesQueried: sources.length,
    sourcesAvailable: blended.contributing,
    simulated: sources.some((s) => s.simulated),
    geo,
    tags: tags.slice(0, 25),
    sources,
    attackTechniques: techniques,
    reputationTimeline: reputationTimeline(value, blended.score),
    queriedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
  };

  result.stix = stix.bundleForResult(result);
  return result;
}

async function recordHistory(result, user) {
  const entry = {
    id: crypto.randomUUID(),
    indicator: result.indicator,
    type: result.type,
    verdict: result.verdict,
    score: result.score,
    severity: result.severity,
    countryCode: result.geo.countryCode,
    tags: result.tags.slice(0, 10),
    techniques: (result.attackTechniques || []).map((t) => t.id),
    simulated: result.simulated,
    userId: user ? user.sub || user.id : null,
    username: user ? user.username : null,
    queriedAt: result.queriedAt,
  };

  await store.update('iocHistory', (list) => {
    list.unshift(entry);
    // Keep the flat file bounded.
    return list.slice(0, 5000);
  });
  return entry;
}

/** Bulk lookup with a bounded concurrency pool. */
async function lookupBulk(values, options = {}) {
  const list = Array.from(
    new Set(values.map((v) => String(v || '').trim()).filter(Boolean))
  ).slice(0, config.limits.bulkMax);

  const concurrency = Math.min(options.concurrency || 4, 6);
  const results = new Array(list.length);
  let cursor = 0;

  async function worker() {
    while (cursor < list.length) {
      const index = cursor;
      cursor += 1;
      try {
        results[index] = await lookupIndicator(list[index], { type: 'auto' });
      } catch (err) {
        results[index] = {
          indicator: list[index],
          type: indicators.detectType(list[index]),
          verdict: 'unknown',
          score: 0,
          confidence: 0,
          severity: 'Informational',
          error: err.message,
          sources: [],
          attackTechniques: [],
          tags: [],
          geo: { countryCode: null, countryName: null },
          queriedAt: new Date().toISOString(),
        };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, list.length) }, worker));
  return results;
}

function summarise(results) {
  const counts = { malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
  results.forEach((r) => {
    counts[r.verdict] = (counts[r.verdict] || 0) + 1;
  });
  const scores = results.map((r) => r.score || 0);
  return {
    total: results.length,
    ...counts,
    averageScore: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0,
    highestScore: scores.length ? Math.max(...scores) : 0,
  };
}

module.exports = {
  lookupIndicator,
  lookupBulk,
  recordHistory,
  summarise,
  blend,
  verdictFromScore,
  severityFromScore,
  reputationTimeline,
};
