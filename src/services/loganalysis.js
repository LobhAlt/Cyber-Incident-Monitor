'use strict';

const crypto = require('crypto');
const config = require('../config');
const indicators = require('../utils/indicators');
const aggregator = require('./aggregator');
const store = require('./store');

/**
 * Log analysis: regex-extract indicators from a raw log blob, then auto-screen
 * the first N unique indicators against live threat intelligence.
 */

function lineStats(text) {
  const lines = text.split(/\r?\n/);
  return {
    lines: lines.length,
    bytes: Buffer.byteLength(text, 'utf8'),
    nonEmptyLines: lines.filter((l) => l.trim()).length,
  };
}

function guessFormat(text) {
  const sample = text.slice(0, 4000);
  if (/^\s*\{[\s\S]*"\w+"\s*:/.test(sample)) return 'JSON lines';
  if (/\s"(GET|POST|PUT|DELETE|HEAD)\s[^"]*"\s\d{3}\s/.test(sample)) return 'Apache/Nginx access log';
  if (/sshd\[\d+\]|Failed password|Accepted password/.test(sample)) return 'Linux auth log';
  if (/%ASA-|%FTD-|deny\s+(tcp|udp)/i.test(sample)) return 'Firewall log';
  if (/^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/m.test(sample)) return 'Timestamped application log';
  if (/,/.test(sample) && sample.split('\n')[0].split(',').length > 3) return 'CSV export';
  return 'Unstructured text';
}

/** Count how often each indicator appears, so the noisiest are screened first. */
function withFrequency(text, flat) {
  return flat
    .map((item) => {
      const escaped = item.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const matches = text.match(new RegExp(escaped, 'gi'));
      return { ...item, occurrences: matches ? matches.length : 1 };
    })
    .sort((a, b) => b.occurrences - a.occurrences);
}

async function analyse(text, options = {}) {
  const raw = String(text || '');
  if (!raw.trim()) {
    throw Object.assign(new Error('Log content is empty'), { status: 400 });
  }
  if (Buffer.byteLength(raw, 'utf8') > config.limits.logMaxBytes) {
    throw Object.assign(
      new Error(`Log exceeds the ${Math.round(config.limits.logMaxBytes / 1024 / 1024)} MB limit`),
      { status: 413 }
    );
  }

  const extracted = indicators.extractFromText(raw);
  const flat = withFrequency(raw, indicators.flattenExtraction(extracted));
  const screenLimit = Math.min(
    Number(options.screenLimit) || config.limits.logIndicatorScreenMax,
    config.limits.logIndicatorScreenMax
  );

  const toScreen = flat.slice(0, screenLimit);
  const screened = toScreen.length
    ? await aggregator.lookupBulk(toScreen.map((i) => i.value))
    : [];

  const byValue = new Map(screened.map((r) => [r.indicator, r]));
  const findings = toScreen.map((item) => {
    const result = byValue.get(indicators.normalise(item.value, item.type));
    return {
      indicator: item.value,
      type: item.type,
      occurrences: item.occurrences,
      verdict: result ? result.verdict : 'unknown',
      score: result ? result.score : 0,
      severity: result ? result.severity : 'Informational',
      country: result && result.geo ? result.geo.countryCode : null,
      techniques: result ? (result.attackTechniques || []).map((t) => t.id) : [],
      tags: result ? (result.tags || []).slice(0, 6) : [],
      simulated: result ? result.simulated : false,
    };
  });

  const report = {
    id: crypto.randomUUID(),
    fileName: options.fileName || 'pasted-log.txt',
    analysedAt: new Date().toISOString(),
    format: guessFormat(raw),
    stats: lineStats(raw),
    extraction: {
      ips: extracted.ips.length,
      domains: extracted.domains.length,
      urls: extracted.urls.length,
      hashes: extracted.md5.length + extracted.sha1.length + extracted.sha256.length,
      cves: extracted.cves.length,
      totalUnique: flat.length,
    },
    extracted,
    screenedCount: findings.length,
    screenLimit,
    notScreened: Math.max(0, flat.length - findings.length),
    summary: aggregator.summarise(
      findings.map((f) => ({ verdict: f.verdict, score: f.score }))
    ),
    findings,
    userId: options.user ? options.user.sub : null,
    username: options.user ? options.user.username : null,
  };

  await store.update('logReports', (list) => {
    list.unshift({ ...report, extracted: undefined });
    return list.slice(0, 200);
  });

  return report;
}

async function listReports(limit = 25) {
  const reports = await store.read('logReports');
  return reports.slice(0, limit);
}

async function getReport(id) {
  const reports = await store.read('logReports');
  return reports.find((r) => r.id === id) || null;
}

module.exports = { analyse, listReports, getReport, guessFormat };
