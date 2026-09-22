'use strict';

const store = require('./store');
const cache = require('./cache');
const config = require('../config');

const COUNTRY_NAMES = {
  IN: 'India', CN: 'China', RU: 'Russia', US: 'United States', NL: 'Netherlands',
  BR: 'Brazil', VN: 'Vietnam', PK: 'Pakistan', DE: 'Germany', SG: 'Singapore',
  GB: 'United Kingdom', FR: 'France', JP: 'Japan', KR: 'South Korea', TR: 'Turkey',
  IR: 'Iran', UA: 'Ukraine', ID: 'Indonesia', BD: 'Bangladesh', LK: 'Sri Lanka',
};

function dayKey(iso) {
  return String(iso || '').slice(0, 10);
}

/** Build the whole dashboard payload from the analyst's own lookup history. */
async function build({ days = 14 } = {}) {
  const [history, logReports] = await Promise.all([
    store.read('iocHistory'),
    store.read('logReports'),
  ]);

  const windowStart = Date.now() - days * 86_400_000;
  const inWindow = history.filter((h) => new Date(h.queriedAt).getTime() >= windowStart);

  const counts = { malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
  history.forEach((h) => {
    counts[h.verdict] = (counts[h.verdict] || 0) + 1;
  });

  // --- daily verdict trend -------------------------------------------------
  const trendMap = new Map();
  for (let i = days - 1; i >= 0; i -= 1) {
    const key = new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10);
    trendMap.set(key, { date: key, malicious: 0, suspicious: 0, clean: 0, unknown: 0, total: 0 });
  }
  inWindow.forEach((h) => {
    const bucket = trendMap.get(dayKey(h.queriedAt));
    if (!bucket) return;
    bucket[h.verdict] = (bucket[h.verdict] || 0) + 1;
    bucket.total += 1;
  });
  const trend = Array.from(trendMap.values());

  // --- geographic distribution --------------------------------------------
  const geoMap = new Map();
  history.forEach((h) => {
    if (!h.countryCode) return;
    const entry = geoMap.get(h.countryCode) || {
      countryCode: h.countryCode,
      countryName: COUNTRY_NAMES[h.countryCode] || h.countryCode,
      total: 0,
      malicious: 0,
    };
    entry.total += 1;
    if (h.verdict === 'malicious') entry.malicious += 1;
    geoMap.set(h.countryCode, entry);
  });
  const geography = Array.from(geoMap.values()).sort((a, b) => b.total - a.total).slice(0, 12);

  // --- indicator type split ------------------------------------------------
  const typeMap = new Map();
  history.forEach((h) => {
    typeMap.set(h.type, (typeMap.get(h.type) || 0) + 1);
  });
  const byType = Array.from(typeMap.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);

  // --- top ATT&CK techniques ----------------------------------------------
  const techMap = new Map();
  history.forEach((h) => {
    (h.techniques || []).forEach((t) => techMap.set(t, (techMap.get(t) || 0) + 1));
  });
  const topTechniques = Array.from(techMap.entries())
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // --- top tags ------------------------------------------------------------
  const tagMap = new Map();
  history.forEach((h) => {
    (h.tags || []).forEach((t) => {
      const key = String(t).toLowerCase();
      tagMap.set(key, (tagMap.get(key) || 0) + 1);
    });
  });
  const topTags = Array.from(tagMap.entries())
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  const scores = history.map((h) => h.score || 0);
  const averageScore = scores.length
    ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
    : 0;

  const last24h = history.filter(
    (h) => Date.now() - new Date(h.queriedAt).getTime() < 86_400_000
  ).length;

  return {
    generatedAt: new Date().toISOString(),
    windowDays: days,
    kpis: {
      totalLookups: history.length,
      lookupsLast24h: last24h,
      maliciousCount: counts.malicious,
      suspiciousCount: counts.suspicious,
      cleanCount: counts.clean,
      unknownCount: counts.unknown,
      detectionRate: history.length
        ? Math.round(((counts.malicious + counts.suspicious) / history.length) * 100)
        : 0,
      averageScore,
      logReports: logReports.length,
      uniqueIndicators: new Set(history.map((h) => h.indicator)).size,
    },
    trend,
    geography,
    byType,
    topTechniques,
    topTags,
    recentAlerts: history
      .filter((h) => h.verdict === 'malicious' || h.verdict === 'suspicious')
      .slice(0, 12),
    recentLookups: history.slice(0, 15),
    system: {
      demoMode: config.forceDemoMode,
      providers: {
        virustotal: config.providerEnabled.virustotal ? 'live' : 'simulated',
        abuseipdb: config.providerEnabled.abuseipdb ? 'live' : 'simulated',
        otx: config.providerEnabled.otx ? 'live' : 'simulated',
        cisaKev: 'live-with-offline-fallback',
        certin: 'scraper-with-offline-fallback',
      },
      cache: {
        entries: cache.snapshot().entries,
        hitRate: cache.snapshot().hitRate,
      },
    },
  };
}

module.exports = { build, COUNTRY_NAMES };
