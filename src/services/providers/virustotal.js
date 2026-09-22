'use strict';

const config = require('../../config');
const cache = require('../cache');
const { request } = require('../../utils/http');
const simulator = require('../simulator');

function resourcePath(value, type) {
  switch (type) {
    case 'ip':
      return `/ip_addresses/${encodeURIComponent(value)}`;
    case 'domain':
      return `/domains/${encodeURIComponent(value)}`;
    case 'url':
      return `/urls/${Buffer.from(value).toString('base64url').replace(/=+$/, '')}`;
    case 'md5':
    case 'sha1':
    case 'sha256':
      return `/files/${encodeURIComponent(value)}`;
    default:
      return null;
  }
}

function verdictFromStats(stats) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  if (malicious >= 3) return 'malicious';
  if (malicious >= 1 || suspicious >= 3) return 'suspicious';
  return 'clean';
}

function normalise(value, type, body) {
  const attrs = (body && body.data && body.data.attributes) || {};
  const stats = attrs.last_analysis_stats || {};
  const totalEngines =
    (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);
  const results = attrs.last_analysis_results || {};
  const detectedFamilies = Array.from(
    new Set(
      Object.values(results)
        .filter((r) => r && (r.category === 'malicious' || r.category === 'suspicious') && r.result)
        .map((r) => r.result)
    )
  ).slice(0, 8);

  return {
    source: 'VirusTotal',
    available: true,
    simulated: false,
    score: totalEngines ? Math.min(100, Math.round(((stats.malicious || 0) / totalEngines) * 100 * 2.4)) : 0,
    verdict: verdictFromStats(stats),
    stats: {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      totalEngines,
    },
    details: {
      reputation: attrs.reputation ?? 0,
      firstSubmission: attrs.first_submission_date
        ? new Date(attrs.first_submission_date * 1000).toISOString()
        : null,
      lastAnalysis: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      country: attrs.country || null,
      asOwner: attrs.as_owner || null,
      meaningfulName: attrs.meaningful_name || null,
      fileType: attrs.type_description || null,
      size: attrs.size || null,
      detectedFamilies,
    },
    link:
      type === 'ip'
        ? `https://www.virustotal.com/gui/ip-address/${value}`
        : type === 'domain'
        ? `https://www.virustotal.com/gui/domain/${value}`
        : type === 'url'
        ? 'https://www.virustotal.com/gui/home/url'
        : `https://www.virustotal.com/gui/file/${value}`,
  };
}

async function lookup(value, type) {
  const path = resourcePath(value, type);
  if (!path) {
    return { source: 'VirusTotal', available: false, simulated: false, score: 0, verdict: 'unknown', reason: `type "${type}" not supported by VirusTotal` };
  }

  if (!config.providerEnabled.virustotal) {
    return simulator.virustotal(value, type);
  }

  const key = `vt:${type}:${value}`;
  const cached = cache.get(key);
  if (cached) return { ...cached, cached: true };

  const res = await request(`${config.endpoints.virustotal}${path}`, {
    headers: { 'x-apikey': config.keys.virustotal },
  });

  if (!res.ok) {
    const stale = cache.getStale(key);
    if (stale) return { ...stale, cached: true, stale: true };
    if (res.status === 404) {
      return {
        source: 'VirusTotal', available: true, simulated: false, score: 0, verdict: 'unknown',
        stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, totalEngines: 0 },
        details: { notFound: true }, reason: 'indicator not present in VirusTotal',
      };
    }
    return {
      source: 'VirusTotal', available: false, simulated: false, score: 0, verdict: 'unknown',
      reason: res.status === 429 ? 'rate limit exceeded (free tier: 4 req/min)' : res.error,
    };
  }

  return cache.set(key, normalise(value, type, res.data), config.cache.defaultTtl);
}

module.exports = { lookup, normalise };
