'use strict';

const config = require('../../config');
const cache = require('../cache');
const { request } = require('../../utils/http');
const simulator = require('../simulator');

function sectionFor(type) {
  switch (type) {
    case 'ip': return 'IPv4';
    case 'domain': return 'domain';
    case 'url': return 'url';
    case 'md5':
    case 'sha1':
    case 'sha256': return 'file';
    default: return null;
  }
}

function verdictFromPulses(count, tags) {
  const hot = tags.some((t) =>
    /malware|ransom|c2|apt|phish|trojan|botnet|exploit/i.test(t)
  );
  if (count >= 5 || (count >= 2 && hot)) return 'malicious';
  if (count >= 1) return 'suspicious';
  return 'clean';
}

function normalise(value, type, body) {
  const pulseInfo = (body && body.pulse_info) || {};
  const pulses = (pulseInfo.pulses || []).slice(0, 10).map((p) => ({
    id: p.id,
    name: p.name,
    author: (p.author && p.author.username) || p.author_name || 'unknown',
    created: p.created || p.modified || null,
    tags: p.tags || [],
    adversary: p.adversary || '',
  }));

  const tags = Array.from(new Set(pulses.flatMap((p) => p.tags))).slice(0, 20);
  const families = Array.from(
    new Set((pulseInfo.pulses || []).flatMap((p) => p.malware_families || []).map((m) => (typeof m === 'string' ? m : m.display_name)))
  ).filter(Boolean).slice(0, 8);

  const count = pulseInfo.count || pulses.length;

  return {
    source: 'AlienVault OTX',
    available: true,
    simulated: false,
    score: Math.min(100, count * 12),
    verdict: verdictFromPulses(count, tags),
    stats: { pulseCount: count, tagCount: tags.length },
    details: {
      pulses,
      tags,
      malwareFamilies: families,
      indicatorType: type,
      validation: (body && body.validation) || [],
      country: (body && body.country_name) || null,
      asn: (body && body.asn) || null,
    },
    link:
      type === 'ip'
        ? `https://otx.alienvault.com/indicator/ip/${value}`
        : type === 'domain'
        ? `https://otx.alienvault.com/indicator/domain/${value}`
        : `https://otx.alienvault.com/indicator/file/${value}`,
  };
}

async function lookup(value, type) {
  const section = sectionFor(type);
  if (!section) {
    return { source: 'AlienVault OTX', available: false, simulated: false, score: 0, verdict: 'unknown', reason: `type "${type}" not supported by OTX` };
  }

  if (!config.providerEnabled.otx) {
    return simulator.otx(value, type);
  }

  const key = `otx:${type}:${value}`;
  const cached = cache.get(key);
  if (cached) return { ...cached, cached: true };

  const target = type === 'url' ? encodeURIComponent(value) : encodeURIComponent(value);
  const url = `${config.endpoints.otx}/indicators/${section}/${target}/general`;
  const res = await request(url, { headers: { 'X-OTX-API-KEY': config.keys.otx } });

  if (!res.ok) {
    const stale = cache.getStale(key);
    if (stale) return { ...stale, cached: true, stale: true };
    if (res.status === 404) {
      return {
        source: 'AlienVault OTX', available: true, simulated: false, score: 0, verdict: 'clean',
        stats: { pulseCount: 0, tagCount: 0 },
        details: { pulses: [], tags: [], malwareFamilies: [], indicatorType: type },
      };
    }
    return { source: 'AlienVault OTX', available: false, simulated: false, score: 0, verdict: 'unknown', reason: res.error };
  }

  return cache.set(key, normalise(value, type, res.data), config.cache.defaultTtl);
}

/** Subscribed / recent community pulses used by the Threat Feeds module. */
async function recentPulses(limit = 20) {
  if (!config.providerEnabled.otx) {
    const sim = simulator.otx('otx-feed-sample.example', 'domain');
    return sim.details.pulses.map((p) => ({ ...p, simulated: true }));
  }

  const key = `otx:pulses:subscribed:${limit}`;
  const cached = cache.get(key);
  if (cached) return cached;

  const res = await request(`${config.endpoints.otx}/pulses/subscribed?limit=${limit}`, {
    headers: { 'X-OTX-API-KEY': config.keys.otx },
  });

  if (!res.ok) {
    const stale = cache.getStale(key);
    if (stale) return stale;
    return [];
  }

  const pulses = ((res.data && res.data.results) || []).map((p) => ({
    id: p.id,
    name: p.name,
    author: (p.author && p.author.username) || 'unknown',
    created: p.created,
    tags: p.tags || [],
    adversary: p.adversary || '',
    indicatorCount: (p.indicators || []).length,
    simulated: false,
  }));

  return cache.set(key, pulses, config.cache.defaultTtl);
}

module.exports = { lookup, normalise, recentPulses };
