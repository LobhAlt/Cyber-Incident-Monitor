'use strict';

const config = require('../../config');
const cache = require('../cache');
const { requestWithRetry } = require('../../utils/http');
const simulator = require('../simulator');

/**
 * CERT-In advisory collector.
 *
 * CERT-In serves its vulnerability notes from a Java servlet endpoint that is
 * fronted by request-pattern / rate-limiting controls. Requests therefore carry
 * a full set of browser-like headers, and failures are retried with exponential
 * back-off. If the endpoint still refuses (the intermittent RemoteDisconnected
 * behaviour documented in the synopsis), the module degrades gracefully to a
 * representative offline advisory set flagged `simulated: true`, so downstream
 * modules never break.
 */

const BROWSER_HEADERS = {
  'User-Agent':
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-IN,en-GB;q=0.9,en;q=0.8',
  'Cache-Control': 'no-cache',
  Pragma: 'no-cache',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-User': '?1',
  'Upgrade-Insecure-Requests': '1',
  Referer: 'https://www.cert-in.org.in/',
  Connection: 'keep-alive',
};

function stripTags(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function severityFrom(text) {
  const t = text.toLowerCase();
  if (t.includes('critical')) return 'Critical';
  if (t.includes('high')) return 'High';
  if (t.includes('medium') || t.includes('moderate')) return 'Medium';
  if (t.includes('low')) return 'Low';
  return 'Unrated';
}

function categoryFrom(title) {
  const t = title.toLowerCase();
  if (/chrome|firefox|edge|safari|browser/.test(t)) return 'Browser';
  if (/android|ios|mobile/.test(t)) return 'Mobile';
  if (/windows|linux|kernel|macos|operating system/.test(t)) return 'Operating System';
  if (/cisco|fortinet|router|firewall|vpn/.test(t)) return 'Network Device';
  if (/phishing|ransomware|campaign|malware|fraud/.test(t)) return 'Threat Advisory';
  return 'Application';
}

/** Parse the advisory table rows out of a CERT-In servlet HTML page. */
function parseAdvisories(html) {
  const out = [];
  const rowRe = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
  const cellRe = /<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi;

  let rowMatch;
  while ((rowMatch = rowRe.exec(html)) !== null) {
    const cells = [];
    let cellMatch;
    cellRe.lastIndex = 0;
    while ((cellMatch = cellRe.exec(rowMatch[1])) !== null) {
      cells.push(stripTags(cellMatch[1]));
    }
    if (cells.length < 2) continue;

    const joined = cells.join(' ');
    const idMatch = /(CIVN-\d{4}-\d{3,5}|CIAD-\d{4}-\d{3,5})/i.exec(joined);
    if (!idMatch) continue;

    const id = idMatch[1].toUpperCase();
    const title =
      cells.find((c) => c.length > 20 && !/^(CIVN|CIAD)-/i.test(c)) || `CERT-In advisory ${id}`;
    const dateMatch = /(\d{1,2}[-/ ](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[-/ ]\d{2,4})|(\d{4}-\d{2}-\d{2})/i.exec(joined);
    const parsedDate = dateMatch ? new Date(dateMatch[0].replace(/[-/]/g, ' ')) : null;

    out.push({
      id,
      title,
      severity: severityFrom(joined),
      category: categoryFrom(title),
      publishedAt:
        parsedDate && !Number.isNaN(parsedDate.getTime())
          ? parsedDate.toISOString()
          : new Date().toISOString(),
      summary: title,
      cves: Array.from(new Set((joined.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((c) => c.toUpperCase()))),
      source: 'CERT-In',
      url: config.endpoints.certin,
      simulated: false,
    });
  }

  // De-duplicate by advisory ID, newest first.
  const seen = new Set();
  return out
    .filter((a) => (seen.has(a.id) ? false : seen.add(a.id)))
    .sort((a, b) => String(b.publishedAt).localeCompare(String(a.publishedAt)));
}

async function fetchAdvisories({ force = false } = {}) {
  const key = 'certin:advisories';
  if (!force) {
    const cached = cache.get(key);
    if (cached) return { ...cached, cached: true };
  }

  const res = await requestWithRetry(
    config.endpoints.certin,
    { headers: BROWSER_HEADERS, raw: true, accept: 'text/html', timeoutMs: 20000 },
    3,
    900
  );

  if (res.ok && typeof res.data === 'string' && res.data.length > 200) {
    const advisories = parseAdvisories(res.data);
    if (advisories.length > 0) {
      const payload = {
        ok: true,
        simulated: false,
        fetchedAt: new Date().toISOString(),
        source: config.endpoints.certin,
        count: advisories.length,
        advisories,
      };
      return cache.set(key, payload, config.cache.certinTtl);
    }
  }

  // Degraded mode — endpoint blocked, rate-limited or markup changed.
  const stale = cache.getStale(key);
  if (stale) return { ...stale, cached: true, stale: true };

  const advisories = simulator.certinAdvisories(14);
  const payload = {
    ok: false,
    simulated: true,
    fetchedAt: new Date().toISOString(),
    source: config.endpoints.certin,
    reason: res.ok
      ? 'CERT-In returned a page with no parsable advisory rows (markup change or WAF interstitial)'
      : `CERT-In endpoint unreachable: ${res.error}`,
    count: advisories.length,
    advisories,
  };
  // Cache the degraded result briefly so a blocked endpoint is not hammered.
  return cache.set(key, payload, Math.min(config.cache.certinTtl, 30 * 60 * 1000));
}

module.exports = { fetchAdvisories, parseAdvisories, stripTags, BROWSER_HEADERS };
