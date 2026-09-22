'use strict';

const IPV4 =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'<>\\)\]]+/gi;
const DOMAIN_RE =
  /\b(?=.{4,253}\b)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|in|co|io|gov|edu|info|biz|ru|cn|xyz|top|online|site|club|shop|app|dev|me|tk|ml|ga|cf|pw|us|uk|de|fr|jp|br|ir|pk|bd|lk|np))\b/gi;
const MD5_RE = /\b[a-f0-9]{32}\b/gi;
const SHA1_RE = /\b[a-f0-9]{40}\b/gi;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

const PRIVATE_V4 =
  /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|22[4-9]\.|2[3-5]\d\.)/;

/** Detect the STIX-relevant type of a single indicator string. */
function detectType(rawValue) {
  const value = String(rawValue || '').trim();
  if (!value) return 'unknown';

  if (/^https?:\/\//i.test(value)) return 'url';
  if (new RegExp(`^${IPV4.source}$`).test(value)) return 'ip';
  if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
  if (/^CVE-\d{4}-\d{4,7}$/i.test(value)) return 'cve';
  if (/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(value)) {
    return 'domain';
  }
  return 'unknown';
}

function isHash(type) {
  return type === 'md5' || type === 'sha1' || type === 'sha256';
}

function normalise(value, type) {
  const v = String(value || '').trim();
  if (isHash(type)) return v.toLowerCase();
  if (type === 'domain') return v.toLowerCase().replace(/\.$/, '');
  if (type === 'cve') return v.toUpperCase();
  return v;
}

function isPublicIp(ip) {
  return !PRIVATE_V4.test(ip);
}

function uniq(list) {
  return Array.from(new Set(list));
}

/**
 * Extract every indicator found in an arbitrary blob of log text.
 * URLs are extracted first, then their hostnames are excluded from the
 * bare-domain sweep so the same host is not reported twice.
 */
function extractFromText(text) {
  const body = String(text || '');

  const urls = uniq((body.match(URL_RE) || []).map((u) => u.replace(/[.,;:)\]}'"]+$/, '')));
  const ips = uniq(body.match(IPV4) || []).filter(isPublicIp);
  const sha256 = uniq((body.match(SHA256_RE) || []).map((h) => h.toLowerCase()));
  const sha1 = uniq((body.match(SHA1_RE) || []).map((h) => h.toLowerCase())).filter(
    (h) => !sha256.some((s) => s.includes(h))
  );
  const md5 = uniq((body.match(MD5_RE) || []).map((h) => h.toLowerCase())).filter(
    (h) => !sha256.some((s) => s.includes(h)) && !sha1.some((s) => s.includes(h))
  );
  const cves = uniq((body.match(CVE_RE) || []).map((c) => c.toUpperCase()));

  const urlHosts = new Set(
    urls
      .map((u) => {
        try {
          return new URL(u).hostname.toLowerCase();
        } catch {
          return null;
        }
      })
      .filter(Boolean)
  );

  const domains = uniq((body.match(DOMAIN_RE) || []).map((d) => d.toLowerCase())).filter(
    (d) => !urlHosts.has(d) && !new RegExp(`^${IPV4.source}$`).test(d)
  );

  return { ips, domains, urls, md5, sha1, sha256, cves };
}

function flattenExtraction(extracted) {
  const out = [];
  extracted.ips.forEach((v) => out.push({ value: v, type: 'ip' }));
  extracted.domains.forEach((v) => out.push({ value: v, type: 'domain' }));
  extracted.urls.forEach((v) => out.push({ value: v, type: 'url' }));
  extracted.sha256.forEach((v) => out.push({ value: v, type: 'sha256' }));
  extracted.sha1.forEach((v) => out.push({ value: v, type: 'sha1' }));
  extracted.md5.forEach((v) => out.push({ value: v, type: 'md5' }));
  return out;
}

module.exports = {
  detectType,
  normalise,
  isHash,
  isPublicIp,
  extractFromText,
  flattenExtraction,
  patterns: { IPV4, URL_RE, DOMAIN_RE, MD5_RE, SHA1_RE, SHA256_RE, CVE_RE },
};
