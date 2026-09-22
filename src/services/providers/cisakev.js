'use strict';

const config = require('../../config');
const cache = require('../cache');
const { request } = require('../../utils/http');

const FALLBACK = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities (offline sample)',
  catalogVersion: 'offline-sample',
  dateReleased: null,
  count: 10,
  vulnerabilities: [
    ['CVE-2021-44228', 'Apache', 'Log4j2', 'Apache Log4j2 Remote Code Execution Vulnerability', '2021-12-10', 'known'],
    ['CVE-2023-4863', 'Google', 'Chrome', 'Google Chrome libwebp Heap Buffer Overflow', '2023-09-13', 'known'],
    ['CVE-2023-34362', 'Progress', 'MOVEit Transfer', 'Progress MOVEit Transfer SQL Injection Vulnerability', '2023-06-01', 'known'],
    ['CVE-2024-3400', 'Palo Alto Networks', 'PAN-OS', 'PAN-OS GlobalProtect Command Injection Vulnerability', '2024-04-12', 'known'],
    ['CVE-2023-20198', 'Cisco', 'IOS XE', 'Cisco IOS XE Web UI Privilege Escalation Vulnerability', '2023-10-16', 'known'],
    ['CVE-2022-22965', 'VMware', 'Spring Framework', 'Spring Framework Remote Code Execution (Spring4Shell)', '2022-04-04', 'known'],
    ['CVE-2018-13379', 'Fortinet', 'FortiOS', 'Fortinet FortiOS SSL VPN Path Traversal Vulnerability', '2019-05-24', 'known'],
    ['CVE-2023-27997', 'Fortinet', 'FortiOS', 'Fortinet FortiOS Heap-Based Buffer Overflow Vulnerability', '2023-06-11', 'known'],
    ['CVE-2021-26855', 'Microsoft', 'Exchange Server', 'Microsoft Exchange Server SSRF Vulnerability (ProxyLogon)', '2021-03-02', 'known'],
    ['CVE-2024-21412', 'Microsoft', 'Windows', 'Windows SmartScreen Security Feature Bypass Vulnerability', '2024-02-13', 'known'],
  ].map(([cveID, vendorProject, product, vulnerabilityName, dateAdded, known]) => ({
    cveID,
    vendorProject,
    product,
    vulnerabilityName,
    dateAdded,
    shortDescription: `${vulnerabilityName}. Listed in the CISA Known Exploited Vulnerabilities catalog; apply vendor mitigations per instructions.`,
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: dateAdded,
    knownRansomwareCampaignUse: known === 'known' ? 'Known' : 'Unknown',
    notes: '',
  })),
  simulated: true,
};

async function catalog() {
  const key = 'cisa:kev:catalog';
  const cached = cache.get(key);
  if (cached) return cached;

  const res = await request(config.endpoints.cisaKev, { timeoutMs: 20000 });

  if (!res.ok || !res.data || !Array.isArray(res.data.vulnerabilities)) {
    const stale = cache.getStale(key);
    if (stale) return stale;
    return { ...FALLBACK, error: res.error || 'CISA KEV feed unavailable' };
  }

  const value = {
    title: res.data.title,
    catalogVersion: res.data.catalogVersion,
    dateReleased: res.data.dateReleased,
    count: res.data.count || res.data.vulnerabilities.length,
    vulnerabilities: res.data.vulnerabilities,
    simulated: false,
  };
  return cache.set(key, value, config.cache.cisaTtl);
}

/** Look up a single CVE in the KEV catalog. */
async function lookupCve(cve) {
  const data = await catalog();
  const needle = String(cve || '').toUpperCase();
  const hit = (data.vulnerabilities || []).find((v) => (v.cveID || '').toUpperCase() === needle);

  if (!hit) {
    return {
      source: 'CISA KEV',
      available: true,
      simulated: Boolean(data.simulated),
      score: 0,
      verdict: 'clean',
      stats: { inKevCatalog: false },
      details: { catalogVersion: data.catalogVersion, note: 'CVE is not in the Known Exploited Vulnerabilities catalog' },
      link: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    };
  }

  const ransomware = String(hit.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
  return {
    source: 'CISA KEV',
    available: true,
    simulated: Boolean(data.simulated),
    score: ransomware ? 100 : 85,
    verdict: 'malicious',
    stats: { inKevCatalog: true },
    details: {
      vendorProject: hit.vendorProject,
      product: hit.product,
      vulnerabilityName: hit.vulnerabilityName,
      dateAdded: hit.dateAdded,
      dueDate: hit.dueDate,
      requiredAction: hit.requiredAction,
      shortDescription: hit.shortDescription,
      knownRansomwareCampaignUse: hit.knownRansomwareCampaignUse,
      catalogVersion: data.catalogVersion,
    },
    link: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  };
}

/** Recent additions, newest first — used by the Threat Feeds module. */
async function recent(limit = 25, query = '') {
  const data = await catalog();
  const needle = String(query || '').trim().toLowerCase();
  const list = (data.vulnerabilities || [])
    .filter((v) =>
      !needle ||
      [v.cveID, v.vendorProject, v.product, v.vulnerabilityName]
        .join(' ')
        .toLowerCase()
        .includes(needle)
    )
    .slice()
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)))
    .slice(0, limit);

  return {
    catalogVersion: data.catalogVersion,
    dateReleased: data.dateReleased,
    total: data.count,
    simulated: Boolean(data.simulated),
    error: data.error || null,
    items: list,
  };
}

module.exports = { catalog, lookupCve, recent };
