'use strict';

const crypto = require('crypto');

/**
 * Deterministic offline intelligence simulator.
 *
 * Used when a provider API key is absent (or FORCE_DEMO_MODE=true) so the whole
 * platform remains demonstrable without credentials. Output is derived from a
 * SHA-256 of the indicator, so the SAME indicator always yields the SAME
 * verdict — results are reproducible and safe to show in a viva/demo.
 *
 * Everything produced here is explicitly flagged `simulated: true` and the UI
 * renders a "SIMULATED" badge, so it can never be mistaken for live data.
 */

const MALWARE_FAMILIES = [
  'Emotet', 'AgentTesla', 'RedLine Stealer', 'Mirai', 'Qakbot',
  'Cobalt Strike', 'AsyncRAT', 'Lokibot', 'Gh0st RAT', 'Remcos',
];

const CAMPAIGN_TAGS = [
  'phishing', 'banking-trojan', 'upi-fraud', 'credential-harvesting',
  'ransomware', 'botnet', 'c2', 'apt', 'scanning', 'exploit-kit',
];

const COUNTRIES = [
  { code: 'IN', name: 'India' }, { code: 'CN', name: 'China' },
  { code: 'RU', name: 'Russia' }, { code: 'US', name: 'United States' },
  { code: 'NL', name: 'Netherlands' }, { code: 'BR', name: 'Brazil' },
  { code: 'VN', name: 'Vietnam' }, { code: 'PK', name: 'Pakistan' },
  { code: 'DE', name: 'Germany' }, { code: 'SG', name: 'Singapore' },
];

const ISPS = [
  'Bharti Airtel Ltd', 'Reliance Jio Infocomm', 'DigitalOcean LLC',
  'Hetzner Online GmbH', 'Alibaba Cloud', 'OVH SAS', 'Contabo GmbH',
  'Amazon Data Services', 'Chinanet Backbone', 'M247 Europe',
];

/** Stable pseudo-random generator seeded by the indicator itself. */
function seeded(value) {
  const digest = crypto.createHash('sha256').update(String(value)).digest();
  let cursor = 0;
  return {
    /** float in [0,1) */
    next() {
      const byte = digest[cursor % digest.length];
      const byte2 = digest[(cursor + 7) % digest.length];
      cursor += 1;
      return ((byte << 8) | byte2) / 65536;
    },
    int(maxExclusive) {
      return Math.floor(this.next() * maxExclusive);
    },
    pick(list) {
      return list[this.int(list.length)];
    },
    sample(list, count) {
      const copy = [...list];
      const out = [];
      for (let i = 0; i < count && copy.length; i += 1) {
        out.push(copy.splice(this.int(copy.length), 1)[0]);
      }
      return out;
    },
  };
}

function riskBand(rng) {
  const roll = rng.next();
  if (roll < 0.45) return 'clean';
  if (roll < 0.72) return 'suspicious';
  return 'malicious';
}

function virustotal(value, type) {
  const rng = seeded(`vt:${value}`);
  const band = riskBand(rng);
  const total = 70 + rng.int(8);
  const malicious = band === 'clean' ? 0 : band === 'suspicious' ? 1 + rng.int(3) : 8 + rng.int(28);
  const suspicious = band === 'clean' ? rng.int(2) : 1 + rng.int(4);

  return {
    source: 'VirusTotal',
    available: true,
    simulated: true,
    score: Math.min(100, Math.round((malicious / total) * 100 * 2.4)),
    verdict: band,
    stats: {
      malicious,
      suspicious,
      harmless: total - malicious - suspicious,
      undetected: rng.int(6),
      totalEngines: total,
    },
    details: {
      reputation: band === 'malicious' ? -(10 + rng.int(80)) : rng.int(20),
      firstSubmission: new Date(Date.now() - rng.int(900) * 86_400_000).toISOString(),
      lastAnalysis: new Date(Date.now() - rng.int(72) * 3_600_000).toISOString(),
      ...(type === 'ip' || type === 'domain'
        ? { country: rng.pick(COUNTRIES).code, asOwner: rng.pick(ISPS) }
        : { meaningfulName: `${rng.pick(MALWARE_FAMILIES)}.sample.bin`, fileType: 'Win32 EXE', size: 40_960 + rng.int(4_000_000) }),
      detectedFamilies: band === 'clean' ? [] : rng.sample(MALWARE_FAMILIES, 1 + rng.int(3)),
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

function abuseipdb(value) {
  const rng = seeded(`abuse:${value}`);
  const band = riskBand(rng);
  const confidence = band === 'clean' ? rng.int(8) : band === 'suspicious' ? 20 + rng.int(40) : 70 + rng.int(31);
  const country = rng.pick(COUNTRIES);

  return {
    source: 'AbuseIPDB',
    available: true,
    simulated: true,
    score: confidence,
    verdict: band,
    stats: {
      abuseConfidenceScore: confidence,
      totalReports: band === 'clean' ? rng.int(3) : 5 + rng.int(400),
      distinctReporters: band === 'clean' ? rng.int(2) : 2 + rng.int(60),
    },
    details: {
      countryCode: country.code,
      countryName: country.name,
      isp: rng.pick(ISPS),
      usageType: rng.pick(['Data Center/Web Hosting/Transit', 'Fixed Line ISP', 'Mobile ISP', 'Commercial']),
      isPublic: true,
      isWhitelisted: band === 'clean' && rng.next() > 0.8,
      lastReportedAt: band === 'clean' ? null : new Date(Date.now() - rng.int(30) * 86_400_000).toISOString(),
      categories: band === 'clean' ? [] : rng.sample(['SSH Bruteforce', 'Port Scan', 'Web Spam', 'Phishing', 'DDoS Source', 'Hacking'], 1 + rng.int(3)),
    },
    link: `https://www.abuseipdb.com/check/${value}`,
  };
}

function otx(value, type) {
  const rng = seeded(`otx:${value}`);
  const band = riskBand(rng);
  const pulseCount = band === 'clean' ? rng.int(2) : 1 + rng.int(12);
  const tags = band === 'clean' ? [] : rng.sample(CAMPAIGN_TAGS, 1 + rng.int(4));
  const families = band === 'clean' ? [] : rng.sample(MALWARE_FAMILIES, 1 + rng.int(2));

  const pulses = Array.from({ length: Math.min(pulseCount, 6) }, (_, i) => {
    const prng = seeded(`otx:${value}:pulse:${i}`);
    return {
      id: crypto.createHash('md5').update(`${value}:${i}`).digest('hex').slice(0, 24),
      name: `${prng.pick(families.length ? families : MALWARE_FAMILIES)} ${prng.pick(['infrastructure', 'campaign', 'C2 servers', 'delivery domains', 'IOC set'])} ${2025 + prng.int(2)}`,
      author: prng.pick(['AlienVault', 'CyberThreatIntel', 'IN-SOC-Share', 'OTX Community', 'BlueTeamOps']),
      created: new Date(Date.now() - prng.int(400) * 86_400_000).toISOString(),
      tags: prng.sample(CAMPAIGN_TAGS, 2 + prng.int(3)),
      adversary: prng.next() > 0.7 ? prng.pick(['APT41', 'SideWinder', 'Transparent Tribe', 'Lazarus', 'FIN7']) : '',
    };
  });

  return {
    source: 'AlienVault OTX',
    available: true,
    simulated: true,
    score: Math.min(100, pulseCount * 12 + (band === 'malicious' ? 25 : 0)),
    verdict: band,
    stats: { pulseCount, tagCount: tags.length },
    details: {
      pulses,
      tags,
      malwareFamilies: families,
      indicatorType: type,
      validation: [],
    },
    link:
      type === 'ip'
        ? `https://otx.alienvault.com/indicator/ip/${value}`
        : type === 'domain'
        ? `https://otx.alienvault.com/indicator/domain/${value}`
        : `https://otx.alienvault.com/indicator/file/${value}`,
  };
}

/** A small, realistic CERT-In-style advisory set used when the scraper is blocked. */
function certinAdvisories(count = 12) {
  const templates = [
    ['Multiple Vulnerabilities in Google Chrome', 'High', 'Browser'],
    ['Remote Code Execution Vulnerability in Apache Struts', 'Critical', 'Application'],
    ['Multiple Vulnerabilities in Android OS', 'High', 'Operating System'],
    ['Privilege Escalation Vulnerability in Linux Kernel', 'High', 'Operating System'],
    ['Phishing Campaign Targeting Indian Banking Customers', 'High', 'Threat Advisory'],
    ['Vulnerability in Cisco IOS XE Web UI', 'Critical', 'Network Device'],
    ['Multiple Vulnerabilities in Microsoft Products', 'Critical', 'Application'],
    ['Ransomware Targeting Indian Healthcare Infrastructure', 'Critical', 'Threat Advisory'],
    ['SQL Injection Vulnerability in WordPress Plugins', 'Medium', 'CMS'],
    ['UPI-themed Mobile Malware Distribution Campaign', 'High', 'Mobile'],
    ['Vulnerability in Fortinet FortiOS SSL-VPN', 'Critical', 'Network Device'],
    ['Multiple Vulnerabilities in Mozilla Firefox', 'Medium', 'Browser'],
    ['Data Exfiltration Campaign Against Indian Government Entities', 'Critical', 'Threat Advisory'],
    ['Vulnerability in VMware vCenter Server', 'High', 'Virtualization'],
  ];

  return Array.from({ length: Math.min(count, templates.length) }, (_, i) => {
    const rng = seeded(`certin:${i}:${templates[i][0]}`);
    const daysAgo = i * 3 + rng.int(3);
    const published = new Date(Date.now() - daysAgo * 86_400_000);
    return {
      id: `CIVN-2026-${String(100 + i).padStart(4, '0')}`,
      title: templates[i][0],
      severity: templates[i][1],
      category: templates[i][2],
      publishedAt: published.toISOString(),
      summary: `CERT-In has observed ${templates[i][0].toLowerCase()} affecting systems deployed in Indian cyberspace. Successful exploitation could allow an attacker to ${rng.pick([
        'execute arbitrary code',
        'obtain sensitive information',
        'escalate privileges',
        'cause a denial of service',
        'bypass security restrictions',
      ])} on the targeted system.`,
      cves: Array.from({ length: 1 + rng.int(3) }, (__, k) =>
        `CVE-${2025 + rng.int(2)}-${String(1000 + rng.int(48999) + k).padStart(5, '0')}`
      ),
      source: 'CERT-In',
      url: 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01',
      simulated: true,
    };
  });
}

module.exports = { virustotal, abuseipdb, otx, certinAdvisories, seeded, MALWARE_FAMILIES, CAMPAIGN_TAGS, COUNTRIES };
