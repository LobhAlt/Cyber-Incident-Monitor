'use strict';

/**
 * MITRE ATT&CK (Enterprise) technique mapping.
 *
 * Maps evidence gathered from the aggregation layer — indicator type, OTX pulse
 * tags, AbuseIPDB report categories and VirusTotal detection families — onto the
 * ATT&CK techniques most commonly associated with that evidence, so an analyst
 * reads behaviour rather than a bare indicator list.
 */

const TECHNIQUES = {
  'T1071.001': { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'command-and-control', description: 'Adversaries communicate with a C2 server using HTTP/HTTPS to blend in with normal web traffic.' },
  'T1071.004': { id: 'T1071.004', name: 'Application Layer Protocol: DNS', tactic: 'command-and-control', description: 'Adversaries use DNS queries and responses to carry command-and-control traffic.' },
  'T1566.001': { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'initial-access', description: 'Adversaries send malicious attachments to gain access to victim systems.' },
  'T1566.002': { id: 'T1566.002', name: 'Phishing: Spearphishing Link', tactic: 'initial-access', description: 'Adversaries send links to malicious sites to gain access to victim systems or credentials.' },
  'T1189': { id: 'T1189', name: 'Drive-by Compromise', tactic: 'initial-access', description: 'Adversaries gain access through a user visiting a compromised or malicious website.' },
  'T1190': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access', description: 'Adversaries exploit an internet-facing application to gain initial access.' },
  'T1110': { id: 'T1110', name: 'Brute Force', tactic: 'credential-access', description: 'Adversaries systematically guess credentials to gain access to accounts.' },
  'T1110.001': { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'credential-access', description: 'Adversaries guess passwords against exposed services such as SSH or RDP.' },
  'T1046': { id: 'T1046', name: 'Network Service Discovery', tactic: 'discovery', description: 'Adversaries scan for listening services to identify exploitable targets.' },
  'T1595.001': { id: 'T1595.001', name: 'Active Scanning: Scanning IP Blocks', tactic: 'reconnaissance', description: 'Adversaries scan IP blocks to gather victim network information.' },
  'T1498': { id: 'T1498', name: 'Network Denial of Service', tactic: 'impact', description: 'Adversaries degrade or block availability of targeted network resources.' },
  'T1486': { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact', description: 'Adversaries encrypt data on target systems to interrupt availability (ransomware).' },
  'T1204.002': { id: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'execution', description: 'An adversary relies on a user opening a malicious file to gain execution.' },
  'T1105': { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'command-and-control', description: 'Adversaries transfer tools or other files from an external system into a victim environment.' },
  'T1555': { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'credential-access', description: 'Adversaries retrieve credentials stored by browsers and password managers (info-stealers).' },
  'T1027': { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defense-evasion', description: 'Adversaries obfuscate executable content to hinder analysis and detection.' },
  'T1090': { id: 'T1090', name: 'Proxy', tactic: 'command-and-control', description: 'Adversaries relay traffic through proxies or anonymising infrastructure.' },
  'T1584': { id: 'T1584', name: 'Compromise Infrastructure', tactic: 'resource-development', description: 'Adversaries compromise third-party infrastructure to stage operations.' },
  'T1583.001': { id: 'T1583.001', name: 'Acquire Infrastructure: Domains', tactic: 'resource-development', description: 'Adversaries register domains used for phishing or command-and-control.' },
  'T1496': { id: 'T1496', name: 'Resource Hijacking', tactic: 'impact', description: 'Adversaries abuse compromised resources, e.g. for cryptomining or botnet activity.' },
  'T1078': { id: 'T1078', name: 'Valid Accounts', tactic: 'defense-evasion', description: 'Adversaries use compromised legitimate credentials to access systems.' },
  'T1568': { id: 'T1568', name: 'Dynamic Resolution', tactic: 'command-and-control', description: 'Adversaries dynamically resolve C2 infrastructure (DGA, fast flux) to evade blocking.' },
};

/** keyword (lower-case, matched as a substring) -> technique IDs */
const KEYWORD_MAP = [
  [['phish', 'spearphish', 'credential-harvest', 'credential harvesting'], ['T1566.002', 'T1566.001', 'T1583.001']],
  [['ransom', 'locker', 'crypt'], ['T1486', 'T1204.002', 'T1027']],
  [['c2', 'c&c', 'command and control', 'cobalt', 'beacon'], ['T1071.001', 'T1105', 'T1568']],
  [['botnet', 'mirai', 'ddos'], ['T1498', 'T1496', 'T1584']],
  [['brute', 'bruteforce', 'ssh', 'rdp'], ['T1110.001', 'T1110', 'T1078']],
  [['scan', 'port scan', 'probe', 'recon'], ['T1046', 'T1595.001']],
  [['stealer', 'redline', 'lokibot', 'agenttesla', 'infostealer'], ['T1555', 'T1027', 'T1071.001']],
  [['trojan', 'rat', 'backdoor', 'remcos', 'asyncrat', 'gh0st'], ['T1105', 'T1071.001', 'T1204.002']],
  [['exploit', 'rce', 'cve-', 'struts', 'log4j', 'injection', 'sql'], ['T1190', 'T1203']],
  [['proxy', 'vpn', 'tor', 'anonym'], ['T1090']],
  [['drive-by', 'exploit kit', 'watering hole'], ['T1189']],
  [['spam', 'web spam', 'blog spam'], ['T1566.002']],
  [['apt', 'espionage', 'targeted'], ['T1071.001', 'T1078', 'T1584']],
  [['upi', 'banking', 'fraud', 'fake app'], ['T1566.002', 'T1555']],
  [['dga', 'fast flux', 'dns'], ['T1071.004', 'T1568']],
  [['dropper', 'loader', 'downloader'], ['T1105', 'T1204.002']],
];

const BASELINE_BY_TYPE = {
  ip: ['T1071.001'],
  domain: ['T1071.004', 'T1583.001'],
  url: ['T1566.002'],
  md5: ['T1204.002'],
  sha1: ['T1204.002'],
  sha256: ['T1204.002'],
  cve: ['T1190'],
};

// T1203 is referenced above but not in the main table — add it.
TECHNIQUES.T1203 = {
  id: 'T1203',
  name: 'Exploitation for Client Execution',
  tactic: 'execution',
  description: 'Adversaries exploit software vulnerabilities in client applications to execute code.',
};

/**
 * @param {object} input
 * @param {string} input.type      indicator type
 * @param {string} input.verdict   composite verdict
 * @param {string[]} input.tags    OTX tags, AbuseIPDB categories, VT families, …
 * @returns {object[]} deduplicated technique objects with the matched evidence
 */
function mapTechniques({ type, verdict, tags = [] }) {
  // ATT&CK describes adversary behaviour. An indicator that no source flagged
  // has no observed behaviour to describe, so incidental keyword matches (a
  // pulse title, a hosting-provider usage type) must not become a technique
  // mapping — that would tell the analyst a benign IP is running ransomware.
  if (verdict === 'clean' || verdict === 'unknown') return [];

  const hay = tags.map((t) => String(t).toLowerCase());
  const scored = new Map();

  function add(id, evidence) {
    const technique = TECHNIQUES[id];
    if (!technique) return;
    const existing = scored.get(id);
    if (existing) {
      if (evidence && !existing.evidence.includes(evidence)) existing.evidence.push(evidence);
      existing.weight += 1;
    } else {
      scored.set(id, { ...technique, evidence: evidence ? [evidence] : [], weight: 1 });
    }
  }

  KEYWORD_MAP.forEach(([keywords, ids]) => {
    const hit = hay.find((tag) => keywords.some((kw) => tag.includes(kw)));
    if (hit) ids.forEach((id) => add(id, hit));
  });

  // Baseline techniques only when the indicator is actually flagged.
  if (verdict === 'malicious' || verdict === 'suspicious') {
    (BASELINE_BY_TYPE[type] || []).forEach((id) => add(id, `${type} indicator`));
  }

  return Array.from(scored.values())
    .sort((a, b) => b.weight - a.weight || a.id.localeCompare(b.id))
    .slice(0, 8)
    .map(({ weight, ...rest }) => rest);
}

module.exports = { mapTechniques, TECHNIQUES };
