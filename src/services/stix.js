'use strict';

const crypto = require('crypto');

/**
 * STIX 2.1 normalisation layer (OASIS CTI TC, STIX Version 2.1).
 *
 * Produces spec-shaped SDOs/SCOs so CIMI output can be consumed directly by
 * external SOAR/SIEM tooling:
 *   - indicator          (SDO, with a STIX patterning expression)
 *   - observed-data      (SDO, wrapping the SCO)
 *   - ipv4-addr / domain-name / url / file   (SCOs)
 *   - attack-pattern     (SDO, for the MITRE ATT&CK mapping)
 *   - relationship       (SRO, indicator --indicates--> attack-pattern)
 *   - bundle             (STIX bundle object)
 */

const SPEC_VERSION = '2.1';
const NAMESPACE = 'cimi.gh-raisoni.in';

function deterministicUuid(kind, value) {
  const digest = crypto.createHash('sha1').update(`${NAMESPACE}:${kind}:${value}`).digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function stixId(type, value) {
  return `${type}--${deterministicUuid(type, value)}`;
}

function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

function escapeStixString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

/** STIX patterning expression for an indicator. */
function patternFor(value, type) {
  const v = escapeStixString(value);
  switch (type) {
    case 'ip': return `[ipv4-addr:value = '${v}']`;
    case 'domain': return `[domain-name:value = '${v}']`;
    case 'url': return `[url:value = '${v}']`;
    case 'md5': return `[file:hashes.'MD5' = '${v}']`;
    case 'sha1': return `[file:hashes.'SHA-1' = '${v}']`;
    case 'sha256': return `[file:hashes.'SHA-256' = '${v}']`;
    case 'cve': return `[vulnerability:name = '${v}']`;
    default: return `[artifact:payload_bin = '${v}']`;
  }
}

/** Cyber-observable object (SCO) for an indicator value. */
function observableFor(value, type) {
  const base = { type: null, spec_version: SPEC_VERSION, id: null };
  switch (type) {
    case 'ip':
      return { ...base, type: 'ipv4-addr', id: stixId('ipv4-addr', value), value };
    case 'domain':
      return { ...base, type: 'domain-name', id: stixId('domain-name', value), value };
    case 'url':
      return { ...base, type: 'url', id: stixId('url', value), value };
    case 'md5':
      return { ...base, type: 'file', id: stixId('file', value), hashes: { MD5: value } };
    case 'sha1':
      return { ...base, type: 'file', id: stixId('file', value), hashes: { 'SHA-1': value } };
    case 'sha256':
      return { ...base, type: 'file', id: stixId('file', value), hashes: { 'SHA-256': value } };
    default:
      return null;
  }
}

const LABEL_BY_VERDICT = {
  malicious: ['malicious-activity'],
  suspicious: ['anomalous-activity'],
  clean: ['benign'],
  unknown: ['unknown'],
};

/**
 * Build the full set of STIX 2.1 objects for one aggregated lookup result.
 * @returns {object[]} array of STIX objects (indicator, SCO, observed-data,
 *                     attack-patterns, relationships)
 */
function objectsForResult(result) {
  const created = nowIso();
  const objects = [];

  const indicator = {
    type: 'indicator',
    spec_version: SPEC_VERSION,
    id: stixId('indicator', `${result.type}:${result.indicator}`),
    created,
    modified: created,
    name: `${result.type.toUpperCase()} ${result.indicator}`,
    description:
      `Composite verdict "${result.verdict}" (score ${result.score}/100) aggregated by CIMI from ` +
      `${(result.sources || []).filter((s) => s.available).map((s) => s.source).join(', ') || 'no available source'}.`,
    indicator_types: result.verdict === 'clean' ? ['benign'] : ['malicious-activity'],
    pattern: patternFor(result.indicator, result.type),
    pattern_type: 'stix',
    pattern_version: SPEC_VERSION,
    valid_from: created,
    labels: LABEL_BY_VERDICT[result.verdict] || LABEL_BY_VERDICT.unknown,
    confidence: Math.max(0, Math.min(100, Math.round(result.confidence ?? result.score ?? 0))),
    external_references: (result.sources || [])
      .filter((s) => s.link)
      .map((s) => ({ source_name: s.source, url: s.link })),
  };
  objects.push(indicator);

  const observable = observableFor(result.indicator, result.type);
  if (observable) {
    objects.push(observable);
    objects.push({
      type: 'observed-data',
      spec_version: SPEC_VERSION,
      id: stixId('observed-data', `${result.type}:${result.indicator}`),
      created,
      modified: created,
      first_observed: created,
      last_observed: created,
      number_observed: 1,
      object_refs: [observable.id],
    });
  }

  (result.attackTechniques || []).forEach((technique) => {
    const ap = {
      type: 'attack-pattern',
      spec_version: SPEC_VERSION,
      id: stixId('attack-pattern', technique.id),
      created,
      modified: created,
      name: technique.name,
      description: technique.description || '',
      external_references: [
        {
          source_name: 'mitre-attack',
          external_id: technique.id,
          url: `https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`,
        },
      ],
      kill_chain_phases: [
        { kill_chain_name: 'mitre-attack', phase_name: technique.tactic },
      ],
    };
    objects.push(ap);
    objects.push({
      type: 'relationship',
      spec_version: SPEC_VERSION,
      id: stixId('relationship', `${result.indicator}:indicates:${technique.id}`),
      created,
      modified: created,
      relationship_type: 'indicates',
      source_ref: indicator.id,
      target_ref: ap.id,
    });
  });

  return objects;
}

/** Wrap objects in a STIX 2.1 bundle. */
function bundle(objects) {
  const list = Array.isArray(objects) ? objects : [objects];
  const seen = new Set();
  const deduped = list.filter((o) => (o && o.id && !seen.has(o.id) ? seen.add(o.id) : false));
  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    objects: deduped,
  };
}

/** Convenience: full bundle for one aggregated result. */
function bundleForResult(result) {
  return bundle(objectsForResult(result));
}

/** STIX vulnerability SDO for a CERT-In / KEV advisory. */
function vulnerabilityFromAdvisory(advisory) {
  const created = nowIso();
  return {
    type: 'vulnerability',
    spec_version: SPEC_VERSION,
    id: stixId('vulnerability', advisory.id || advisory.cveID),
    created,
    modified: created,
    name: advisory.id || advisory.cveID,
    description: advisory.summary || advisory.shortDescription || advisory.title || '',
    external_references: [
      ...(advisory.cves || []).map((cve) => ({ source_name: 'cve', external_id: cve })),
      ...(advisory.cveID ? [{ source_name: 'cve', external_id: advisory.cveID }] : []),
      ...(advisory.url ? [{ source_name: advisory.source || 'CERT-In', url: advisory.url }] : []),
    ],
  };
}

module.exports = {
  SPEC_VERSION,
  stixId,
  patternFor,
  observableFor,
  objectsForResult,
  bundle,
  bundleForResult,
  vulnerabilityFromAdvisory,
};
