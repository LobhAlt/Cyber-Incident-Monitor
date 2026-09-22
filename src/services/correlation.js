'use strict';

const aggregator = require('./aggregator');
const store = require('./store');

/**
 * Threat correlation: group indicators that share OTX pulses, tags, malware
 * families, ASN/country or ATT&CK techniques, and emit a relationship network
 * (nodes + edges) that the frontend renders as a force-free radial graph.
 */

function signalsFor(result) {
  const pulses = new Set();
  const tags = new Set();
  const families = new Set();

  (result.sources || []).forEach((s) => {
    if (!s || !s.details) return;
    (s.details.pulses || []).forEach((p) => {
      if (p && p.id) pulses.add(`pulse:${p.id}`);
    });
    (s.details.tags || []).forEach((t) => tags.add(`tag:${String(t).toLowerCase()}`));
    (s.details.malwareFamilies || []).forEach((m) => families.add(`family:${String(m).toLowerCase()}`));
    (s.details.detectedFamilies || []).forEach((m) => families.add(`family:${String(m).toLowerCase()}`));
  });

  (result.attackTechniques || []).forEach((t) => tags.add(`attack:${t.id}`));
  if (result.geo && result.geo.countryCode) tags.add(`geo:${result.geo.countryCode}`);

  return { pulses, tags, families, all: new Set([...pulses, ...tags, ...families]) };
}

function jaccard(a, b) {
  if (a.size === 0 || b.size === 0) return 0;
  let shared = 0;
  a.forEach((v) => {
    if (b.has(v)) shared += 1;
  });
  return shared / (a.size + b.size - shared);
}

function labelForSignal(signal) {
  const [kind, ...rest] = signal.split(':');
  const value = rest.join(':');
  switch (kind) {
    case 'pulse': return `OTX pulse ${value.slice(0, 8)}`;
    case 'tag': return `tag "${value}"`;
    case 'family': return `family ${value}`;
    case 'attack': return `ATT&CK ${value}`;
    case 'geo': return `geo ${value}`;
    default: return value;
  }
}

/**
 * @param {string[]} values indicators to correlate (max 25)
 * @param {object} options  { threshold }
 */
async function correlate(values, options = {}) {
  const threshold = typeof options.threshold === 'number' ? options.threshold : 0.12;
  const results = await aggregator.lookupBulk(values);
  const enriched = results.map((r) => ({ result: r, signals: signalsFor(r) }));

  const nodes = enriched.map(({ result }) => ({
    id: result.indicator,
    type: result.type,
    verdict: result.verdict,
    score: result.score,
    country: result.geo ? result.geo.countryCode : null,
    techniques: (result.attackTechniques || []).map((t) => t.id),
  }));

  const edges = [];
  for (let i = 0; i < enriched.length; i += 1) {
    for (let j = i + 1; j < enriched.length; j += 1) {
      const a = enriched[i];
      const b = enriched[j];
      const shared = [...a.signals.all].filter((s) => b.signals.all.has(s));
      if (shared.length === 0) continue;

      // A single weak signal (a shared country, or one generic ATT&CK technique)
      // is not evidence of a campaign. An edge needs either a strong signal —
      // a shared OTX pulse or malware family — or at least two shared signals.
      const strong = shared.some((s) => s.indexOf('pulse:') === 0 || s.indexOf('family:') === 0);
      if (!strong && shared.filter((s) => s.indexOf('geo:') !== 0).length < 2) continue;

      const weight = jaccard(a.signals.all, b.signals.all);
      if (!strong && weight < threshold) continue;
      edges.push({
        source: a.result.indicator,
        target: b.result.indicator,
        weight: Math.round(weight * 100) / 100,
        sharedCount: shared.length,
        shared: shared.slice(0, 6).map(labelForSignal),
      });
    }
  }

  // Connected components => likely campaigns.
  const adjacency = new Map(nodes.map((n) => [n.id, []]));
  edges.forEach((e) => {
    adjacency.get(e.source).push(e.target);
    adjacency.get(e.target).push(e.source);
  });

  const visited = new Set();
  const clusters = [];
  nodes.forEach((node) => {
    if (visited.has(node.id)) return;
    const stack = [node.id];
    const members = [];
    visited.add(node.id);
    while (stack.length) {
      const current = stack.pop();
      members.push(current);
      (adjacency.get(current) || []).forEach((next) => {
        if (!visited.has(next)) {
          visited.add(next);
          stack.push(next);
        }
      });
    }

    const memberResults = enriched.filter((e) => members.includes(e.result.indicator));
    const sharedSignals = memberResults.length > 1
      ? [...memberResults[0].signals.all].filter((s) =>
          memberResults.every((m) => m.signals.all.has(s))
        )
      : [];
    const maxScore = Math.max(...memberResults.map((m) => m.result.score || 0), 0);

    clusters.push({
      id: `cluster-${clusters.length + 1}`,
      size: members.length,
      members,
      isolated: members.length === 1,
      maxScore,
      severity: aggregator.severityFromScore(maxScore),
      sharedSignals: sharedSignals.slice(0, 8).map(labelForSignal),
      label:
        members.length === 1
          ? `Isolated indicator: ${members[0]}`
          : `Campaign cluster of ${members.length} indicators` +
            (sharedSignals.length ? ` sharing ${labelForSignal(sharedSignals[0])}` : ''),
    });
  });

  clusters.sort((a, b) => b.size - a.size || b.maxScore - a.maxScore);

  return {
    generatedAt: new Date().toISOString(),
    threshold,
    summary: {
      indicators: nodes.length,
      relationships: edges.length,
      clusters: clusters.filter((c) => !c.isolated).length,
      isolated: clusters.filter((c) => c.isolated).length,
      ...aggregator.summarise(results),
    },
    nodes,
    edges,
    clusters,
    results,
  };
}

/** Correlate the analyst's own recent lookup history (no new API calls needed). */
async function correlateHistory(limit = 25) {
  const history = await store.read('iocHistory');
  const values = Array.from(new Set(history.slice(0, limit * 2).map((h) => h.indicator))).slice(0, limit);
  if (values.length < 2) {
    return {
      generatedAt: new Date().toISOString(),
      threshold: 0.12,
      summary: { indicators: values.length, relationships: 0, clusters: 0, isolated: values.length, total: values.length, malicious: 0, suspicious: 0, clean: 0, unknown: 0, averageScore: 0, highestScore: 0 },
      nodes: [], edges: [], clusters: [], results: [],
      note: 'Run at least two IoC lookups first — correlation works on your lookup history.',
    };
  }
  return correlate(values);
}

module.exports = { correlate, correlateHistory, signalsFor };
