'use strict';

const express = require('express');
const certin = require('../services/providers/certin');
const cisakev = require('../services/providers/cisakev');
const otx = require('../services/providers/otx');
const stix = require('../services/stix');
const store = require('../services/store');
const cache = require('../services/cache');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();
router.use(requireAuth);

/** GET /api/feeds/certin */
router.get(
  '/certin',
  asyncHandler(async (req, res) => {
    const force = req.query.refresh === 'true';
    const data = await certin.fetchAdvisories({ force });
    const limit = Math.min(Number(req.query.limit) || 25, 100);
    const severity = req.query.severity;
    const query = String(req.query.q || '').toLowerCase();

    let items = data.advisories || [];
    if (severity) items = items.filter((a) => a.severity.toLowerCase() === severity.toLowerCase());
    if (query) {
      items = items.filter((a) =>
        `${a.id} ${a.title} ${a.summary} ${(a.cves || []).join(' ')}`.toLowerCase().includes(query)
      );
    }

    // Persist the latest snapshot so the feed survives restarts.
    await store.write('advisories', (data.advisories || []).slice(0, 100)).catch(() => {});

    res.json({
      source: 'CERT-In',
      live: data.ok === true,
      simulated: Boolean(data.simulated),
      reason: data.reason || null,
      fetchedAt: data.fetchedAt,
      cached: Boolean(data.cached),
      total: items.length,
      items: items.slice(0, limit),
    });
  })
);

/** GET /api/feeds/kev */
router.get(
  '/kev',
  asyncHandler(async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 25, 200);
    const data = await cisakev.recent(limit, req.query.q || '');
    res.json({ source: 'CISA KEV', live: !data.simulated, ...data });
  })
);

/** GET /api/feeds/otx */
router.get(
  '/otx',
  asyncHandler(async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 20, 50);
    const pulses = await otx.recentPulses(limit);
    res.json({
      source: 'AlienVault OTX',
      live: pulses.some((p) => p.simulated === false),
      simulated: pulses.every((p) => p.simulated !== false),
      total: pulses.length,
      items: pulses,
    });
  })
);

/** GET /api/feeds/health — feed health + data-quality scoring */
router.get(
  '/health',
  asyncHandler(async (req, res) => {
    const [certinData, kevData, pulses] = await Promise.all([
      certin.fetchAdvisories().catch(() => ({ ok: false, advisories: [], reason: 'fetch failed' })),
      cisakev.recent(5).catch(() => ({ items: [], simulated: true })),
      otx.recentPulses(5).catch(() => []),
    ]);

    function quality(count, live, freshness) {
      let score = 0;
      if (count > 0) score += 40;
      if (count >= 10) score += 15;
      if (live) score += 30;
      if (freshness !== null && freshness <= 7) score += 15;
      else if (freshness !== null && freshness <= 30) score += 8;
      return Math.min(100, score);
    }

    const newestCertin = (certinData.advisories || [])[0];
    const certinAgeDays = newestCertin
      ? Math.round((Date.now() - new Date(newestCertin.publishedAt).getTime()) / 86_400_000)
      : null;
    const newestKev = (kevData.items || [])[0];
    const kevAgeDays = newestKev
      ? Math.round((Date.now() - new Date(newestKev.dateAdded).getTime()) / 86_400_000)
      : null;

    res.json({
      generatedAt: new Date().toISOString(),
      cache: cache.snapshot(),
      feeds: [
        {
          name: 'CERT-In Advisories',
          status: certinData.ok ? 'live' : 'degraded',
          live: Boolean(certinData.ok),
          items: (certinData.advisories || []).length,
          newestAgeDays: certinAgeDays,
          qualityScore: quality((certinData.advisories || []).length, certinData.ok, certinAgeDays),
          note: certinData.reason || 'Scraped from CERT-In servlet endpoint',
        },
        {
          name: 'CISA Known Exploited Vulnerabilities',
          status: kevData.simulated ? 'degraded' : 'live',
          live: !kevData.simulated,
          items: kevData.total || (kevData.items || []).length,
          newestAgeDays: kevAgeDays,
          qualityScore: quality((kevData.items || []).length, !kevData.simulated, kevAgeDays),
          note: kevData.error || `Catalog version ${kevData.catalogVersion || 'unknown'}`,
        },
        {
          name: 'AlienVault OTX Pulses',
          status: pulses.length && pulses.some((p) => p.simulated === false) ? 'live' : 'degraded',
          live: pulses.some((p) => p.simulated === false),
          items: pulses.length,
          newestAgeDays: null,
          qualityScore: quality(pulses.length, pulses.some((p) => p.simulated === false), null),
          note: pulses.some((p) => p.simulated === false)
            ? 'Subscribed pulses'
            : 'No OTX API key configured — simulated pulses',
        },
      ],
    });
  })
);

/** GET /api/feeds/certin/stix — advisories as a STIX 2.1 bundle */
router.get(
  '/certin/stix',
  asyncHandler(async (req, res) => {
    const data = await certin.fetchAdvisories();
    const objects = (data.advisories || []).map((a) => stix.vulnerabilityFromAdvisory(a));
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="cimi-certin-stix.json"');
    res.send(JSON.stringify(stix.bundle(objects), null, 2));
  })
);

module.exports = router;
