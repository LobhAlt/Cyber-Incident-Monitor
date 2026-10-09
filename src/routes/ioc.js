'use strict';

const express = require('express');
const config = require('../config');
const aggregator = require('../services/aggregator');
const stix = require('../services/stix');
const store = require('../services/store');
const audit = require('../services/audit');
const indicatorUtils = require('../utils/indicators');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();
router.use(requireAuth);

/** POST /api/ioc/lookup  — single indicator */
router.post(
  '/lookup',
  asyncHandler(async (req, res) => {
    const { indicator, type } = req.body || {};
    if (!indicator || typeof indicator !== 'string') {
      return res.status(400).json({ error: 'Field "indicator" is required' });
    }
    if (indicator.length > 2048) {
      return res.status(400).json({ error: 'Indicator is too long' });
    }

    const result = await aggregator.lookupIndicator(indicator, { type });
    await aggregator.recordHistory(result, req.user);
    await audit.log('ioc.lookup', { req, target: result.indicator, detail: `${result.verdict} (${result.score})` });
    return res.json(result);
  })
);

/** POST /api/ioc/bulk — up to 25 indicators */
router.post(
  '/bulk',
  asyncHandler(async (req, res) => {
    let { indicators: list } = req.body || {};
    if (typeof list === 'string') {
      list = list.split(/[\s,;]+/);
    }
    if (!Array.isArray(list) || list.length === 0) {
      return res.status(400).json({ error: 'Field "indicators" must be a non-empty array or delimited string' });
    }

    const cleaned = Array.from(new Set(list.map((v) => String(v || '').trim()).filter(Boolean)));
    if (cleaned.length > config.limits.bulkMax) {
      return res.status(400).json({
        error: `Bulk lookup is limited to ${config.limits.bulkMax} indicators per request (received ${cleaned.length})`,
      });
    }

    const results = await aggregator.lookupBulk(cleaned);
    for (const result of results) {
      if (!result.error) await aggregator.recordHistory(result, req.user);
    }
    await audit.log('ioc.bulk_lookup', { req, detail: `${cleaned.length} indicators` });

    return res.json({
      requested: cleaned.length,
      summary: aggregator.summarise(results),
      results,
      queriedAt: new Date().toISOString(),
    });
  })
);

/** GET /api/ioc/detect?value=... — type detection helper */
router.get('/detect', (req, res) => {
  const value = String(req.query.value || '');
  const type = indicatorUtils.detectType(value);
  res.json({ value, type, supported: type !== 'unknown' });
});

/** GET /api/ioc/history */
router.get(
  '/history',
  asyncHandler(async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 50, 500);
    const verdict = req.query.verdict;
    const history = await store.read('iocHistory');
    const filtered = verdict ? history.filter((h) => h.verdict === verdict) : history;
    res.json({ total: filtered.length, items: filtered.slice(0, limit) });
  })
);

/**
 * DELETE /api/ioc/history: analysts clear their own lookups; admins may pass
 * ?scope=all to clear everyone's.
 */
router.delete(
  '/history',
  asyncHandler(async (req, res) => {
    const all = req.query.scope === 'all';
    if (all && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only an admin can clear every analyst\'s history' });
    }
    let removed = 0;
    await store.update('iocHistory', (list) => {
      const kept = all ? [] : list.filter((h) => h.userId !== req.user.sub);
      removed = list.length - kept.length;
      return kept;
    });
    await audit.log('ioc.history_cleared', { req, detail: `${all ? 'all analysts' : 'own history'}, ${removed} entries` });
    return res.json({ cleared: true, removed, scope: all ? 'all' : 'own' });
  })
);

/** POST /api/ioc/stix — STIX 2.1 bundle for one or more indicators */
router.post(
  '/stix',
  asyncHandler(async (req, res) => {
    let { indicators: list, indicator } = req.body || {};
    if (indicator) list = [indicator];
    if (typeof list === 'string') list = list.split(/[\s,;]+/);
    if (!Array.isArray(list) || list.length === 0) {
      return res.status(400).json({ error: 'Provide "indicator" or "indicators"' });
    }

    const results = await aggregator.lookupBulk(list);
    const objects = results
      .filter((r) => !r.error)
      .flatMap((r) => stix.objectsForResult(r));

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="cimi-stix-bundle.json"');
    return res.send(JSON.stringify(stix.bundle(objects), null, 2));
  })
);

module.exports = router;
