'use strict';

const express = require('express');
const config = require('../config');
const correlation = require('../services/correlation');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();
router.use(requireAuth);

/** POST /api/correlation — correlate an explicit indicator set */
router.post(
  '/',
  asyncHandler(async (req, res) => {
    let { indicators: list, threshold } = req.body || {};
    if (typeof list === 'string') list = list.split(/[\s,;]+/);
    if (!Array.isArray(list) || list.length < 2) {
      return res.status(400).json({ error: 'Provide at least two indicators to correlate' });
    }
    const cleaned = Array.from(new Set(list.map((v) => String(v || '').trim()).filter(Boolean)));
    if (cleaned.length > config.limits.bulkMax) {
      return res.status(400).json({
        error: `Correlation is limited to ${config.limits.bulkMax} indicators per request`,
      });
    }
    const result = await correlation.correlate(cleaned, {
      threshold: threshold === undefined ? undefined : Number(threshold),
    });
    return res.json(result);
  })
);

/** GET /api/correlation/history — correlate the analyst's recent lookups */
router.get(
  '/history',
  asyncHandler(async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 15, config.limits.bulkMax);
    res.json(await correlation.correlateHistory(limit));
  })
);

module.exports = router;
