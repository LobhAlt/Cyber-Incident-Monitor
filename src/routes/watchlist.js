'use strict';

const express = require('express');
const watchlist = require('../services/watchlist');
const audit = require('../services/audit');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();
router.use(requireAuth);

/** GET /api/watchlist: the signed-in analyst's watched indicators */
router.get(
  '/',
  asyncHandler(async (req, res) => {
    res.json({ items: await watchlist.listFor(req.user.sub), max: watchlist.MAX_PER_USER });
  })
);

/** POST /api/watchlist {indicator, note?}: add and screen once for a baseline */
router.post(
  '/',
  asyncHandler(async (req, res) => {
    const { indicator, note } = req.body || {};
    const entry = await watchlist.add(req.user, { indicator, note });
    await audit.log('watchlist.added', { req, target: entry.indicator });
    res.status(201).json({ item: entry });
  })
);

/** POST /api/watchlist/:id/check: re-screen now */
router.post(
  '/:id/check',
  asyncHandler(async (req, res) => {
    res.json({ item: await watchlist.check(req.params.id, { userId: req.user.sub }) });
  })
);

/** PATCH /api/watchlist/:id {alerts}: turn email alerts on or off */
router.patch(
  '/:id',
  asyncHandler(async (req, res) => {
    const { alerts } = req.body || {};
    if (typeof alerts !== 'boolean') return res.status(400).json({ error: 'Field "alerts" must be true or false' });
    res.json({ item: await watchlist.setAlerts(req.user.sub, req.params.id, alerts) });
  })
);

/** DELETE /api/watchlist/:id */
router.delete(
  '/:id',
  asyncHandler(async (req, res) => {
    await watchlist.remove(req.user.sub, req.params.id);
    await audit.log('watchlist.removed', { req, target: req.params.id });
    res.json({ removed: true });
  })
);

module.exports = router;
