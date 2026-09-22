'use strict';

const express = require('express');
const dashboard = require('../services/dashboard');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();
router.use(requireAuth);

/** GET /api/dashboard?days=14 */
router.get(
  '/',
  asyncHandler(async (req, res) => {
    const days = Math.min(Math.max(Number(req.query.days) || 14, 3), 90);
    res.json(await dashboard.build({ days }));
  })
);

module.exports = router;
