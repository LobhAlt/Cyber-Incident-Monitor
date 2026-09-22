'use strict';

const express = require('express');
const config = require('../config');
const loganalysis = require('../services/loganalysis');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();
router.use(requireAuth);

/**
 * POST /api/logs/analyse
 * Body: { content: "<raw log text>", fileName?: string, screenLimit?: number }
 * The frontend reads the chosen file with the browser FileReader API and posts
 * its text, so no multipart dependency is required on the server.
 */
router.post(
  '/analyse',
  express.text({ type: ['text/plain', 'text/*'], limit: config.limits.logMaxBytes }),
  asyncHandler(async (req, res) => {
    const isText = typeof req.body === 'string';
    const content = isText ? req.body : (req.body && req.body.content);
    const fileName = isText ? req.query.fileName : (req.body && req.body.fileName);
    const screenLimit = isText ? req.query.screenLimit : (req.body && req.body.screenLimit);

    const report = await loganalysis.analyse(content, {
      fileName: fileName || 'pasted-log.txt',
      screenLimit,
      user: req.user,
    });
    res.json(report);
  })
);

/** Alias with the American spelling, so either path works. */
router.post(
  '/analyze',
  express.text({ type: ['text/plain', 'text/*'], limit: config.limits.logMaxBytes }),
  asyncHandler(async (req, res) => {
    const isText = typeof req.body === 'string';
    const content = isText ? req.body : (req.body && req.body.content);
    const report = await loganalysis.analyse(content, {
      fileName: (req.body && req.body.fileName) || req.query.fileName || 'pasted-log.txt',
      screenLimit: (req.body && req.body.screenLimit) || req.query.screenLimit,
      user: req.user,
    });
    res.json(report);
  })
);

/** GET /api/logs/reports */
router.get(
  '/reports',
  asyncHandler(async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 25, 100);
    const items = await loganalysis.listReports(limit);
    res.json({ total: items.length, items });
  })
);

/** GET /api/logs/reports/:id */
router.get(
  '/reports/:id',
  asyncHandler(async (req, res) => {
    const report = await loganalysis.getReport(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    return res.json(report);
  })
);

module.exports = router;
