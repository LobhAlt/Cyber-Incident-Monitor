'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const authService = require('../services/auth');
const { requireAuth } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.authMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again later' },
});

router.post(
  '/login',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { username, password, mfaToken } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    const result = await authService.login({ username, password, mfaToken });
    return res.json(result);
  })
);

router.post(
  '/register',
  loginLimiter,
  asyncHandler(async (req, res) => {
    if (!config.allowRegistration) {
      return res.status(403).json({ error: 'Self-service registration is disabled on this instance' });
    }
    const { username, password, website } = req.body || {};
    // Honeypot: the signup form has a hidden "website" field humans never fill.
    // Bots that do get a plausible-looking response and no account.
    if (website) {
      return res.status(201).json({ user: { username: String(username || '').trim(), role: 'analyst' } });
    }
    const user = await authService.register({ username, password });
    return res.status(201).json({ user });
  })
);

router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const user = await authService.getById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user });
  })
);

router.post(
  '/mfa/setup',
  requireAuth,
  asyncHandler(async (req, res) => {
    res.json(await authService.beginMfaSetup(req.user.sub));
  })
);

router.post(
  '/mfa/confirm',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { token } = req.body || {};
    res.json(await authService.confirmMfa(req.user.sub, token));
  })
);

router.post(
  '/mfa/disable',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { password } = req.body || {};
    res.json(await authService.disableMfa(req.user.sub, password));
  })
);

module.exports = router;
