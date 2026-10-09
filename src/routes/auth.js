'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const authService = require('../services/auth');
const audit = require('../services/audit');
const siteSettings = require('../services/settings');
const jwt = require('../utils/jwt');
const { requireAuth, extractToken } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();

/** Base URL for links in emails. PUBLIC_URL wins; the Host header is never trusted for this. */
function baseUrl() {
  return config.publicUrl || `http://localhost:${config.port}`;
}

function cookieOptions(req) {
  return {
    httpOnly: true, // page scripts cannot read it, so XSS cannot steal the session
    secure: req.secure || config.forceHttps,
    sameSite: 'strict', // never sent on cross-site requests, which blocks CSRF
    path: '/',
  };
}

function setSessionCookie(req, res, token) {
  res.cookie(config.sessionCookie, token, { ...cookieOptions(req), maxAge: authService.sessionMaxAgeMs() });
}

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
    let result;
    try {
      result = await authService.login({ username, password, mfaToken });
    } catch (err) {
      await audit.log('auth.login', { req, target: String(username).slice(0, 254), outcome: 'failure', detail: err.code || err.message });
      throw err;
    }
    if (result.mfaRequired) return res.json({ mfaRequired: true });
    // The token goes only into the HttpOnly cookie, never into the response body.
    setSessionCookie(req, res, result.token);
    await audit.log('auth.login', { req, actor: { id: result.user.id, username: result.user.username }, detail: result.mustChangePassword ? 'password change required' : null });
    return res.json({ user: result.user });
  })
);

router.post(
  '/register',
  loginLimiter,
  asyncHandler(async (req, res) => {
    if (!(await siteSettings.get()).registrationEnabled) {
      return res.status(403).json({ error: 'Self-service registration is disabled on this instance' });
    }
    const { username, email, password, website } = req.body || {};
    // Honeypot: the signup form has a hidden "website" field humans never fill.
    // Bots that do get a plausible-looking response and no account.
    if (website) {
      return res.status(201).json({ verificationRequired: true, email: String(email || '').trim(), delivery: 'email' });
    }
    const { user, delivery } = await authService.register({ username, email, password }, { baseUrl: baseUrl() });
    await audit.log('auth.register', { req, actor: { id: user.id, username: user.username }, target: user.email });
    return res.status(201).json({ verificationRequired: true, email: user.email, delivery });
  })
);

router.post(
  '/verify-email',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { token } = req.body || {};
    if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Verification token is missing' });
    const { user } = await authService.verifyEmail(token);
    await audit.log('auth.email_verified', { req, actor: { id: user.id, username: user.username } });
    return res.json({ verified: true, username: user.username });
  })
);

router.post(
  '/resend-verification',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { login } = req.body || {};
    await authService.resendVerification(login, { baseUrl: baseUrl() });
    return res.json({ ok: true, message: 'If that account is waiting for confirmation, a new link is on its way.' });
  })
);

router.post(
  '/forgot-password',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { login } = req.body || {};
    const { user } = await authService.requestPasswordReset(login, { baseUrl: baseUrl() });
    if (user) await audit.log('auth.password_reset_requested', { req, actor: { id: user.id, username: user.username } });
    return res.json({ ok: true, message: 'If an account matches, a reset link is on its way. It expires in 30 minutes.' });
  })
);

router.post(
  '/reset-password',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { token, password } = req.body || {};
    if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Reset token is missing' });
    const { user } = await authService.resetPassword(token, password);
    await audit.log('auth.password_reset', { req, actor: { id: user.id, username: user.username } });
    return res.json({ ok: true, username: user.username });
  })
);

router.post(
  '/change-password',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const { token, user } = await authService.changePassword(req.user.sub, currentPassword, newPassword);
    // Every other session is now invalid; this one gets a fresh cookie.
    setSessionCookie(req, res, token);
    await audit.log('auth.password_changed', { req });
    return res.json({ user: { ...user, mustChangePassword: false } });
  })
);

router.post(
  '/logout',
  asyncHandler(async (req, res) => {
    const token = extractToken(req);
    if (token) {
      try {
        const payload = jwt.verify(token, config.jwtSecret);
        await authService.revokeSession(payload);
        await audit.log('auth.logout', { req, actor: { id: payload.sub, username: payload.username } });
      } catch (e) { /* expired or invalid: nothing to revoke */ }
    }
    res.clearCookie(config.sessionCookie, cookieOptions(req));
    res.json({ ok: true });
  })
);

router.post(
  '/logout-all',
  requireAuth,
  asyncHandler(async (req, res) => {
    await authService.endAllSessions(req.user.sub);
    await audit.log('auth.logout_all', { req });
    res.clearCookie(config.sessionCookie, cookieOptions(req));
    res.json({ ok: true });
  })
);

router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const user = await authService.getById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user: { ...user, mustChangePassword: Boolean(req.user.pwc) } });
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
    const result = await authService.confirmMfa(req.user.sub, token);
    await audit.log('auth.mfa_enabled', { req });
    res.json(result);
  })
);

router.post(
  '/mfa/disable',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { password } = req.body || {};
    const result = await authService.disableMfa(req.user.sub, password);
    await audit.log('auth.mfa_disabled', { req });
    res.json(result);
  })
);

module.exports = router;
