'use strict';

const express = require('express');
const config = require('../config');
const authService = require('../services/auth');
const audit = require('../services/audit');
const siteSettings = require('../services/settings');
const { requireAuth, requireRole } = require('../middleware/auth');
const { asyncHandler } = require('../middleware/errors');

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

function baseUrl() {
  return config.publicUrl || `http://localhost:${config.port}`;
}

/** GET /api/admin/users */
router.get(
  '/users',
  asyncHandler(async (req, res) => {
    res.json({ items: await authService.listUsers() });
  })
);

/** POST /api/admin/users/:id/disable and /enable */
for (const action of ['disable', 'enable']) {
  router.post(
    `/users/:id/${action}`,
    asyncHandler(async (req, res) => {
      const user = await authService.setDisabled(req.user.sub, req.params.id, action === 'disable');
      await audit.log(`admin.user_${action}d`, { req, target: user.username });
      res.json({ user });
    })
  );
}

/** POST /api/admin/users/:id/resend-verification */
router.post(
  '/users/:id/resend-verification',
  asyncHandler(async (req, res) => {
    const user = await authService.getById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.emailVerified) return res.status(400).json({ error: 'That account is already confirmed' });
    await authService.resendVerification(user.username, { baseUrl: baseUrl() });
    await audit.log('admin.verification_resent', { req, target: user.username });
    return res.json({ ok: true });
  })
);

/** DELETE /api/admin/users/:id */
router.delete(
  '/users/:id',
  asyncHandler(async (req, res) => {
    const user = await authService.deleteUser(req.user.sub, req.params.id);
    await audit.log('admin.user_deleted', { req, target: user.username });
    res.json({ deleted: true });
  })
);

/** GET /api/admin/audit?limit=&event= */
router.get(
  '/audit',
  asyncHandler(async (req, res) => {
    const items = await audit.list({ limit: req.query.limit, event: req.query.event, actor: req.query.actor });
    res.json({ items });
  })
);

/** GET / PUT /api/admin/settings */
router.get(
  '/settings',
  asyncHandler(async (req, res) => {
    res.json(await siteSettings.get());
  })
);

router.put(
  '/settings',
  asyncHandler(async (req, res) => {
    const { registrationEnabled } = req.body || {};
    if (typeof registrationEnabled !== 'boolean') {
      return res.status(400).json({ error: 'Field "registrationEnabled" must be true or false' });
    }
    const next = await siteSettings.set({ registrationEnabled });
    await audit.log('admin.settings_changed', { req, detail: `registration ${registrationEnabled ? 'on' : 'off'}` });
    return res.json(next);
  })
);

module.exports = router;
