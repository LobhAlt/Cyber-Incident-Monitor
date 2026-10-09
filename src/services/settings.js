'use strict';

const config = require('../config');
const store = require('./store');

/**
 * Settings an admin can change at runtime from the Admin page. Values saved
 * here override the matching .env defaults.
 */

async function get() {
  const saved = await store.read('settings');
  return {
    registrationEnabled: typeof saved.registrationEnabled === 'boolean'
      ? saved.registrationEnabled
      : config.allowRegistration,
  };
}

async function set(patch) {
  const next = {};
  if (typeof patch.registrationEnabled === 'boolean') next.registrationEnabled = patch.registrationEnabled;
  await store.update('settings', (current) => ({ ...(current || {}), ...next }));
  return get();
}

module.exports = { get, set };
