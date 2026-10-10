'use strict';

/**
 * Email delivery tests. Runs outside the "test" environment so the real
 * Brevo and SMTP code paths execute, with the network replaced by stubs.
 * Run with: npm test
 */

process.env.NODE_ENV = 'development';
process.env.BREVO_API_KEY = 'xkeysib-0123456789abcdef-test-key';
process.env.MAIL_FROM = 'CIMI <cimi.alerts@gmail.com>';
process.env.SMTP_HOST = '';

const assert = require('assert');
const net = require('net');
const config = require('../src/config');
const mailer = require('../src/services/mailer');

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  \x1b[32m✓\x1b[0m ${name}`); } catch (err) {
    failed += 1; console.log(`  \x1b[31m✗\x1b[0m ${name}\n     ${err.message}`);
  }
}

(async function run() {
  console.log('\n  Email delivery tests\n');
  const realFetch = global.fetch;

  await test('BREVO_API_KEY takes priority over SMTP', () => {
    assert.strictEqual(mailer.provider(), 'brevo');
  });

  await test('sender addresses are parsed for the API', () => {
    assert.deepStrictEqual(mailer.parseAddress('CIMI <a@b.org>'), { name: 'CIMI', email: 'a@b.org' });
    assert.deepStrictEqual(mailer.parseAddress('a@b.org'), { email: 'a@b.org' });
  });

  await test('Brevo receives a well-formed request', async () => {
    let seen = null;
    global.fetch = async (url, opts) => { seen = { url, opts }; return { ok: true, status: 201, text: async () => '' }; };
    const msg = mailer.verificationEmail({ username: 'riya', link: 'https://x/verify.html#token=abc', hours: 24 });
    const result = await mailer.send({ to: 'riya@example.org', ...msg });
    assert.strictEqual(result.delivery, 'email');
    assert.strictEqual(seen.url, 'https://api.brevo.com/v3/smtp/email');
    assert.strictEqual(seen.opts.headers['api-key'], 'xkeysib-0123456789abcdef-test-key');
    const body = JSON.parse(seen.opts.body);
    assert.deepStrictEqual(body.sender, { name: 'CIMI', email: 'cimi.alerts@gmail.com' });
    assert.deepStrictEqual(body.to, [{ email: 'riya@example.org' }]);
    assert.ok(body.textContent.includes('#token=abc') && body.htmlContent.includes('#token=abc'));
    assert.ok(seen.opts.signal, 'request has a timeout');
  });

  await test('a Brevo error is reported, not swallowed', async () => {
    global.fetch = async () => ({ ok: false, status: 401, text: async () => '{"message":"Key not found"}' });
    await assert.rejects(mailer.send({ to: 'a@b.org', subject: 's', text: 't' }), /HTTP 401/);
  });

  global.fetch = realFetch;

  await test('SMTP gives up quickly instead of hanging when the port is blocked', async () => {
    // A server that accepts the connection and never speaks: what a blocked or filtered port looks like.
    const silent = net.createServer(() => {});
    await new Promise((r) => silent.listen(0, '127.0.0.1', r));
    config.mail.brevoApiKey = '';
    config.mail.host = '127.0.0.1';
    config.mail.port = silent.address().port;
    config.mail.secure = false;
    const started = Date.now();
    await assert.rejects(mailer.send({ to: 'a@b.org', subject: 's', text: 't' }));
    const took = Date.now() - started;
    silent.close();
    assert.ok(took < 20000, `failed after ${took} ms`);
  });

  console.log(`\n  ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
