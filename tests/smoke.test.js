'use strict';

/**
 * CIMI end-to-end smoke test.
 * Boots the real server on an ephemeral port and exercises every endpoint.
 * Run with:  npm test
 */

process.env.PORT = process.env.TEST_PORT || '4311';
process.env.FORCE_DEMO_MODE = 'true';
process.env.ENABLE_SCHEDULER = 'false';
process.env.JWT_SECRET = 'test-secret-for-the-cimi-smoke-suite-0123456789';
process.env.NODE_ENV = 'test';
// The suite makes far more sign-in calls than a person would; lift the per-IP auth limit.
process.env.AUTH_RATE_LIMIT_MAX = '1000';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Isolate the flat-file store so the test never touches real data.
const tmpData = fs.mkdtempSync(path.join(os.tmpdir(), 'cimi-test-'));
const config = require('../src/config');
config.dataDir = tmpData;

const { bootstrap } = require('../server');
const mailer = require('../src/services/mailer');

const BASE = `http://127.0.0.1:${config.port}`;
let passed = 0;
let failed = 0;
// Acts like a browser cookie jar holding only the session cookie.
let session = null;
// The default admin password must be changed on first sign-in; this is what the suite changes it to.
const ADMIN_PW = 'Nagpur-Soc-Lab-77';

async function api(pathname, options = {}) {
  const res = await fetch(BASE + pathname, {
    method: options.method || 'GET',
    headers: Object.assign(
      { Accept: 'application/json' },
      options.body ? { 'Content-Type': 'application/json' } : {},
      session ? { Cookie: `${config.sessionCookie}=${session}` } : {},
      options.headers || {}
    ),
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const setCookie = res.headers.get('set-cookie') || '';
  const match = new RegExp(`${config.sessionCookie}=([^;]*)`).exec(setCookie);
  if (match) session = match[1] || null;
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data, setCookie, headers: res.headers };
}

/** Pulls the token out of the newest verification email sent to `address`. */
function tokenFromOutbox(address) {
  const mail = mailer.outbox.slice().reverse().find((m) => m.to === address);
  assert.ok(mail, `a verification email was sent to ${address}`);
  const m = /#token=([A-Za-z0-9_%-]+)/.exec(mail.text);
  assert.ok(m, 'email contains a verification link');
  return decodeURIComponent(m[1]);
}

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`  \x1b[31m✗\x1b[0m ${name}`);
    console.log(`     ${err.message}`);
  }
}

(async function run() {
  const server = await bootstrap();
  console.log('\n  CIMI smoke test suite\n');

  // --- unit-level checks ---------------------------------------------------
  const indicators = require('../src/utils/indicators');
  const stix = require('../src/services/stix');
  const jwt = require('../src/utils/jwt');
  const totp = require('../src/utils/totp');

  await test('detects every supported indicator type', () => {
    assert.strictEqual(indicators.detectType('8.8.8.8'), 'ip');
    assert.strictEqual(indicators.detectType('example.com'), 'domain');
    assert.strictEqual(indicators.detectType('https://example.com/a'), 'url');
    assert.strictEqual(indicators.detectType('44d88612fea8a8f36de82e1278abb02f'), 'md5');
    assert.strictEqual(indicators.detectType('a'.repeat(40)), 'sha1');
    assert.strictEqual(indicators.detectType('b'.repeat(64)), 'sha256');
    assert.strictEqual(indicators.detectType('CVE-2021-44228'), 'cve');
    assert.strictEqual(indicators.detectType('not an indicator!!'), 'unknown');
  });

  await test('extracts indicators from raw log text', () => {
    const text = 'from 185.220.101.44 GET http://evil.example.com/x md5=44d88612fea8a8f36de82e1278abb02f CVE-2021-44228 private 192.168.1.1';
    const out = indicators.extractFromText(text);
    assert.ok(out.ips.includes('185.220.101.44'), 'public IP extracted');
    assert.ok(!out.ips.includes('192.168.1.1'), 'private IP excluded');
    assert.strictEqual(out.urls.length, 1);
    assert.strictEqual(out.md5.length, 1);
    assert.strictEqual(out.cves.length, 1);
  });

  await test('builds a valid STIX 2.1 bundle', () => {
    const objects = stix.objectsForResult({
      indicator: '8.8.8.8', type: 'ip', verdict: 'clean', score: 4, confidence: 70,
      sources: [{ source: 'VirusTotal', available: true, link: 'https://x' }],
      attackTechniques: [{ id: 'T1071.001', name: 'Web Protocols', tactic: 'command-and-control' }],
    });
    const bundle = stix.bundle(objects);
    assert.strictEqual(bundle.type, 'bundle');
    const indicator = bundle.objects.find((o) => o.type === 'indicator');
    assert.strictEqual(indicator.spec_version, '2.1');
    assert.strictEqual(indicator.pattern, "[ipv4-addr:value = '8.8.8.8']");
    assert.ok(bundle.objects.some((o) => o.type === 'ipv4-addr'));
    assert.ok(bundle.objects.some((o) => o.type === 'observed-data'));
    assert.ok(bundle.objects.some((o) => o.type === 'attack-pattern'));
    assert.ok(bundle.objects.some((o) => o.type === 'relationship'));
  });

  await test('JWT signs, verifies and rejects tampering', () => {
    const t = jwt.sign({ sub: 'u1' }, 'secret', { expiresIn: '1h' });
    assert.strictEqual(jwt.verify(t, 'secret').sub, 'u1');
    assert.throws(() => jwt.verify(t, 'wrong-secret'));
    assert.throws(() => jwt.verify(t.slice(0, -2) + 'xy', 'secret'));
  });

  await test('ATT&CK mapping only fires for flagged indicators', () => {
    const attack = require('../src/services/attack');
    assert.deepStrictEqual(
      attack.mapTechniques({ type: 'ip', verdict: 'clean', tags: ['ransomware', 'botnet'] }),
      [],
      'a clean verdict must not be given behavioural techniques'
    );
    const mapped = attack.mapTechniques({ type: 'ip', verdict: 'malicious', tags: ['ransomware'] });
    assert.ok(mapped.length > 0);
    assert.ok(mapped.some((t) => t.id === 'T1486'), 'ransomware maps to Data Encrypted for Impact');
  });

  await test('TOTP generates and verifies a 6-digit code', () => {
    const secret = totp.generateSecret();
    const code = totp.generate(secret);
    assert.match(code, /^\d{6}$/);
    assert.strictEqual(totp.verify(secret, code), true);
    assert.strictEqual(totp.verify(secret, '000001'), false);
  });

  // --- API checks ----------------------------------------------------------
  await test('GET /api/health returns ok', async () => {
    const { status, data } = await api('/api/health');
    assert.strictEqual(status, 200);
    assert.strictEqual(data.status, 'ok');
    assert.strictEqual(data.stixVersion, '2.1');
  });

  await test('protected routes reject unauthenticated calls', async () => {
    const { status } = await api('/api/dashboard');
    assert.strictEqual(status, 401);
  });

  await test('login with the default analyst account succeeds', async () => {
    const { status, data } = await api('/api/auth/login', {
      method: 'POST',
      body: { username: config.defaultAdmin.username, password: config.defaultAdmin.password },
    });
    assert.strictEqual(status, 200);
    assert.strictEqual(data.token, undefined, 'token is never put in the response body');
    assert.ok(session, 'session cookie issued');
  });

  await test('session cookie is HttpOnly and SameSite=Strict', async () => {
    const saved = session;
    const { setCookie } = await api('/api/auth/login', {
      method: 'POST',
      body: { username: config.defaultAdmin.username, password: config.defaultAdmin.password },
    });
    assert.ok(/HttpOnly/i.test(setCookie), 'HttpOnly');
    assert.ok(/SameSite=Strict/i.test(setCookie), 'SameSite=Strict');
    assert.ok(session, 'session cookie set');
    if (!session) session = saved;
  });

  await test('API responses are marked no-store', async () => {
    const { headers } = await api('/api/auth/me');
    assert.strictEqual(headers.get('cache-control'), 'no-store');
  });

  await test('session token in the query string is not accepted', async () => {
    const saved = session; session = null;
    const { status } = await api(`/api/auth/me?token=${saved}`);
    session = saved;
    assert.strictEqual(status, 401);
  });

  await test('login with a wrong password is rejected', async () => {
    const { status } = await api('/api/auth/login', {
      method: 'POST',
      body: { username: config.defaultAdmin.username, password: 'definitely-wrong' },
    });
    assert.strictEqual(status, 401);
  });

  await test('GET /api/auth/me returns the session user', async () => {
    const { status, data } = await api('/api/auth/me');
    assert.strictEqual(status, 200);
    assert.strictEqual(data.user.username, config.defaultAdmin.username);
  });

  await test('registration requires a valid email', async () => {
    const { status } = await api('/api/auth/register', {
      method: 'POST',
      body: { username: 'no.email', password: 'StrongPass#2026' },
    });
    assert.strictEqual(status, 400);
  });

  await test('new account must confirm its email before signing in', async () => {
    const saved = session; session = null;
    const email = 'riya.analyst@example.org';
    const reg = await api('/api/auth/register', {
      method: 'POST',
      body: { username: 'riya.analyst', email, password: 'StrongPass#2026' },
    });
    assert.strictEqual(reg.status, 201);
    assert.strictEqual(reg.data.verificationRequired, true);
    assert.ok(!session, 'registration does not sign the account in');

    const early = await api('/api/auth/login', { method: 'POST', body: { username: 'riya.analyst', password: 'StrongPass#2026' } });
    assert.strictEqual(early.status, 403);
    assert.strictEqual(early.data.code, 'EMAIL_UNVERIFIED');

    const wrongPw = await api('/api/auth/login', { method: 'POST', body: { username: 'riya.analyst', password: 'wrong-password' } });
    assert.strictEqual(wrongPw.status, 401, 'unverified status is not revealed without the right password');

    const token = tokenFromOutbox(email);
    const users = JSON.parse(fs.readFileSync(path.join(tmpData, 'users.json'), 'utf8'));
    assert.ok(!JSON.stringify(users).includes(token), 'only a hash of the token is stored');

    const ok = await api('/api/auth/verify-email', { method: 'POST', body: { token } });
    assert.strictEqual(ok.status, 200);
    const again = await api('/api/auth/verify-email', { method: 'POST', body: { token } });
    assert.strictEqual(again.status, 400, 'tokens are single-use');

    const viaEmail = await api('/api/auth/login', { method: 'POST', body: { username: email, password: 'StrongPass#2026' } });
    assert.strictEqual(viaEmail.status, 200, 'can sign in with the email address once confirmed');
    assert.strictEqual(viaEmail.data.user.emailVerified, true);
    session = saved;
  });

  await test('the same email cannot register twice', async () => {
    const { status } = await api('/api/auth/register', {
      method: 'POST',
      body: { username: 'riya.second', email: 'Riya.Analyst@example.org', password: 'StrongPass#2026' },
    });
    assert.strictEqual(status, 409);
  });

  await test('resending verification gives the same answer for unknown accounts', async () => {
    const known = await api('/api/auth/resend-verification', { method: 'POST', body: { login: 'riya.analyst' } });
    const unknown = await api('/api/auth/resend-verification', { method: 'POST', body: { login: 'nobody@example.org' } });
    assert.strictEqual(known.status, 200);
    assert.deepStrictEqual(known.data, unknown.data);
  });

  await test('a made-up verification token is rejected', async () => {
    const { status } = await api('/api/auth/verify-email', { method: 'POST', body: { token: 'not-a-real-token' } });
    assert.strictEqual(status, 400);
  });

  await test('default password forces a password change before anything else', async () => {
    const me = await api('/api/auth/me');
    assert.strictEqual(me.data.user.mustChangePassword, true);
    const blocked = await api('/api/dashboard');
    assert.strictEqual(blocked.status, 403);
    assert.strictEqual(blocked.data.code, 'PASSWORD_CHANGE_REQUIRED');
  });

  await test('weak or reused passwords are refused', async () => {
    for (const bad of ['short', 'password123', 'lowercaseonly', 'analyst-Pass-1', config.defaultAdmin.password]) {
      const { status } = await api('/api/auth/change-password', {
        method: 'POST', body: { currentPassword: config.defaultAdmin.password, newPassword: bad },
      });
      assert.strictEqual(status, 400, bad);
    }
  });

  await test('changing the password unlocks the account and ends other sessions', async () => {
    const before = session;
    const { status, data } = await api('/api/auth/change-password', {
      method: 'POST', body: { currentPassword: config.defaultAdmin.password, newPassword: ADMIN_PW },
    });
    assert.strictEqual(status, 200);
    assert.strictEqual(data.user.mustChangePassword, false);
    assert.ok(session && session !== before, 'a fresh session cookie is issued');
    assert.strictEqual((await api('/api/dashboard')).status, 200);

    const current = session; session = before;
    const stale = await api('/api/auth/me');
    session = current;
    assert.strictEqual(stale.status, 401, 'the old session no longer works');

    const oldPw = await api('/api/auth/login', {
      method: 'POST', body: { username: config.defaultAdmin.username, password: config.defaultAdmin.password },
    });
    session = current;
    assert.strictEqual(oldPw.status, 401, 'the default password is gone');
  });

  await test('IP lookup returns a blended verdict from three sources', async () => {
    const { status, data } = await api('/api/ioc/lookup', {
      method: 'POST', body: { indicator: '185.220.101.44' },
    });
    assert.strictEqual(status, 200);
    assert.strictEqual(data.type, 'ip');
    assert.strictEqual(data.sources.length, 3);
    assert.ok(['malicious', 'suspicious', 'clean', 'unknown'].includes(data.verdict));
    assert.ok(data.score >= 0 && data.score <= 100);
    assert.strictEqual(data.stix.type, 'bundle');
  });

  await test('domain, hash and CVE lookups all succeed', async () => {
    for (const value of ['secure-upi-verify.in', '44d88612fea8a8f36de82e1278abb02f', 'CVE-2021-44228']) {
      const { status, data } = await api('/api/ioc/lookup', { method: 'POST', body: { indicator: value } });
      assert.strictEqual(status, 200, `${value} -> ${status}`);
      assert.ok(data.indicator);
    }
  });

  await test('lookup results are deterministic in simulator mode', async () => {
    const a = await api('/api/ioc/lookup', { method: 'POST', body: { indicator: '203.0.113.77' } });
    const b = await api('/api/ioc/lookup', { method: 'POST', body: { indicator: '203.0.113.77' } });
    assert.strictEqual(a.data.score, b.data.score);
    assert.strictEqual(a.data.verdict, b.data.verdict);
  });

  await test('an unparsable indicator is rejected with 400', async () => {
    const { status } = await api('/api/ioc/lookup', { method: 'POST', body: { indicator: '%%% not valid %%%' } });
    assert.strictEqual(status, 400);
  });

  await test('bulk lookup screens a batch and summarises it', async () => {
    const { status, data } = await api('/api/ioc/bulk', {
      method: 'POST',
      body: { indicators: ['8.8.8.8', '1.1.1.1', 'example.com', 'phish-login-hdfc.top'] },
    });
    assert.strictEqual(status, 200);
    assert.strictEqual(data.results.length, 4);
    assert.strictEqual(data.summary.total, 4);
  });

  await test('bulk lookup enforces the 25-indicator limit', async () => {
    const many = Array.from({ length: 30 }, (_, i) => `10.10.${i}.5`).map((v) => v.replace('10.10', '198.51'));
    const { status } = await api('/api/ioc/bulk', { method: 'POST', body: { indicators: many } });
    assert.strictEqual(status, 400);
  });

  await test('lookup history is recorded', async () => {
    const { status, data } = await api('/api/ioc/history?limit=50');
    assert.strictEqual(status, 200);
    assert.ok(data.items.length >= 4, `expected recorded history, got ${data.items.length}`);
  });

  await test('STIX export endpoint returns a bundle', async () => {
    const { status, data } = await api('/api/ioc/stix', {
      method: 'POST', body: { indicators: ['185.220.101.44', 'secure-upi-verify.in'] },
    });
    assert.strictEqual(status, 200);
    assert.strictEqual(data.type, 'bundle');
    assert.ok(data.objects.length > 0);
  });

  await test('dashboard aggregates KPIs, trend and geography', async () => {
    const { status, data } = await api('/api/dashboard?days=14');
    assert.strictEqual(status, 200);
    assert.ok(data.kpis.totalLookups > 0);
    assert.strictEqual(data.trend.length, 14);
    assert.ok(Array.isArray(data.geography));
    assert.ok(Array.isArray(data.topTechniques));
  });

  await test('correlation builds nodes, edges and clusters', async () => {
    const { status, data } = await api('/api/correlation', {
      method: 'POST',
      body: { indicators: ['185.220.101.44', '45.155.205.233', 'secure-upi-verify.in', 'login-icici-alerts.com'] },
    });
    assert.strictEqual(status, 200);
    assert.strictEqual(data.nodes.length, 4);
    assert.ok(Array.isArray(data.edges));
    assert.ok(data.clusters.length >= 1);
    assert.strictEqual(
      data.clusters.reduce((sum, c) => sum + c.size, 0), 4,
      'every indicator belongs to exactly one cluster'
    );
  });

  await test('correlation requires at least two indicators', async () => {
    const { status } = await api('/api/correlation', { method: 'POST', body: { indicators: ['8.8.8.8'] } });
    assert.strictEqual(status, 400);
  });

  await test('correlating history works', async () => {
    const { status, data } = await api('/api/correlation/history?limit=10');
    assert.strictEqual(status, 200);
    assert.ok(data.summary);
  });

  await test('log analysis extracts and screens indicators', async () => {
    const log = [
      '2026-09-14T08:12:44Z sshd[2211]: Failed password for root from 185.220.101.44 port 51022 ssh2',
      '2026-09-14T08:15:02Z firewall: DENY tcp 45.155.205.233:4444 -> 10.4.2.19:3389',
      '2026-09-14T08:19:31Z proxy: GET http://secure-upi-verify.in/login.php 200',
      '2026-09-14T08:25:10Z edr: quarantined md5=44d88612fea8a8f36de82e1278abb02f',
      '2026-09-14T08:40:17Z vuln-scan: host affected by CVE-2021-44228',
    ].join('\n');
    const { status, data } = await api('/api/logs/analyse', { method: 'POST', body: { content: log, fileName: 'auth.log' } });
    assert.strictEqual(status, 200);
    assert.ok(data.extraction.ips >= 2, 'IPs extracted');
    assert.ok(data.extraction.urls >= 1, 'URL extracted');
    assert.ok(data.extraction.hashes >= 1, 'hash extracted');
    assert.ok(data.findings.length > 0, 'indicators screened');
    assert.ok(data.screenedCount <= 15, 'respects the 15-indicator screen limit');
  });

  await test('empty log content is rejected', async () => {
    const { status } = await api('/api/logs/analyse', { method: 'POST', body: { content: '   ' } });
    assert.strictEqual(status, 400);
  });

  await test('log reports are listed', async () => {
    const { status, data } = await api('/api/logs/reports');
    assert.strictEqual(status, 200);
    assert.ok(data.items.length >= 1);
  });

  await test('CERT-In feed returns advisories (live or offline fallback)', async () => {
    const { status, data } = await api('/api/feeds/certin?limit=10');
    assert.strictEqual(status, 200);
    assert.ok(Array.isArray(data.items));
    assert.ok(data.items.length > 0, 'advisories always available thanks to the fallback');
    assert.ok(data.items[0].id && data.items[0].title);
  });

  await test('CISA KEV feed returns vulnerabilities', async () => {
    const { status, data } = await api('/api/feeds/kev?limit=10');
    assert.strictEqual(status, 200);
    assert.ok(data.items.length > 0);
    assert.ok(data.items[0].cveID);
  });

  await test('OTX feed returns pulses', async () => {
    const { status, data } = await api('/api/feeds/otx');
    assert.strictEqual(status, 200);
    assert.ok(Array.isArray(data.items));
  });

  await test('feed health scores every source', async () => {
    const { status, data } = await api('/api/feeds/health');
    assert.strictEqual(status, 200);
    assert.strictEqual(data.feeds.length, 3);
    data.feeds.forEach((f) => {
      assert.ok(f.qualityScore >= 0 && f.qualityScore <= 100);
    });
  });

  await test('CERT-In STIX export returns vulnerability SDOs', async () => {
    const { status, data } = await api('/api/feeds/certin/stix');
    assert.strictEqual(status, 200);
    assert.strictEqual(data.type, 'bundle');
    assert.ok(data.objects.every((o) => o.type === 'vulnerability'));
  });

  await test('MFA can be set up, confirmed and used at login', async () => {
    const setup = await api('/api/auth/mfa/setup', { method: 'POST', body: {} });
    assert.strictEqual(setup.status, 200);
    const code = totp.generate(setup.data.secret);
    const confirm = await api('/api/auth/mfa/confirm', { method: 'POST', body: { token: code } });
    assert.strictEqual(confirm.status, 200);

    const challenge = await api('/api/auth/login', {
      method: 'POST',
      body: { username: config.defaultAdmin.username, password: ADMIN_PW },
    });
    assert.strictEqual(challenge.data.mfaRequired, true, 'login now demands a second factor');

    const withCode = await api('/api/auth/login', {
      method: 'POST',
      body: {
        username: config.defaultAdmin.username,
        password: ADMIN_PW,
        mfaToken: totp.generate(setup.data.secret),
      },
    });
    assert.strictEqual(withCode.status, 200);
    assert.ok(withCode.data.user, 'signed in after the second factor');

    const off = await api('/api/auth/mfa/disable', {
      method: 'POST', body: { password: ADMIN_PW },
    });
    assert.strictEqual(off.status, 200);
  });

  await test('the SPA shell is served at /', async () => {
    const res = await fetch(BASE + '/');
    const html = await res.text();
    assert.strictEqual(res.status, 200);
    assert.ok(html.includes('Cyber Incident Monitor in India'));
    assert.ok(html.includes('/js/app.js'));
  });

  await test('static assets are served', async () => {
    for (const asset of ['/css/app.css', '/js/api.js', '/js/charts.js', '/js/app.js', '/vendor/tailwind.js']) {
      const res = await fetch(BASE + asset);
      assert.strictEqual(res.status, 200, `${asset} -> ${res.status}`);
    }
  });

  await test('unknown API routes return 404 JSON', async () => {
    const { status, data } = await api('/api/does-not-exist');
    assert.strictEqual(status, 404);
    assert.ok(data.error);
  });

  await test('unknown paths get the custom 404 page with a 404 status', async () => {
    const res = await fetch(BASE + '/some/deep/route');
    assert.strictEqual(res.status, 404);
    assert.ok((await res.text()).includes('Page not found'));
  });

  await test('privacy and terms pages are served', async () => {
    for (const page of ['/privacy.html', '/terms.html']) {
      const res = await fetch(BASE + page);
      assert.strictEqual(res.status, 200, page);
      const html = await res.text();
      assert.ok(html.includes('<meta name="description"'), `${page} has a meta description`);
      assert.ok(!html.includes('\u2014'), `${page} contains no em dashes`);
    }
  });

  await test('robots.txt and sitemap.xml are generated', async () => {
    const robots = await (await fetch(BASE + '/robots.txt')).text();
    assert.ok(robots.includes('Disallow: /api/'));
    assert.ok(robots.includes(`Sitemap: ${BASE}/sitemap.xml`));
    const sitemap = await (await fetch(BASE + '/sitemap.xml')).text();
    assert.ok(sitemap.includes(`<loc>${BASE}/privacy.html</loc>`));
  });

  await test('favicon, touch icon and social preview image exist', async () => {
    for (const asset of ['/favicon.svg', '/apple-touch-icon.png', '/og-image.png']) {
      const res = await fetch(BASE + asset);
      assert.strictEqual(res.status, 200, asset);
    }
  });

  await test('public site config exposes no secrets', async () => {
    const { status, data } = await api('/api/site');
    assert.strictEqual(status, 200);
    assert.strictEqual(typeof data.registrationEnabled, 'boolean');
    assert.ok(!JSON.stringify(data).toLowerCase().includes('key'));
  });

  await test('registration honeypot swallows bot signups', async () => {
    const saved = session; session = null;
    const { status } = await api('/api/auth/register', {
      method: 'POST', body: { username: 'bot-' + Date.now(), email: 'bot@spam.example', password: 'BotPassword123', website: 'http://spam.example' },
    });
    assert.strictEqual(status, 201);
    const login = await api('/api/auth/login', { method: 'POST', body: { username: 'bot-x', password: 'BotPassword123' } });
    assert.strictEqual(login.status, 401, 'no account was actually created');
    session = saved;
  });

  await test('frontend bundle contains no provider API keys', async () => {
    const files = ['/js/app.js', '/js/api.js', '/js/charts.js', '/'];
    for (const f of files) {
      const text = await (await fetch(BASE + f)).text();
      assert.ok(!/API_KEY|apiKey\s*[:=]\s*['"][A-Za-z0-9]{20,}/.test(text), f);
    }
  });

  // --- password reset, sessions, lockout -----------------------------------
  const RIYA_PW = 'StrongPass#2026';
  const RIYA_NEW = 'Raisoni-Lab-Pass-91';
  const asRiya = async (password) => {
    const res = await api('/api/auth/login', { method: 'POST', body: { username: 'riya.analyst', password } });
    return res;
  };

  await test('forgot-password replies the same for real and unknown accounts', async () => {
    const saved = session; session = null;
    const real = await api('/api/auth/forgot-password', { method: 'POST', body: { login: 'riya.analyst' } });
    const fake = await api('/api/auth/forgot-password', { method: 'POST', body: { login: 'nobody.here' } });
    session = saved;
    assert.strictEqual(real.status, 200);
    assert.deepStrictEqual(real.data, fake.data);
  });

  await test('a reset link sets a new password once and ends sessions', async () => {
    const saved = session; session = null;
    const signedIn = await asRiya(RIYA_PW);
    assert.strictEqual(signedIn.status, 200);
    const riyaSession = session;

    const mail = mailer.outbox.slice().reverse().find((m) => m.to === 'riya.analyst@example.org' && /Reset/.test(m.subject));
    assert.ok(mail, 'reset email sent');
    const token = decodeURIComponent(/#token=([A-Za-z0-9_%-]+)/.exec(mail.text)[1]);

    session = null;
    const weak = await api('/api/auth/reset-password', { method: 'POST', body: { token, password: 'weakpass' } });
    assert.strictEqual(weak.status, 400, 'policy applies to resets');
    const ok = await api('/api/auth/reset-password', { method: 'POST', body: { token, password: RIYA_NEW } });
    assert.strictEqual(ok.status, 200);
    const reuse = await api('/api/auth/reset-password', { method: 'POST', body: { token, password: 'Another-Pass-123' } });
    assert.strictEqual(reuse.status, 400, 'reset links are single-use');

    session = riyaSession;
    assert.strictEqual((await api('/api/auth/me')).status, 401, 'existing sessions ended');
    session = null;
    assert.strictEqual((await asRiya(RIYA_PW)).status, 401, 'old password rejected');
    assert.strictEqual((await asRiya(RIYA_NEW)).status, 200, 'new password works');
    session = saved;
  });

  await test('signing out revokes that session token on the server', async () => {
    const saved = session; session = null;
    await asRiya(RIYA_NEW);
    const token = session;
    await api('/api/auth/logout', { method: 'POST', body: {} });
    session = token;
    const reuse = await api('/api/auth/me');
    session = saved;
    assert.strictEqual(reuse.status, 401, 'a copied token stops working after sign-out');
  });

  await test('sign out everywhere ends every session', async () => {
    const saved = session; session = null;
    await asRiya(RIYA_NEW); const first = session;
    session = null;
    await asRiya(RIYA_NEW);
    await api('/api/auth/logout-all', { method: 'POST', body: {} });
    session = first;
    const status = (await api('/api/auth/me')).status;
    session = saved;
    assert.strictEqual(status, 401);
  });

  await test('repeated wrong passwords lock sign-in, for unknown names too', async () => {
    const saved = session; session = null;
    const name = 'ghost.' + Date.now();
    const codes = [];
    for (let i = 0; i < 6; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      codes.push((await api('/api/auth/login', { method: 'POST', body: { username: name, password: 'wrong-' + i } })).status);
    }
    session = saved;
    assert.deepStrictEqual(codes, [401, 401, 401, 401, 429, 429]);
  });

  // --- admin --------------------------------------------------------------------
  let riyaId = null;

  await test('admins can list users', async () => {
    const { status, data } = await api('/api/admin/users');
    assert.strictEqual(status, 200);
    const riya = data.items.find((u) => u.username === 'riya.analyst');
    assert.ok(riya);
    riyaId = riya.id;
    assert.ok(!JSON.stringify(data).match(/"(hash|salt|mfaSecret|passwordResetHash|emailVerifyHash)"/), 'no secrets in the listing');
  });

  await test('analysts cannot reach admin endpoints', async () => {
    const saved = session; session = null;
    await asRiya(RIYA_NEW);
    const { status } = await api('/api/admin/users');
    session = saved;
    assert.strictEqual(status, 403);
  });

  await test('disabling an account blocks sign-in and ends its sessions', async () => {
    const saved = session; session = null;
    await asRiya(RIYA_NEW); const riyaSession = session;
    session = saved;
    assert.strictEqual((await api(`/api/admin/users/${riyaId}/disable`, { method: 'POST', body: {} })).status, 200);
    session = riyaSession;
    const live = (await api('/api/auth/me')).status;
    session = null;
    const login = await asRiya(RIYA_NEW);
    session = saved;
    assert.strictEqual(live, 401);
    assert.strictEqual(login.data.code, 'ACCOUNT_DISABLED');
    assert.strictEqual((await api(`/api/admin/users/${riyaId}/enable`, { method: 'POST', body: {} })).status, 200);
  });

  await test('admins cannot disable themselves', async () => {
    const me = await api('/api/auth/me');
    const { status } = await api(`/api/admin/users/${me.data.user.id}/disable`, { method: 'POST', body: {} });
    assert.strictEqual(status, 400);
  });

  await test('registration can be switched off from the admin page', async () => {
    assert.strictEqual((await api('/api/admin/settings', { method: 'PUT', body: { registrationEnabled: false } })).status, 200);
    assert.strictEqual((await api('/api/site')).data.registrationEnabled, false);
    const saved = session; session = null;
    const reg = await api('/api/auth/register', { method: 'POST', body: { username: 'late.comer', email: 'late@example.org', password: 'Late-Comer-2026' } });
    session = saved;
    assert.strictEqual(reg.status, 403);
    await api('/api/admin/settings', { method: 'PUT', body: { registrationEnabled: true } });
  });

  await test('the activity log records sign-ins and admin actions, never passwords', async () => {
    const { status, data } = await api('/api/admin/audit?limit=500');
    assert.strictEqual(status, 200);
    const events = new Set(data.items.map((e) => e.event));
    for (const e of ['auth.login', 'auth.register', 'auth.password_changed', 'auth.password_reset', 'admin.user_disabled', 'ioc.lookup']) {
      assert.ok(events.has(e), `logged ${e}`);
    }
    assert.ok(data.items.some((e) => e.event === 'auth.login' && e.outcome === 'failure'), 'failed sign-ins logged');
    const text = JSON.stringify(data);
    for (const secret of [ADMIN_PW, RIYA_NEW, RIYA_PW]) assert.ok(!text.includes(secret), 'no passwords in the log');
  });

  await test('analysts clear only their own lookup history', async () => {
    const saved = session; session = null;
    await asRiya(RIYA_NEW);
    await api('/api/ioc/lookup', { method: 'POST', body: { indicator: '9.9.9.9' } });
    const all = await api('/api/ioc/history?scope=all', { method: 'DELETE' });
    assert.strictEqual(all.status, 403, 'analysts cannot wipe everyone');
    const own = await api('/api/ioc/history', { method: 'DELETE' });
    session = saved;
    assert.strictEqual(own.data.removed, 1);
    const left = await api('/api/ioc/history?limit=500');
    assert.ok(left.data.total > 0, 'other analysts\' history survives');
  });

  // --- watchlist ------------------------------------------------------------------
  let watchId = null;

  await test('indicators can be added to the watchlist and screened', async () => {
    const { status, data } = await api('/api/watchlist', { method: 'POST', body: { indicator: '185.220.101.44', note: 'Tor exit seen in proxy logs' } });
    assert.strictEqual(status, 201);
    assert.ok(data.item.lastCheckedAt, 'baseline screening ran');
    watchId = data.item.id;
    const dup = await api('/api/watchlist', { method: 'POST', body: { indicator: '185.220.101.44' } });
    assert.strictEqual(dup.status, 409);
    const bad = await api('/api/watchlist', { method: 'POST', body: { indicator: 'not an indicator' } });
    assert.strictEqual(bad.status, 400);
  });

  await test('watchlists are private to each analyst', async () => {
    const saved = session; session = null;
    await asRiya(RIYA_NEW);
    const list = await api('/api/watchlist');
    const del = await api(`/api/watchlist/${watchId}`, { method: 'DELETE' });
    session = saved;
    assert.strictEqual(list.data.items.length, 0);
    assert.strictEqual(del.status, 404);
  });

  await test('a worsening verdict emails the owner', async () => {
    // Find an indicator the deterministic simulator flags, and watch it.
    let flagged = null;
    for (const candidate of ['45.155.205.233', 'secure-upi-verify.in', 'login-icici-alerts.com', 'phish-login-hdfc.top', '44d88612fea8a8f36de82e1278abb02f']) {
      // eslint-disable-next-line no-await-in-loop
      const r = await api('/api/ioc/lookup', { method: 'POST', body: { indicator: candidate } });
      if (['malicious', 'suspicious'].includes(r.data.verdict)) { flagged = r.data.indicator; break; }
    }
    assert.ok(flagged, 'the simulator flags at least one sample indicator');
    const added = await api('/api/watchlist', { method: 'POST', body: { indicator: flagged } });
    const flaggedId = added.data.item.id;

    const watchFile = path.join(tmpData, 'watchlist.json');
    const before = JSON.parse(fs.readFileSync(watchFile, 'utf8'));
    const entry = before.find((e) => e.id === flaggedId);
    // Pretend it was clean last time, then re-check.
    entry.verdict = 'clean';
    fs.writeFileSync(watchFile, JSON.stringify(before));

    // The admin has no email, so give the admin account one for this check.
    const usersFile = path.join(tmpData, 'users.json');
    const users = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    users.find((u) => u.username === config.defaultAdmin.username).email = 'soc-admin@example.org';
    fs.writeFileSync(usersFile, JSON.stringify(users));

    const sent = mailer.outbox.length;
    const { status, data } = await api(`/api/watchlist/${flaggedId}/check`, { method: 'POST', body: {} });
    assert.strictEqual(status, 200);
    assert.ok(data.item.lastAlertAt, 'alert recorded');
    const mail = mailer.outbox.slice(sent).find((m) => m.to === 'soc-admin@example.org');
    assert.ok(mail && mail.subject.includes(flagged), 'alert email sent');
    await api(`/api/watchlist/${flaggedId}`, { method: 'DELETE' });
  });

  await test('watchlist alerts can be turned off and entries removed', async () => {
    const off = await api(`/api/watchlist/${watchId}`, { method: 'PATCH', body: { alerts: false } });
    assert.strictEqual(off.data.item.alerts, false);
    assert.strictEqual((await api(`/api/watchlist/${watchId}`, { method: 'DELETE' })).status, 200);
    assert.strictEqual((await api('/api/watchlist')).data.items.length, 0);
  });

  await test('reset and confirmation pages are served', async () => {
    for (const page of ['/reset.html', '/verify.html', '/js/reset.js', '/js/verify.js']) {
      assert.strictEqual((await fetch(BASE + page)).status, 200, page);
    }
  });

  await test('frontend never stores the session or user in web storage', async () => {
    for (const f of ['/js/app.js', '/js/api.js', '/js/verify.js', '/js/reset.js']) {
      const text = await (await fetch(BASE + f)).text();
      const uses = (text.match(/(localStorage|sessionStorage)\.(setItem|getItem)\(([^)]*)\)/g) || []);
      uses.forEach((u) => assert.ok(/CONSENT_KEY/.test(u), `${f}: ${u}`));
    }
  });

  await test('logout clears the session cookie', async () => {
    const out = await api('/api/auth/logout', { method: 'POST', body: {} });
    assert.strictEqual(out.status, 200);
    assert.ok(!session, 'cookie cleared');
    const me = await api('/api/auth/me');
    assert.strictEqual(me.status, 401);
  });

  // --- summary -------------------------------------------------------------
  console.log(`\n  ${passed} passed, ${failed} failed\n`);
  server.close();
  fs.rmSync(tmpData, { recursive: true, force: true });
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error('Test harness failed:', err);
  process.exit(1);
});
