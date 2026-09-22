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

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Isolate the flat-file store so the test never touches real data.
const tmpData = fs.mkdtempSync(path.join(os.tmpdir(), 'cimi-test-'));
const config = require('../src/config');
config.dataDir = tmpData;

const { bootstrap } = require('../server');

const BASE = `http://127.0.0.1:${config.port}`;
let passed = 0;
let failed = 0;
let token = null;

async function api(pathname, options = {}) {
  const res = await fetch(BASE + pathname, {
    method: options.method || 'GET',
    headers: Object.assign(
      { Accept: 'application/json' },
      options.body ? { 'Content-Type': 'application/json' } : {},
      token ? { Authorization: `Bearer ${token}` } : {},
      options.headers || {}
    ),
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
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
    assert.ok(data.token, 'token issued');
    token = data.token;
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

  await test('registering a second analyst works', async () => {
    const { status } = await api('/api/auth/register', {
      method: 'POST',
      body: { username: 'riya.analyst', password: 'StrongPass#2026' },
    });
    assert.strictEqual(status, 201);
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
      body: { username: config.defaultAdmin.username, password: config.defaultAdmin.password },
    });
    assert.strictEqual(challenge.data.mfaRequired, true, 'login now demands a second factor');

    const withCode = await api('/api/auth/login', {
      method: 'POST',
      body: {
        username: config.defaultAdmin.username,
        password: config.defaultAdmin.password,
        mfaToken: totp.generate(setup.data.secret),
      },
    });
    assert.strictEqual(withCode.status, 200);
    assert.ok(withCode.data.token);

    const off = await api('/api/auth/mfa/disable', {
      method: 'POST', body: { password: config.defaultAdmin.password },
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
    const saved = token; token = null;
    const { status } = await api('/api/auth/register', {
      method: 'POST', body: { username: 'bot-' + Date.now(), password: 'BotPassword123', website: 'http://spam.example' },
    });
    assert.strictEqual(status, 201);
    const login = await api('/api/auth/login', { method: 'POST', body: { username: 'bot-x', password: 'BotPassword123' } });
    assert.strictEqual(login.status, 401, 'no account was actually created');
    token = saved;
  });

  await test('frontend bundle contains no provider API keys', async () => {
    const files = ['/js/app.js', '/js/api.js', '/js/charts.js', '/'];
    for (const f of files) {
      const text = await (await fetch(BASE + f)).text();
      assert.ok(!/API_KEY|apiKey\s*[:=]\s*['"][A-Za-z0-9]{20,}/.test(text), f);
    }
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
