'use strict';

/**
 * One-step local launcher used by `npm start`. It only uses Node built-ins
 * until the dependencies are present, so it works on a fresh clone:
 *
 *   1. checks the Node.js version
 *   2. creates .env from .env.example if it is missing
 *   3. runs `npm install` if node_modules is missing
 *   4. picks the next free port if the configured one is taken
 *   5. starts the server and opens the dashboard in the default browser
 *
 * Set OPEN_BROWSER=false to skip step 5. Hosting (Render) runs `node server.js`.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
const { spawnSync, spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');

function step(msg) {
  // eslint-disable-next-line no-console
  console.log(`  ▸ ${msg}`);
}

function fail(msg) {
  // eslint-disable-next-line no-console
  console.error(`\n  ✖ ${msg}\n`);
  process.exit(1);
}

// 1. Node version ------------------------------------------------------------
const major = Number(process.versions.node.split('.')[0]);
if (major < 20) fail(`CIMI needs Node.js 20 or newer (found ${process.versions.node}). Get it from https://nodejs.org`);

// 2. .env ------------------------------------------------------------------
const envFile = path.join(ROOT, '.env');
if (!fs.existsSync(envFile)) {
  fs.copyFileSync(path.join(ROOT, '.env.example'), envFile);
  step('Created .env from .env.example (add API keys there for live data)');
}

// 3. dependencies ------------------------------------------------------------
if (!fs.existsSync(path.join(ROOT, 'node_modules', 'express'))) {
  step('Installing dependencies (first run only)…');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const res = spawnSync(npm, ['install', '--no-audit', '--no-fund'], { cwd: ROOT, stdio: 'inherit', shell: process.platform === 'win32' });
  if (res.status !== 0) fail('npm install failed. Check your internet connection and run it again.');
}

// 4. free port ---------------------------------------------------------------
function isFree(port) {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(port);
  });
}

async function pickPort(start) {
  for (let port = start; port < start + 20; port += 1) {
    // eslint-disable-next-line no-await-in-loop
    if (await isFree(port)) return port;
  }
  return fail(`Ports ${start}-${start + 19} are all in use. Set PORT in .env to a free port.`);
}

// 5. open browser ------------------------------------------------------------
function openBrowser(url) {
  const cmd = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'cmd'
      : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '""', url] : [url];
  try {
    spawn(cmd, args, { stdio: 'ignore', detached: true, windowsVerbatimArguments: true }).unref();
  } catch (e) { /* no browser available: the URL is printed anyway */ }
}

async function main() {
  require('dotenv').config({ path: envFile });
  const wanted = Number.parseInt(process.env.PORT, 10) || 3000;
  const port = await pickPort(wanted);
  if (port !== wanted) step(`Port ${wanted} is busy, using ${port} instead`);
  process.env.PORT = String(port);

  const { bootstrap } = require('../server');
  const server = await bootstrap();

  const shouldOpen = String(process.env.OPEN_BROWSER || 'true').toLowerCase() !== 'false' && !process.env.CI;
  if (shouldOpen) {
    const open = () => openBrowser(`http://localhost:${port}`);
    if (server.listening) open();
    else server.once('listening', open);
  }
}

main().catch((err) => fail(err && err.stack ? err.stack : String(err)));
