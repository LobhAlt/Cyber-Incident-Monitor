'use strict';

const config = require('./src/config');
const { createApp } = require('./src/app');
const store = require('./src/services/store');
const authService = require('./src/services/auth');
const certin = require('./src/services/providers/certin');
const cisakev = require('./src/services/providers/cisakev');
const watchlist = require('./src/services/watchlist');
const mailer = require('./src/services/mailer');

async function bootstrap() {
  try {
    await store.init();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`\n[CIMI] Could not connect to MongoDB: ${err.message}\n` +
      '        Check MONGODB_URI, the database user\'s password, and that Atlas Network Access allows this server.\n');
    throw err;
  }
  store.ensureDataDir();
  const admin = await authService.ensureDefaultUser();

  const app = createApp();

  const server = app.listen(config.port, () => {
    const live = Object.entries(config.providerEnabled)
      .filter(([, enabled]) => enabled)
      .map(([name]) => name);

    /* eslint-disable no-console */
    console.log('');
    console.log('  ╔══════════════════════════════════════════════════════════════╗');
    console.log('  ║   CIMI · Cyber Incident Monitor in India                     ║');
    console.log('  ║   STIX 2.1-compliant threat intelligence aggregation         ║');
    console.log('  ╚══════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log(`   ▸ URL           http://localhost:${config.port}`);
    console.log(`   ▸ Environment   ${config.env}`);
    console.log(`   ▸ Storage       ${store.backend() === 'mongodb' ? `MongoDB (${config.mongodb.dbName})` : `files in ${config.dataDir}`}`);
    console.log(`   ▸ Live sources  ${live.length ? live.join(', ') : 'none (simulator active; add API keys in .env)'}`);
    console.log(`   ▸ Sign in as    ${admin.username} / ${config.defaultAdmin.password}`);
    const mailVia = { brevo: 'Brevo API', smtp: `SMTP via ${config.mail.host}`, console: 'not configured (confirmation links print here)' }[mailer.provider()];
    console.log(`   ▸ Email         ${mailVia}`);
    console.log('');
    /* eslint-enable no-console */
  });

  // Warm the slow feeds in the background so the first page load is fast.
  setTimeout(() => {
    cisakev.catalog().catch(() => {});
    certin.fetchAdvisories().catch(() => {});
  }, 1500);

  // Scheduled refresh of CERT-In advisories and the KEV catalog.
  if (config.scheduler.enabled) {
    const timer = setInterval(() => {
      certin.fetchAdvisories({ force: true }).catch(() => {});
      cisakev.catalog().catch(() => {});
      // Re-screen watched indicators and email owners whose verdicts got worse.
      watchlist.checkAll().catch((err) => console.error('[CIMI] Watchlist check failed:', err.message)); // eslint-disable-line no-console
    }, config.scheduler.intervalMs);
    if (timer.unref) timer.unref();
  }

  function shutdown(signal) {
    // eslint-disable-next-line no-console
    console.log(`\n[CIMI] ${signal} received, shutting down.`);
    server.close(() => store.close().finally(() => process.exit(0)));
    setTimeout(() => process.exit(0), 5000).unref();
  }
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  return server;
}

if (require.main === module) {
  bootstrap().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[CIMI] Failed to start:', err);
    process.exit(1);
  });
}

module.exports = { bootstrap };
