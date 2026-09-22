'use strict';

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const config = require('./config');
const cache = require('./services/cache');
const { notFound, errorHandler } = require('./middleware/errors');

const authRoutes = require('./routes/auth');
const iocRoutes = require('./routes/ioc');
const feedRoutes = require('./routes/feeds');
const logRoutes = require('./routes/logs');
const correlationRoutes = require('./routes/correlation');
const dashboardRoutes = require('./routes/dashboard');

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // --- Force HTTPS (behind a reverse proxy / load balancer) ---------------
  if (config.forceHttps) {
    app.use((req, res, next) => {
      if (req.secure || req.path === '/api/health') return next();
      return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
    });
  }

  // --- Security headers ----------------------------------------------------
  const analyticsOrigin = config.analytics.plausibleDomain
    ? new URL(config.analytics.plausibleSrc).origin
    : null;
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          'default-src': ["'self'"],
          // Tailwind is vendored locally (public/vendor/tailwind.js) so the UI
          // works fully offline; its JIT engine injects styles at runtime.
          'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", ...(analyticsOrigin ? [analyticsOrigin] : [])],
          'style-src': ["'self'", "'unsafe-inline'"],
          'font-src': ["'self'", 'data:'],
          'img-src': ["'self'", 'data:'],
          'connect-src': ["'self'", ...(analyticsOrigin ? [analyticsOrigin] : [])],
          'object-src': ["'none'"],
          'frame-ancestors': ["'self'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(cors({ origin: true, credentials: false }));
  app.use(compression());
  app.use(express.json({ limit: '4mb' }));
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));

  // --- Global API rate limit ----------------------------------------------
  app.use(
    '/api',
    rateLimit({
      windowMs: config.rateLimit.windowMs,
      max: config.rateLimit.max,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Rate limit exceeded — slow down and try again shortly' },
    })
  );

  // --- Public endpoints ----------------------------------------------------
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      service: 'CIMI — Cyber Incident Monitor in India',
      version: require('../package.json').version,
      stixVersion: '2.1',
      uptimeSeconds: Math.round(process.uptime()),
      demoMode: config.forceDemoMode,
      providers: config.providerEnabled,
      cache: { entries: cache.snapshot().entries, hitRate: cache.snapshot().hitRate },
      timestamp: new Date().toISOString(),
    });
  });

  /** Public, non-sensitive site settings the frontend needs before sign-in. */
  app.get('/api/site', (req, res) => {
    res.json({
      registrationEnabled: config.allowRegistration,
      analytics: config.analytics.plausibleDomain
        ? { provider: 'plausible', domain: config.analytics.plausibleDomain, src: config.analytics.plausibleSrc }
        : null,
    });
  });

  // --- Crawler files -------------------------------------------------------
  const baseUrl = (req) => config.publicUrl || `${req.protocol}://${req.get('host')}`;
  const PUBLIC_PAGES = ['/', '/privacy.html', '/terms.html'];

  app.get('/robots.txt', (req, res) => {
    res.type('text/plain').send(
      ['User-agent: *', 'Allow: /', 'Disallow: /api/', '', `Sitemap: ${baseUrl(req)}/sitemap.xml`, ''].join('\n')
    );
  });

  app.get('/sitemap.xml', (req, res) => {
    const base = baseUrl(req);
    const urls = PUBLIC_PAGES.map((p) => `  <url><loc>${base}${p === '/' ? '/' : p}</loc></url>`).join('\n');
    res.type('application/xml').send(
      `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`
    );
  });

  // --- API routes ----------------------------------------------------------
  app.use('/api/auth', authRoutes);
  app.use('/api/ioc', iocRoutes);
  app.use('/api/feeds', feedRoutes);
  app.use('/api/logs', logRoutes);
  app.use('/api/correlation', correlationRoutes);
  app.use('/api/dashboard', dashboardRoutes);

  // --- Static SPA ----------------------------------------------------------
  app.use(express.static(config.publicDir, { index: 'index.html', maxAge: '1h' }));

  app.get('/api/*', notFound);
  // The SPA routes by URL hash (#dashboard etc.), so any other path is a
  // genuine 404: serve the branded page with the correct status code.
  app.get('*', (req, res) => {
    res.status(404).sendFile(path.join(config.publicDir, '404.html'));
  });

  app.use(notFound);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
