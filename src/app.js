'use strict';

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
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

  // --- Security headers ----------------------------------------------------
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          'default-src': ["'self'"],
          // Tailwind is loaded from the CDN; inline styles are used for chart geometry.
          // Tailwind is vendored locally (public/vendor/tailwind.js) so the UI
          // works fully offline; its JIT engine injects styles at runtime.
          'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          'style-src': ["'self'", "'unsafe-inline'"],
          'font-src': ["'self'", 'data:'],
          'img-src': ["'self'", 'data:'],
          'connect-src': ["'self'"],
          'object-src': ["'none'"],
          'frame-ancestors': ["'self'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(cors({ origin: true, credentials: false }));
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
  app.get('*', (req, res) => {
    res.sendFile(path.join(config.publicDir, 'index.html'));
  });

  app.use(notFound);
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
