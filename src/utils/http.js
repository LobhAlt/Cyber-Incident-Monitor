'use strict';

const config = require('../config');

/**
 * fetch() wrapper with a hard timeout and normalised error reporting.
 * Never throws for non-2xx: it returns { ok:false, status, error }.
 */
async function request(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || config.httpTimeoutMs);

  try {
    const res = await fetch(url, {
      method: options.method || 'GET',
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
        Accept: options.accept || 'application/json, text/plain, */*',
        ...(options.headers || {}),
      },
      body: options.body,
      signal: controller.signal,
      redirect: 'follow',
    });

    const contentType = res.headers.get('content-type') || '';
    let payload;
    if (options.raw || !contentType.includes('json')) {
      payload = await res.text();
    } else {
      payload = await res.json().catch(() => null);
    }

    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        error: `HTTP ${res.status}`,
        data: payload,
      };
    }
    return { ok: true, status: res.status, data: payload };
  } catch (err) {
    const aborted = err && (err.name === 'AbortError' || err.name === 'TimeoutError');
    return {
      ok: false,
      status: 0,
      error: aborted ? 'request timed out' : (err && err.message) || 'network error',
      data: null,
    };
  } finally {
    clearTimeout(timeout);
  }
}

/** Retry with exponential back-off — used for WAF-protected endpoints (CERT-In). */
async function requestWithRetry(url, options = {}, attempts = 3, baseDelayMs = 700) {
  let last = null;
  for (let i = 0; i < attempts; i += 1) {
    last = await request(url, options);
    if (last.ok) return last;
    if (last.status && last.status >= 400 && last.status < 500 && last.status !== 429) return last;
    if (i < attempts - 1) {
      await new Promise((r) => setTimeout(r, baseDelayMs * 2 ** i));
    }
  }
  return last;
}

module.exports = { request, requestWithRetry };
