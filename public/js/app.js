/* CIMI single-page application controller. */
(function () {
  'use strict';

  var Api = window.CimiApi;
  var Pw = window.CimiPassword;
  var C = window.CimiCharts;
  var esc = C.esc;

  var state = {
    page: 'dashboard',
    user: null,
    health: null,
    lastLookup: null,
    lastCorrelation: null,
    lastLogReport: null,
    dashboard: null,
    site: { registrationEnabled: true, analytics: null },
  };

  var PAGE_META = {
    dashboard:   { title: 'Security Dashboard',  sub: 'KPIs, verdict trend and geographic distribution from your lookup history' },
    lookup:      { title: 'IoC Lookup',          sub: 'Single and bulk indicator screening with a blended composite verdict' },
    correlation: { title: 'Threat Correlation',  sub: 'Group indicators by shared pulses, tags and techniques to surface campaigns' },
    logs:        { title: 'Log Analysis',        sub: 'Extract indicators from raw logs and auto-screen them against live intelligence' },
    feeds:       { title: 'Threat Intelligence Feeds', sub: 'CERT-In advisories, CISA KEV catalog, OTX pulses and feed health' },
    watchlist:   { title: 'Watchlist',           sub: 'Indicators re-screened every hour, with an email when a verdict gets worse' },
    admin:       { title: 'Admin',               sub: 'Accounts, sign-up policy and the activity log' },
    settings:    { title: 'Settings',            sub: 'Account, multi-factor authentication and platform status' },
  };

  // ======================= helpers =======================

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function toast(message, kind) {
    var root = $('#toast-root');
    var el = document.createElement('div');
    el.className = 'toast ' + (kind === 'error' ? 'toast-error' : kind === 'success' ? 'toast-success' : '');
    el.textContent = message;
    root.appendChild(el);
    setTimeout(function () {
      el.style.opacity = '0';
      el.style.transition = 'opacity .3s';
      setTimeout(function () { el.remove(); }, 320);
    }, kind === 'error' ? 6000 : 3800);
  }

  function pill(verdict) {
    var v = verdict || 'unknown';
    return '<span class="pill pill-' + esc(v) + '">' + esc(v) + '</span>';
  }

  function scoreColor(score) {
    if (score >= 65) return C.PALETTE.malicious;
    if (score >= 30) return C.PALETTE.suspicious;
    if (score > 0) return C.PALETTE.clean;
    return C.PALETTE.unknown;
  }

  function scoreBar(score) {
    return '<div class="scorebar" title="' + score + '/100"><span style="width:' +
      Math.max(2, score) + '%;background:' + scoreColor(score) + '"></span></div>';
  }

  function fmtDate(iso) {
    if (!iso) return '-';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso).slice(0, 16);
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  function fmtRelative(iso) {
    var diff = Date.now() - new Date(iso).getTime();
    if (isNaN(diff)) return '-';
    var mins = Math.round(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    var hrs = Math.round(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    return Math.round(hrs / 24) + 'd ago';
  }

  function card(title, subtitle, bodyHtml, extraClass) {
    return '<section class="card ' + (extraClass || '') + '">' +
      (title ? '<div class="card-pad pb-3"><h3 class="card-title">' + esc(title) + '</h3>' +
        (subtitle ? '<p class="card-sub">' + esc(subtitle) + '</p>' : '') + '</div>' : '') +
      '<div class="card-pad ' + (title ? 'pt-0' : '') + '">' + bodyHtml + '</div>' +
      '</section>';
  }

  function kpiTile(label, value, hint, accent) {
    return '<div class="card card-pad">' +
      '<p class="text-[11px] uppercase tracking-wider text-slate-500">' + esc(label) + '</p>' +
      '<p class="mt-1.5 text-2xl font-semibold tabular-nums" style="color:' + (accent || C.PALETTE.label) + '"' +
        (typeof value === 'number' ? ' data-count="' + value + '"' : '') + '>' + esc(value) + '</p>' +
      (hint ? '<p class="text-[11px] text-slate-600 mt-0.5">' + esc(hint) + '</p>' : '') +
      '</div>';
  }

  /** A "Download PDF report" button row placed above a result. */
  function reportToolbar(title, subtitle) {
    return '<div class="flex justify-end mb-3 no-print">' +
      '<button class="btn-ghost text-[11px]" data-print-report="' + esc(title) + '" data-print-sub="' + esc(subtitle || '') + '">Download PDF report</button>' +
      '</div>';
  }

  /**
   * Uses the browser's print dialog ("Save as PDF") with a print stylesheet
   * that turns the current result into a white, paper-friendly report.
   */
  function printReport(title, subtitle) {
    var u = state.user || {};
    $('#print-header').innerHTML =
      '<p style="font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:#e5192d;margin:0 0 4px">CIMI · Cyber Incident Monitor in India</p>' +
      '<h1 style="font-size:20px;font-weight:700;margin:0">' + esc(title) + '</h1>' +
      (subtitle ? '<p class="mono" style="margin:4px 0 0;font-size:12px">' + esc(subtitle) + '</p>' : '') +
      '<p style="font-size:11px;color:#555;margin:6px 0 16px;padding-bottom:10px;border-bottom:2px solid #e5192d">Generated ' +
        esc(new Date().toLocaleString()) + ' by ' + esc(u.username || 'analyst') + '. Verdicts blend VirusTotal, AbuseIPDB, AlienVault OTX and CISA KEV.</p>';
    var previous = document.title;
    document.title = title.replace(/\s+/g, '-').toLowerCase() + '-' + new Date().toISOString().slice(0, 10);
    window.print();
    document.title = previous;
  }

  function loading(message) {
    return '<div class="flex-center gap-3 py-16 text-sm text-slate-500"><span class="spinner"></span>' +
      esc(message || 'Loading…') + '</div>';
  }

  function errorBox(message) {
    return '<div class="card card-pad text-sm text-danger-400 bg-danger-500/5">' + esc(message) + '</div>';
  }

  function simBadge(isSim) {
    return isSim ? '<span class="pill pill-sim" title="Generated by the offline simulator. Add API keys in .env for live data">simulated</span>' : '';
  }

  // ======================= auth view =======================

  var authMode = 'signin';

  var loginGlobe = null;

  function showLogin() {
    var host = $('#login-globe');
    if (!loginGlobe && host && window.CimiGlobe) {
      // Decorative: a few common source countries, arcs ending in India.
      loginGlobe = window.CimiGlobe.mount(host, {
        label: 'Rotating globe with arcs ending in India',
        points: [
          { code: 'RU', value: 3, malicious: true }, { code: 'CN', value: 3, malicious: true },
          { code: 'NL', value: 2 }, { code: 'US', value: 2 }, { code: 'VN', value: 1, malicious: true },
          { code: 'BR', value: 1 }, { code: 'IR', value: 1 }, { code: 'SG', value: 1 },
        ],
      });
    }
    $('#app-view').classList.add('hidden');
    var view = $('#login-view');
    view.classList.remove('hidden');
    view.classList.add('is-visible');
    Api.health().then(function (h) {
      state.health = h;
      var live = Object.keys(h.providers).filter(function (k) { return h.providers[k]; });
      $('#login-hint').innerHTML = live.length
        ? 'Live sources: ' + esc(live.join(', ')) + '.'
        : 'No provider API keys configured, so CIMI is running with its offline intelligence simulator. Add keys to <code class="text-slate-400">.env</code> for live data.';
    }).catch(function () {
      $('#login-hint').textContent = 'Could not reach the CIMI API. Is the server running?';
    });
  }

  function showApp() {
    var view = $('#login-view');
    view.classList.add('hidden');
    view.classList.remove('is-visible');
    $('#app-view').classList.remove('hidden');

    var user = state.user || {};
    $('#user-name').textContent = user.username || 'analyst';
    $('#user-role').textContent = user.role || 'analyst';
    $('#user-initial').textContent = (user.username || 'A').charAt(0).toUpperCase();
    $('#nav-admin').classList.toggle('hidden', user.role !== 'admin');

    Api.health().then(function (h) {
      state.health = h;
      renderProviderStatus(h);
      var anySim = !h.providers.virustotal || !h.providers.abuseipdb || !h.providers.otx;
      $('#demo-badge').classList.toggle('hidden', !anySim);
    }).catch(function () {});

    navigate(state.page);
  }

  function renderProviderStatus(health) {
    var providers = [
      ['VirusTotal', health.providers.virustotal],
      ['AbuseIPDB', health.providers.abuseipdb],
      ['AlienVault OTX', health.providers.otx],
    ];
    $('#provider-status').innerHTML = providers.map(function (p) {
      return '<div class="flex items-center gap-2 px-2">' +
        '<span class="h-1.5 w-1.5 rounded-full" style="background:' + (p[1] ? C.PALETTE.clean : C.PALETTE.suspicious) + '"></span>' +
        '<span class="text-slate-500 flex-1 truncate">' + esc(p[0]) + '</span>' +
        '<span class="' + (p[1] ? 'text-safe-400' : 'text-warn-400') + '">' + (p[1] ? 'live' : 'sim') + '</span>' +
        '</div>';
    }).join('');
  }

  function setFieldError(inputId, message) {
    var input = $('#' + inputId);
    var el = $('#' + inputId + '-error');
    if (message) {
      input.setAttribute('aria-invalid', 'true');
      if (el) { el.textContent = message; el.classList.remove('hidden'); }
    } else {
      input.removeAttribute('aria-invalid');
      if (el) { el.textContent = ''; el.classList.add('hidden'); }
    }
  }

  /** Client-side checks mirror the server's rules so people get instant feedback. */
  function validateAuthForm(username, email, password, mfaToken) {
    var ok = true;
    var signup = authMode === 'signup';
    if (!username) { setFieldError('login-username', signup ? 'Choose a username.' : 'Enter your username or email.'); ok = false; }
    else if (signup && username.length < 3) { setFieldError('login-username', 'Username must be at least 3 characters.'); ok = false; }
    else if (signup && !/^[A-Za-z0-9._-]+$/.test(username)) { setFieldError('login-username', 'Use letters, numbers, dots, hyphens or underscores only.'); ok = false; }
    else setFieldError('login-username', null);

    if (signup) {
      if (!email) { setFieldError('login-email', 'Enter your email address.'); ok = false; }
      else if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) { setFieldError('login-email', 'That does not look like an email address.'); ok = false; }
      else setFieldError('login-email', null);
    }

    if (!password) { setFieldError('login-password', 'Enter your password.'); ok = false; }
    else if (signup && Pw.problem(password, { username: username, email: email })) { setFieldError('login-password', Pw.problem(password, { username: username, email: email }) + '.'); ok = false; }
    else setFieldError('login-password', null);

    if (!$('#mfa-wrap').classList.contains('hidden') && !/^\d{6}$/.test(mfaToken)) {
      $('#login-mfa').setAttribute('aria-invalid', 'true'); ok = false;
    } else $('#login-mfa').removeAttribute('aria-invalid');
    return ok;
  }

  function showAuthError(message, offerResend) {
    $('#login-error').textContent = message;
    $('#login-resend').classList.toggle('hidden', !offerResend);
    $('#login-error-wrap').classList.remove('hidden');
  }

  function hideAuthError() {
    $('#login-error-wrap').classList.add('hidden');
    $('#login-resend').classList.add('hidden');
  }

  // Remembered only in memory, so "Resend link" knows which account to use.
  var pendingVerification = null;

  /** Shows one panel of the sign-in card: the main form, the email notice, forgot password or forced change. */
  function showAuthPanel(name) {
    var panels = { form: '#login-form', verify: '#verify-notice', forgot: '#forgot-form', force: '#force-change-form' };
    Object.keys(panels).forEach(function (key) { $(panels[key]).classList.toggle('hidden', key !== name); });
    $('#tab-signin').parentNode.classList.toggle('hidden', name !== 'form');
  }

  function showVerifyNotice(email, delivery) {
    pendingVerification = email;
    $('#verify-email').textContent = email;
    $('#verify-console').classList.toggle('hidden', delivery !== 'console');
    showAuthPanel('verify');
  }

  function hideVerifyNotice() {
    showAuthPanel('form');
  }

  function showForgot() {
    $('#forgot-login').value = $('#login-username').value.trim();
    $('#forgot-status').classList.add('hidden');
    showAuthPanel('forgot');
    $('#forgot-login').focus();
  }

  function handleForgotSubmit(event) {
    event.preventDefault();
    var login = $('#forgot-login').value.trim();
    if (!login) return $('#forgot-login').focus();
    var button = $('#forgot-submit');
    button.disabled = true;
    Api.forgotPassword(login).then(function (res) {
      var status = $('#forgot-status');
      status.textContent = res.message + (state.site.emailConsole ? ' This server prints emails in its terminal.' : '');
      status.classList.remove('hidden');
    }).catch(function (err) { toast(err.message, 'error'); })
      .finally(function () { button.disabled = false; });
  }

  /** Shown after signing in with the published default password; nothing else works until it is changed. */
  function showForceChange() {
    showLogin();
    showAuthPanel('force');
    $('#force-error').classList.add('hidden');
    $('#force-current').focus();
  }

  function handleForceChange(event) {
    event.preventDefault();
    var u = state.user || {};
    var current = $('#force-current').value;
    var next = $('#force-new').value;
    var errorEl = $('#force-error');
    var issue = Pw.problem(next, { username: u.username, email: u.email });
    var message = !current ? 'Enter the current password.'
      : issue ? issue + '.'
        : next !== $('#force-confirm').value ? 'The new passwords do not match.' : null;
    if (message) { errorEl.textContent = message; errorEl.classList.remove('hidden'); return; }
    errorEl.classList.add('hidden');
    Api.changePassword(current, next).then(function (res) {
      state.user = res.user;
      $('#force-change-form').reset();
      showAuthPanel('form');
      toast('Password saved', 'success');
      showApp();
    }).catch(function (err) {
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
    });
  }

  function resendVerification(login) {
    if (!login) return;
    Api.resendVerification(login)
      .then(function (res) { toast(res.message || 'If the account is waiting for confirmation, a new link is on its way.', 'success'); })
      .catch(function (err) { toast(err.message, 'error'); });
  }

  function handleLoginSubmit(event) {
    event.preventDefault();
    var button = $('#login-submit');
    hideAuthError();

    var username = $('#login-username').value.trim();
    var email = $('#login-email').value.trim();
    var password = $('#login-password').value;
    var mfaToken = $('#login-mfa').value.trim();
    var website = $('#login-website').value; // honeypot, normally empty

    if (!validateAuthForm(username, email, password, mfaToken)) return;

    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span>' + (authMode === 'signin' ? 'Signing in…' : 'Creating account…');

    if (authMode === 'signup') {
      Api.registerUser({ username: username, email: email, password: password, website: website })
        .then(function (res) {
          $('#login-form').reset();
          showVerifyNotice(res.email || email, res.delivery);
        })
        .catch(function (err) { showAuthError(err.message, false); })
        .finally(resetButton);
      return;
    }

    Api.login({ username: username, password: password, mfaToken: mfaToken || undefined })
      .then(function (result) {
        if (result.mfaRequired) {
          $('#mfa-wrap').classList.remove('hidden');
          $('#login-mfa').focus();
          showAuthError('Enter the 6-digit code from your authenticator app.', false);
          return;
        }
        // The session token is in an HttpOnly cookie; only the public profile is kept, in memory.
        $('#login-password').value = '';
        state.user = result.user;
        if (result.user.mustChangePassword) return showForceChange();
        toast('Signed in as ' + result.user.username, 'success');
        showApp();
      })
      .catch(function (err) {
        showAuthError(err.message, err.code === 'EMAIL_UNVERIFIED');
        if (err.code === 'ACCOUNT_LOCKED' || err.code === 'BAD_CREDENTIALS') $('#forgot-link').classList.add('text-white');
      })
      .finally(resetButton);

    function resetButton() {
      button.disabled = false;
      button.textContent = authMode === 'signin' ? 'Sign in' : 'Create account';
    }
  }

  function setAuthMode(mode) {
    authMode = mode;
    var signup = mode === 'signup';
    $('#tab-signin').setAttribute('aria-selected', String(!signup));
    $('#tab-signup').setAttribute('aria-selected', String(signup));
    $('#login-submit').textContent = signup ? 'Create account' : 'Sign in';
    $('#login-username-label').textContent = signup ? 'Username' : 'Username or email';
    $('#login-username').setAttribute('placeholder', signup ? 'e.g. riya.adhe' : 'Username or email');
    $('#email-wrap').classList.toggle('hidden', !signup);
    $('#mfa-wrap').classList.add('hidden');
    hideAuthError();
    $('#login-password').setAttribute('autocomplete', signup ? 'new-password' : 'current-password');
    $('#signup-terms').classList.toggle('hidden', !signup);
    $('#signup-meter-slot').classList.toggle('hidden', !signup);
    $('#forgot-link').classList.toggle('hidden', signup);
    setFieldError('login-username', null);
    setFieldError('login-email', null);
    setFieldError('login-password', null);
  }

  // ======================= site config, consent, analytics =======================

  var CONSENT_KEY = 'cimi-consent'; // 'all' | 'essential'

  function readConsent() { try { return localStorage.getItem(CONSENT_KEY); } catch (e) { return null; } }

  function loadAnalytics() {
    var a = state.site.analytics;
    if (!a || a.provider !== 'plausible' || document.getElementById('analytics-script')) return;
    var script = document.createElement('script');
    script.id = 'analytics-script';
    script.defer = true;
    script.src = a.src;
    script.setAttribute('data-domain', a.domain);
    document.head.appendChild(script);
  }

  function initConsent() {
    var box = $('#consent');
    var hasAnalytics = Boolean(state.site.analytics);
    var choice = readConsent();

    if (choice === 'all' && hasAnalytics) loadAnalytics();
    if (choice) return; // already answered

    $('#consent-analytics-text').classList.toggle('hidden', !hasAnalytics);
    $('#consent-essential').classList.toggle('hidden', !hasAnalytics);
    $('#consent-accept').textContent = hasAnalytics ? 'Allow analytics' : 'OK';
    box.classList.remove('hidden');

    function decide(value) {
      try { localStorage.setItem(CONSENT_KEY, value); } catch (e) { /* ignore */ }
      box.classList.add('hidden');
      if (value === 'all') loadAnalytics();
    }
    $('#consent-accept').addEventListener('click', function () { decide(hasAnalytics ? 'all' : 'essential'); });
    $('#consent-essential').addEventListener('click', function () { decide('essential'); });
  }

  function loadSiteConfig() {
    return Api.get('/site').then(function (site) {
      state.site = site;
      if (!site.registrationEnabled) {
        $('#tab-signup').classList.add('hidden');
        if (authMode === 'signup') setAuthMode('signin');
      }
    }).catch(function () { /* keep defaults */ }).then(initConsent);
  }

  // ======================= navigation =======================

  function navigate(page) {
    if (!PAGE_META[page]) page = 'dashboard';
    state.page = page;
    $$('.nav-item').forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.page === page);
    });
    $('#page-title').textContent = PAGE_META[page].title;
    $('#page-subtitle').textContent = PAGE_META[page].sub;
    document.title = PAGE_META[page].title + ' | CIMI';
    closeSidebar();
    if (location.hash !== '#' + page) history.replaceState(null, '', '#' + page);
    renderPage();
  }

  function renderPage() {
    var root = $('#page-root');
    switch (state.page) {
      case 'dashboard': return renderDashboard(root);
      case 'lookup': return renderLookup(root);
      case 'correlation': return renderCorrelation(root);
      case 'logs': return renderLogs(root);
      case 'feeds': return renderFeeds(root);
      case 'settings': return renderSettings(root);
      case 'watchlist': return renderWatchlist(root);
      case 'admin':
        if (!state.user || state.user.role !== 'admin') return navigate('dashboard');
        return renderAdmin(root);
      default: return renderDashboard(root);
    }
  }

  function openSidebar() {
    $('#sidebar').classList.remove('-translate-x-full');
    $('#sidebar-backdrop').classList.remove('hidden');
  }
  function closeSidebar() {
    if (window.innerWidth < 1024) {
      $('#sidebar').classList.add('-translate-x-full');
      $('#sidebar-backdrop').classList.add('hidden');
    }
  }

  // ======================= dashboard =======================

  function renderDashboard(root) {
    root.innerHTML = loading('Building dashboard from your lookup history…');

    Api.dashboard(14).then(function (data) {
      state.dashboard = data;
      var k = data.kpis;

      var kpis = '<div class="grid grid-cols-2 lg:grid-cols-4 gap-3">' +
        kpiTile('Total lookups', k.totalLookups, k.uniqueIndicators + ' unique indicators') +
        kpiTile('Malicious', k.maliciousCount, k.detectionRate + '% detection rate', C.PALETTE.malicious) +
        kpiTile('Suspicious', k.suspiciousCount, 'needs analyst review', C.PALETTE.suspicious) +
        kpiTile('Last 24 hours', k.lookupsLast24h, 'avg score ' + k.averageScore + '/100') +
        '</div>';

      var trend = card('Daily verdict trend', 'Last ' + data.windowDays + ' days of screening activity',
        '<div class="h-56">' + C.trendChart(data.trend) + '</div>' +
        '<div class="flex flex-wrap gap-4 mt-3 text-[11px] text-slate-400">' +
          ['malicious', 'suspicious', 'clean'].map(function (key) {
            return '<span class="inline-flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm" style="background:' +
              C.PALETTE[key] + '"></span>' + key + '</span>';
          }).join('') +
        '</div>');

      var donut = card('Verdict distribution', 'All recorded lookups',
        '<div class="flex-center">' + C.donutChart([
          { label: 'Malicious', value: k.maliciousCount, color: C.PALETTE.malicious },
          { label: 'Suspicious', value: k.suspiciousCount, color: C.PALETTE.suspicious },
          { label: 'Clean', value: k.cleanCount, color: C.PALETTE.clean },
          { label: 'Unknown', value: k.unknownCount, color: C.PALETTE.unknown },
        ]) + '</div>' +
        '<div class="grid grid-cols-2 gap-2 mt-4 text-[11px]">' +
          [['Malicious', k.maliciousCount, C.PALETTE.malicious], ['Suspicious', k.suspiciousCount, C.PALETTE.suspicious],
           ['Clean', k.cleanCount, C.PALETTE.clean], ['Unknown', k.unknownCount, C.PALETTE.unknown]]
          .map(function (r) {
            return '<span class="inline-flex items-center gap-1.5 text-slate-400"><span class="h-2 w-2 rounded-sm" style="background:' +
              r[2] + '"></span>' + r[0] + ' <span class="text-slate-500 tabular-nums">' + r[1] + '</span></span>';
          }).join('') +
        '</div>');

      var geo = card('Threat origins', 'Source countries of screened indicators. Arcs end in India; red means at least one malicious verdict. Drag to spin',
        '<div class="globe-card"><div class="globe-wrap" id="dash-globe"></div><div>' +
        C.barList(data.geography.map(function (g) {
          return {
            label: g.countryName + ' (' + g.countryCode + ')',
            value: g.total,
            suffix: g.malicious ? '· ' + g.malicious + ' malicious' : '',
            color: g.malicious > 0 ? C.PALETTE.malicious : C.PALETTE.accent,
          };
        }), { empty: 'No geolocated indicators yet. Run an IP lookup.' }) + '</div></div>');

      var techniques = card('Top MITRE ATT&CK techniques', 'Mapped from correlated indicator evidence',
        C.barList(data.topTechniques.map(function (t) {
          return { label: t.id, value: t.count, color: C.PALETTE.accent };
        }), { empty: 'No techniques mapped yet.' }));

      var types = card('Indicator types', 'What your team is screening',
        C.barList(data.byType.map(function (t) {
          return { label: t.type.toUpperCase(), value: t.count, color: C.PALETTE.accent };
        }), { empty: 'No lookups yet.' }));

      var alerts = card('Recent alerts', 'Malicious and suspicious verdicts, newest first',
        data.recentAlerts.length
          ? '<div class="overflow-x-auto -mx-1"><table class="tbl"><thead><tr>' +
              '<th>Indicator</th><th>Type</th><th>Verdict</th><th>Score</th><th>Country</th><th>When</th>' +
            '</tr></thead><tbody>' +
            data.recentAlerts.map(function (a) {
              return '<tr>' +
                '<td class="mono truncate-cell"><button class="hover:text-brand-400 underline-offset-2 hover:underline" data-lookup="' + esc(a.indicator) + '">' + esc(a.indicator) + '</button></td>' +
                '<td class="text-slate-500 uppercase text-[11px]">' + esc(a.type) + '</td>' +
                '<td>' + pill(a.verdict) + '</td>' +
                '<td class="w-24">' + scoreBar(a.score) + '</td>' +
                '<td class="text-slate-500">' + esc(a.countryCode || '-') + '</td>' +
                '<td class="text-slate-500 whitespace-nowrap">' + esc(fmtRelative(a.queriedAt)) + '</td>' +
              '</tr>';
            }).join('') + '</tbody></table></div>'
          : C.emptyState('No alerts yet. Screen an indicator from the IoC Lookup page.'));

      var empty = k.totalLookups === 0
        ? '<div class="card card-pad mb-4 bg-brand-600/5 ring-brand-500/20">' +
          '<p class="text-sm text-slate-300">The dashboard is built entirely from your own lookup history, so it starts empty by design.</p>' +
          '<p class="text-xs text-slate-500 mt-1">Run a few lookups from the IoC Lookup page, or click below to screen a sample set.</p>' +
          '<button id="seed-demo" class="btn-primary mt-3 text-xs">Screen a sample indicator set</button></div>'
        : '';

      root.innerHTML = empty + kpis +
        '<div class="grid grid-cols-1 xl:grid-cols-3 gap-3 mt-3">' +
          '<div class="xl:col-span-2">' + trend + '</div>' + donut +
        '</div>' +
        '<div class="mt-3">' + geo + '</div>' +
        '<div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">' + techniques + types + '</div>' +
        '<div class="mt-3">' + alerts + '</div>';

      var globeHost = $('#dash-globe');
      if (globeHost && window.CimiGlobe) {
        window.CimiGlobe.mount(globeHost, {
          label: 'Globe showing ' + data.geography.length + ' source countries of screened indicators',
          points: data.geography.map(function (g) {
            return { code: g.countryCode, value: g.total, malicious: g.malicious > 0 };
          }),
        });
      }

      var seedBtn = $('#seed-demo');
      if (seedBtn) {
        seedBtn.addEventListener('click', function () {
          seedBtn.disabled = true;
          seedBtn.innerHTML = '<span class="spinner"></span>Screening 8 sample indicators…';
          Api.bulk([
            '185.220.101.44', '45.155.205.233', '103.86.49.11', '8.8.8.8',
            'secure-upi-verify.in', 'login-icici-alerts.com',
            '44d88612fea8a8f36de82e1278abb02f', 'CVE-2021-44228',
          ]).then(function () {
            toast('Sample indicators screened', 'success');
            renderDashboard(root);
          }).catch(function (err) { toast(err.message, 'error'); seedBtn.disabled = false; });
        });
      }

      bindLookupLinks(root);
    }).catch(function (err) {
      root.innerHTML = errorBox('Could not load the dashboard: ' + err.message);
    });
  }

  function bindLookupLinks(root) {
    $$('[data-lookup]', root).forEach(function (el) {
      el.addEventListener('click', function () {
        navigate('lookup');
        setTimeout(function () {
          var input = $('#lookup-input');
          if (input) {
            input.value = el.dataset.lookup;
            $('#lookup-form').dispatchEvent(new Event('submit', { cancelable: true }));
          }
        }, 60);
      });
    });
  }

  // ======================= IoC lookup =======================

  function renderLookup(root) {
    root.innerHTML =
      '<div class="grid grid-cols-1 xl:grid-cols-3 gap-3">' +
        '<div class="xl:col-span-2 space-y-3">' +
          '<section class="card card-pad">' +
            '<form id="lookup-form" class="flex flex-col sm:flex-row gap-2">' +
              '<input id="lookup-input" class="field flex-1 mono" placeholder="IP, domain, URL, MD5/SHA1/SHA256 hash or CVE-ID" autocomplete="off" spellcheck="false" />' +
              '<select id="lookup-type" class="field sm:w-36"><option value="auto">Auto-detect</option>' +
                '<option value="ip">IP</option><option value="domain">Domain</option><option value="url">URL</option>' +
                '<option value="md5">MD5</option><option value="sha1">SHA-1</option><option value="sha256">SHA-256</option>' +
                '<option value="cve">CVE</option></select>' +
              '<button type="submit" class="btn-primary sm:w-32">Screen</button>' +
            '</form>' +
            '<p id="detect-hint" class="text-[11px] text-slate-500 mt-2">Type an indicator. CIMI detects the type automatically and queries every applicable source in parallel.</p>' +
            '<div class="flex flex-wrap gap-1.5 mt-3">' +
              ['185.220.101.44', 'secure-upi-verify.in', '44d88612fea8a8f36de82e1278abb02f', 'CVE-2021-44228']
                .map(function (s) { return '<button class="btn-ghost text-[11px] mono" data-sample="' + esc(s) + '">' + esc(s) + '</button>'; }).join('') +
            '</div>' +
          '</section>' +
          '<div id="lookup-result"></div>' +
        '</div>' +
        '<div class="space-y-3">' +
          '<section class="card card-pad">' +
            '<h3 class="card-title">Bulk lookup</h3>' +
            '<p class="card-sub mb-3">Up to 25 indicators, one per line or comma-separated.</p>' +
            '<textarea id="bulk-input" class="field" placeholder="185.220.101.44&#10;secure-upi-verify.in&#10;44d88612fea8a8f36de82e1278abb02f"></textarea>' +
            '<div class="flex gap-2 mt-2">' +
              '<button id="bulk-run" class="btn-primary flex-1 text-xs">Screen batch</button>' +
              '<button id="bulk-stix" class="btn-ghost text-xs">Export STIX 2.1</button>' +
            '</div>' +
          '</section>' +
          '<div id="bulk-result"></div>' +
          '<section class="card card-pad">' +
            '<div class="flex items-center justify-between mb-3">' +
              '<h3 class="card-title">Recent lookups</h3>' +
              '<button id="clear-history" class="text-[11px] text-slate-500 hover:text-danger-400">Clear</button>' +
            '</div>' +
            '<div id="history-list">' + loading('Loading history…') + '</div>' +
          '</section>' +
        '</div>' +
      '</div>';

    $('#lookup-form').addEventListener('submit', function (e) {
      e.preventDefault();
      runLookup($('#lookup-input').value.trim(), $('#lookup-type').value);
    });

    $('#lookup-input').addEventListener('input', function () {
      var value = this.value.trim();
      var hint = $('#detect-hint');
      if (!value) { hint.textContent = 'Type an indicator. CIMI detects the type automatically and queries every applicable source in parallel.'; return; }
      Api.get('/ioc/detect?value=' + encodeURIComponent(value)).then(function (r) {
        hint.innerHTML = r.supported
          ? 'Detected type: <span class="text-brand-400 font-medium">' + esc(r.type.toUpperCase()) + '</span>'
          : '<span class="text-warn-400">Unrecognised format</span>. Check the value, or pick a type manually.';
      }).catch(function () {});
    });

    $$('[data-sample]', root).forEach(function (btn) {
      btn.addEventListener('click', function () {
        $('#lookup-input').value = btn.dataset.sample;
        runLookup(btn.dataset.sample, 'auto');
      });
    });

    $('#bulk-run').addEventListener('click', runBulk);
    $('#bulk-stix').addEventListener('click', function () {
      var list = parseList($('#bulk-input').value);
      if (!list.length) { toast('Enter at least one indicator in the bulk box', 'error'); return; }
      toast('Building STIX 2.1 bundle…');
      Api.downloadStix(list)
        .then(function () { toast('STIX bundle downloaded', 'success'); })
        .catch(function (err) { toast(err.message, 'error'); });
    });

    $('#clear-history').addEventListener('click', function () {
      Api.clearHistory().then(function () {
        toast('Lookup history cleared', 'success');
        loadHistory();
      }).catch(function (err) { toast(err.message, 'error'); });
    });

    loadHistory();

    if (state.lastLookup) renderLookupResult(state.lastLookup);
  }

  function parseList(text) {
    return String(text || '').split(/[\s,;]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  }

  function runLookup(value, type) {
    if (!value) { toast('Enter an indicator first', 'error'); return; }
    var target = $('#lookup-result');
    target.innerHTML = loading('Querying threat intelligence sources in parallel…');

    Api.lookup(value, type).then(function (result) {
      state.lastLookup = result;
      renderLookupResult(result);
      loadHistory();
    }).catch(function (err) {
      target.innerHTML = errorBox(err.message);
    });
  }

  function renderLookupResult(r) {
    var target = $('#lookup-result');
    if (!target) return;

    var header = '<section class="card card-pad">' +
      '<div class="flex flex-wrap items-start justify-between gap-3">' +
        '<div class="min-w-0">' +
          '<div class="flex items-center gap-2 flex-wrap">' + pill(r.verdict) +
            '<span class="text-[11px] uppercase tracking-wider text-slate-500">' + esc(r.type) + '</span>' +
            simBadge(r.simulated) + '</div>' +
          '<p class="mono text-sm text-white mt-2 break-all">' + esc(r.indicator) + '</p>' +
          '<p class="text-[11px] text-slate-500 mt-1">' + esc(r.sourcesAvailable) + ' of ' + esc(r.sourcesQueried) +
            ' sources responded · ' + esc(r.durationMs) + ' ms · confidence ' + esc(r.confidence) + '%' +
            (r.geo && r.geo.countryCode ? ' · ' + esc(r.geo.countryName || r.geo.countryCode) : '') + '</p>' +
        '</div>' +
        '<div class="text-right">' +
          '<p class="text-3xl font-semibold tabular-nums" style="color:' + scoreColor(r.score) + '">' + esc(r.score) + '<span class="text-sm text-slate-600">/100</span></p>' +
          '<p class="text-[11px] text-slate-500">' + esc(r.severity) + ' severity</p>' +
        '</div>' +
      '</div>' +
      '<div class="mt-3">' + scoreBar(r.score) + '</div>' +
      '<div class="flex gap-2 mt-3">' +
        '<button id="dl-stix-one" class="btn-ghost text-[11px]">Download STIX 2.1 bundle</button>' +
        '<button id="add-corr" class="btn-ghost text-[11px]">Add to correlation set</button>' +
        '<button id="watch-one" class="btn-ghost text-[11px]">Add to watchlist</button>' +
        '<button class="btn-ghost text-[11px]" data-print-report="IoC lookup report" data-print-sub="' + esc(r.indicator) + '">Download PDF report</button>' +
      '</div>' +
      '</section>';

    var sources = '<div class="grid grid-cols-1 md:grid-cols-3 gap-3">' + r.sources.map(function (s) {
      if (!s.available) {
        return '<div class="card card-pad opacity-70">' +
          '<div class="flex items-center justify-between"><h4 class="card-title">' + esc(s.source) + '</h4>' +
          '<span class="pill pill-unknown">n/a</span></div>' +
          '<p class="text-[11px] text-slate-500 mt-2">' + esc(s.reason || 'No response') + '</p></div>';
      }
      var rows = [];
      var st = s.stats || {};
      if (st.totalEngines !== undefined) rows.push(['Detections', st.malicious + ' / ' + st.totalEngines + ' engines']);
      if (st.suspicious !== undefined && st.totalEngines !== undefined) rows.push(['Suspicious', String(st.suspicious)]);
      if (st.abuseConfidenceScore !== undefined) rows.push(['Abuse confidence', st.abuseConfidenceScore + '%']);
      if (st.totalReports !== undefined) rows.push(['Reports', st.totalReports + ' from ' + st.distinctReporters + ' reporters']);
      if (st.pulseCount !== undefined) rows.push(['OTX pulses', String(st.pulseCount)]);
      if (st.inKevCatalog !== undefined) rows.push(['In KEV catalog', st.inKevCatalog ? 'Yes, exploited in the wild' : 'No']);

      var d = s.details || {};
      if (d.isp) rows.push(['ISP', d.isp]);
      if (d.countryName) rows.push(['Country', d.countryName]);
      if (d.asOwner) rows.push(['AS owner', d.asOwner]);
      if (d.usageType) rows.push(['Usage type', d.usageType]);
      if (d.fileType) rows.push(['File type', d.fileType]);
      if (d.meaningfulName) rows.push(['Name', d.meaningfulName]);
      if (d.vulnerabilityName) rows.push(['Vulnerability', d.vulnerabilityName]);
      if (d.knownRansomwareCampaignUse) rows.push(['Ransomware use', d.knownRansomwareCampaignUse]);
      if (d.dueDate) rows.push(['Remediation due', d.dueDate]);
      if (d.lastReportedAt) rows.push(['Last reported', fmtDate(d.lastReportedAt)]);
      if (d.lastAnalysis) rows.push(['Last analysis', fmtDate(d.lastAnalysis)]);

      var chips = []
        .concat(d.detectedFamilies || [], d.malwareFamilies || [], d.categories || [], (d.tags || []).slice(0, 8));

      return '<div class="card card-pad">' +
        '<div class="flex items-start justify-between gap-2 flex-wrap">' +
          '<h4 class="card-title">' + esc(s.source) + '</h4>' +
          '<div class="flex items-center gap-1 shrink-0">' + simBadge(s.simulated) + pill(s.verdict) + '</div>' +
        '</div>' +
        '<p class="mt-2 text-xl font-semibold tabular-nums" style="color:' + scoreColor(s.score) + '">' + esc(s.score) + '<span class="text-xs text-slate-600">/100</span></p>' +
        '<div class="mt-2">' + scoreBar(s.score) + '</div>' +
        '<dl class="mt-3 space-y-1.5">' + rows.slice(0, 7).map(function (row) {
          return '<div class="flex justify-between gap-3 text-[11px]"><dt class="text-slate-500 shrink-0">' + esc(row[0]) +
            '</dt><dd class="text-slate-300 text-right truncate">' + esc(row[1]) + '</dd></div>';
        }).join('') + '</dl>' +
        (chips.length ? '<div class="mt-2.5">' + chips.slice(0, 8).map(function (c) { return '<span class="tag">' + esc(c) + '</span>'; }).join('') + '</div>' : '') +
        (s.link ? '<a href="' + esc(s.link) + '" target="_blank" rel="noopener noreferrer" class="inline-block mt-3 text-[11px] text-brand-400 hover:underline">Open in ' + esc(s.source) + ' ↗</a>' : '') +
        (s.cached ? '<p class="text-[10px] text-slate-600 mt-2">served from cache' + (s.stale ? ' (stale: source unavailable)' : '') + '</p>' : '') +
      '</div>';
    }).join('') + '</div>';

    var attack = card('MITRE ATT&CK mapping', r.attackTechniques.length ? 'Techniques inferred from the collected evidence' : '',
      r.attackTechniques.length
        ? '<div class="space-y-2">' + r.attackTechniques.map(function (t) {
            return '<div class="rounded-lg bg-ink-800 p-3">' +
              '<div class="flex items-center justify-between gap-2">' +
                '<a href="https://attack.mitre.org/techniques/' + esc(t.id.replace('.', '/')) + '/" target="_blank" rel="noopener noreferrer" class="mono text-[11px] text-brand-400 hover:underline">' + esc(t.id) + '</a>' +
                '<span class="tag">' + esc(t.tactic) + '</span>' +
              '</div>' +
              '<p class="text-xs text-slate-200 mt-1">' + esc(t.name) + '</p>' +
              '<p class="text-[11px] text-slate-500 mt-1">' + esc(t.description) + '</p>' +
              (t.evidence && t.evidence.length ? '<p class="text-[10px] text-slate-600 mt-1.5">matched on: ' + esc(t.evidence.join(', ')) + '</p>' : '') +
            '</div>';
          }).join('') + '</div>'
        : C.emptyState('No ATT&CK techniques mapped: the indicator carried no behavioural signals.'));

    var timeline = card('Reputation timeline', 'Composite score over the last 14 days',
      '<div class="h-24">' + C.sparkline(r.reputationTimeline, { color: scoreColor(r.score) }) + '</div>');

    var stixPreview = card('STIX 2.1 bundle', r.stix.objects.length + ' objects, ready for SOAR/SIEM ingestion',
      '<pre class="mono text-[10px] leading-relaxed text-slate-400 bg-ink-900 rounded-lg p-3 overflow-x-auto max-h-64 overflow-y-auto">' +
      esc(JSON.stringify(r.stix, null, 2).slice(0, 4000)) + '</pre>');

    target.innerHTML = header +
      '<div class="mt-3">' + sources + '</div>' +
      '<div class="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-3">' + attack + timeline + '</div>' +
      '<div class="mt-3">' + stixPreview + '</div>';

    $('#watch-one').addEventListener('click', function () {
      Api.watchAdd(r.indicator).then(function () { toast(r.indicator + ' added to your watchlist', 'success'); })
        .catch(function (err) { toast(err.message, 'error'); });
    });
    $('#dl-stix-one').addEventListener('click', function () {
      Api.downloadStix([r.indicator])
        .then(function () { toast('STIX bundle downloaded', 'success'); })
        .catch(function (err) { toast(err.message, 'error'); });
    });
    $('#add-corr').addEventListener('click', function () {
      var box = $('#bulk-input');
      var existing = parseList(box.value);
      if (existing.indexOf(r.indicator) === -1) existing.push(r.indicator);
      box.value = existing.join('\n');
      toast('Added to the batch box. Use it for bulk screening or correlation', 'success');
    });
  }

  function runBulk() {
    var list = parseList($('#bulk-input').value);
    if (!list.length) { toast('Enter at least one indicator', 'error'); return; }
    if (list.length > 25) { toast('Maximum 25 indicators per batch', 'error'); return; }

    var target = $('#bulk-result');
    var btn = $('#bulk-run');
    btn.disabled = true;
    target.innerHTML = loading('Screening ' + list.length + ' indicators…');

    Api.bulk(list).then(function (data) {
      var s = data.summary;
      target.innerHTML = card('Batch results', s.total + ' indicators · avg score ' + s.averageScore + '/100',
        '<div class="flex flex-wrap gap-3 text-[11px] mb-3">' +
          '<span class="text-danger-400">' + s.malicious + ' malicious</span>' +
          '<span class="text-warn-400">' + s.suspicious + ' suspicious</span>' +
          '<span class="text-safe-400">' + s.clean + ' clean</span>' +
          '<span class="text-slate-500">' + s.unknown + ' unknown</span>' +
        '</div>' +
        '<div class="overflow-x-auto"><table class="tbl"><thead><tr><th>Indicator</th><th>Verdict</th><th>Score</th></tr></thead><tbody>' +
        data.results.map(function (r) {
          return '<tr><td class="mono truncate-cell"><button class="hover:text-brand-400" data-lookup="' + esc(r.indicator) + '">' + esc(r.indicator) + '</button></td>' +
            '<td>' + pill(r.verdict) + '</td><td class="w-20">' + scoreBar(r.score || 0) + '</td></tr>';
        }).join('') + '</tbody></table></div>');
      bindLookupLinks(target);
      loadHistory();
      toast('Screened ' + s.total + ' indicators', 'success');
    }).catch(function (err) {
      target.innerHTML = errorBox(err.message);
    }).finally(function () { btn.disabled = false; });
  }

  function loadHistory() {
    var target = $('#history-list');
    if (!target) return;
    Api.history(12).then(function (data) {
      if (!data.items.length) {
        target.innerHTML = C.emptyState('No lookups recorded yet.');
        return;
      }
      target.innerHTML = '<div class="space-y-1.5">' + data.items.map(function (h) {
        return '<button class="w-full text-left rounded-lg px-2.5 py-2 hover:bg-white/5 flex items-center gap-2" data-lookup="' + esc(h.indicator) + '">' +
          '<span class="h-1.5 w-1.5 rounded-full shrink-0" style="background:' + scoreColor(h.score) + '"></span>' +
          '<span class="mono text-[11px] text-slate-300 truncate flex-1">' + esc(h.indicator) + '</span>' +
          '<span class="text-[10px] text-slate-600 shrink-0">' + esc(fmtRelative(h.queriedAt)) + '</span>' +
        '</button>';
      }).join('') + '</div>';
      bindLookupLinks(target);
    }).catch(function () {
      target.innerHTML = C.emptyState('Could not load history.');
    });
  }

  // ======================= correlation =======================

  function renderCorrelation(root) {
    root.innerHTML =
      '<section class="card card-pad">' +
        '<h3 class="card-title">Correlate indicators</h3>' +
        '<p class="card-sub mb-3">Indicators sharing OTX pulses, tags, malware families, geography or ATT&amp;CK techniques are grouped into likely campaigns.</p>' +
        '<textarea id="corr-input" class="field" placeholder="185.220.101.44&#10;45.155.205.233&#10;secure-upi-verify.in&#10;login-icici-alerts.com"></textarea>' +
        '<div class="flex flex-wrap gap-2 mt-2">' +
          '<button id="corr-run" class="btn-primary text-xs">Correlate</button>' +
          '<button id="corr-history" class="btn-ghost text-xs">Correlate my recent lookups</button>' +
          '<button id="corr-sample" class="btn-ghost text-xs">Load sample set</button>' +
        '</div>' +
      '</section>' +
      '<div id="corr-result" class="mt-3"></div>';

    $('#corr-sample').addEventListener('click', function () {
      $('#corr-input').value = [
        '185.220.101.44', '45.155.205.233', '103.86.49.11',
        'secure-upi-verify.in', 'login-icici-alerts.com', 'cdn-jquery-min.top',
        '44d88612fea8a8f36de82e1278abb02f',
      ].join('\n');
    });

    $('#corr-run').addEventListener('click', function () {
      var list = parseList($('#corr-input').value);
      if (list.length < 2) { toast('Enter at least two indicators to correlate', 'error'); return; }
      runCorrelation(Api.correlate(list), list.length);
    });

    $('#corr-history').addEventListener('click', function () {
      runCorrelation(Api.correlateHistory(15), null);
    });

    if (state.lastCorrelation) renderCorrelationResult(state.lastCorrelation);
  }

  function runCorrelation(promise, count) {
    var target = $('#corr-result');
    target.innerHTML = loading('Correlating' + (count ? ' ' + count + ' indicators' : ' your recent lookups') + '…');
    promise.then(function (data) {
      state.lastCorrelation = data;
      renderCorrelationResult(data);
    }).catch(function (err) {
      target.innerHTML = errorBox(err.message);
    });
  }

  function renderCorrelationResult(data) {
    var target = $('#corr-result');
    if (!target) return;

    if (data.note) {
      target.innerHTML = '<div class="card card-pad text-sm text-slate-400">' + esc(data.note) + '</div>';
      return;
    }

    var s = data.summary;
    var kpis = '<div class="grid grid-cols-2 lg:grid-cols-4 gap-3">' +
      kpiTile('Indicators', s.indicators, 'in this correlation set') +
      kpiTile('Relationships', s.relationships, 'edges above the similarity threshold', C.PALETTE.accent) +
      kpiTile('Campaign clusters', s.clusters, s.isolated + ' isolated indicators', C.PALETTE.suspicious) +
      kpiTile('Malicious', s.malicious, 'highest score ' + s.highestScore + '/100', C.PALETTE.malicious) +
      '</div>';

    var graph = card('Relationship network', 'Node size reflects the composite score; edge thickness reflects shared-signal overlap',
      C.networkGraph(data.nodes, data.edges, { clusters: data.clusters.filter(function (c) { return !c.isolated; }) }));

    var clusters = card('Detected clusters', 'Connected components of the relationship graph',
      data.clusters.length
        ? '<div class="space-y-2">' + data.clusters.map(function (c) {
            return '<div class="rounded-lg bg-ink-800 p-3">' +
              '<div class="flex items-center justify-between gap-2 flex-wrap">' +
                '<p class="text-xs font-medium text-white">' + esc(c.label) + '</p>' +
                '<span class="pill ' + (c.isolated ? 'pill-unknown' : c.maxScore >= 65 ? 'pill-malicious' : 'pill-suspicious') + '">' + esc(c.severity) + '</span>' +
              '</div>' +
              '<div class="mt-2 flex flex-wrap gap-1">' + c.members.map(function (m) {
                return '<span class="tag mono">' + esc(m) + '</span>';
              }).join('') + '</div>' +
              (c.sharedSignals.length ? '<p class="text-[11px] text-slate-500 mt-2">shared: ' + esc(c.sharedSignals.join(' · ')) + '</p>' : '') +
            '</div>';
          }).join('') + '</div>'
        : C.emptyState('No clusters found.'));

    var edges = card('Relationships', 'Why each pair of indicators is linked',
      data.edges.length
        ? '<div class="overflow-x-auto"><table class="tbl"><thead><tr><th>Indicator A</th><th>Indicator B</th><th>Strength</th><th>Shared signals</th></tr></thead><tbody>' +
          data.edges.slice(0, 40).map(function (e) {
            return '<tr><td class="mono truncate-cell">' + esc(e.source) + '</td><td class="mono truncate-cell">' + esc(e.target) + '</td>' +
              '<td class="w-20">' + scoreBar(Math.round(e.weight * 100)) + '</td>' +
              '<td class="text-slate-400 text-[11px]">' + esc(e.shared.join(', ')) + '</td></tr>';
          }).join('') + '</tbody></table></div>'
        : C.emptyState('No indicator pairs shared enough signals to be linked.'));

    target.innerHTML = reportToolbar('Threat correlation report', s.indicators + ' indicators') +
      kpis + '<div class="mt-3">' + graph + '</div>' +
      '<div class="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-3">' + clusters + edges + '</div>';
  }

  // ======================= log analysis =======================

  var SAMPLE_LOG = [
    '2026-09-14T08:12:44Z sshd[2211]: Failed password for root from 185.220.101.44 port 51022 ssh2',
    '2026-09-14T08:12:47Z sshd[2213]: Failed password for admin from 185.220.101.44 port 51044 ssh2',
    '2026-09-14T08:15:02Z firewall: DENY tcp 45.155.205.233:4444 -> 10.4.2.19:3389',
    '2026-09-14T08:19:31Z proxy: GET http://secure-upi-verify.in/login.php 200 user=finance01',
    '2026-09-14T08:21:09Z proxy: GET https://login-icici-alerts.com/auth 302 user=finance01',
    '2026-09-14T08:24:55Z edr: process notepad.exe spawned child, sha256=9f2c1b8a7d6e5f4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918077665544',
    '2026-09-14T08:25:10Z edr: quarantined file md5=44d88612fea8a8f36de82e1278abb02f name=invoice_sept.exe',
    '2026-09-14T08:31:02Z dns: query cdn-jquery-min.top from 10.4.2.19',
    '2026-09-14T08:40:17Z vuln-scan: host 10.4.2.31 affected by CVE-2021-44228',
    '2026-09-14T08:44:51Z firewall: ALLOW tcp 103.86.49.11:443 -> 10.4.2.19:49812',
  ].join('\n');

  function renderLogs(root) {
    root.innerHTML =
      '<div class="grid grid-cols-1 xl:grid-cols-3 gap-3">' +
        '<section class="card card-pad xl:col-span-1">' +
          '<h3 class="card-title">Upload or paste a log</h3>' +
          '<p class="card-sub mb-3">IPs, domains, URLs and hashes are extracted by regex; the first 15 unique indicators are screened automatically.</p>' +
          '<input id="log-file" type="file" accept=".log,.txt,.csv,.json,text/*" class="field text-xs mb-2" />' +
          '<textarea id="log-input" class="field" style="min-height:14rem" placeholder="Paste raw log lines here…"></textarea>' +
          '<div class="flex gap-2 mt-2">' +
            '<button id="log-run" class="btn-primary flex-1 text-xs">Analyse log</button>' +
            '<button id="log-sample" class="btn-ghost text-xs">Sample</button>' +
          '</div>' +
        '</section>' +
        '<div id="log-result" class="xl:col-span-2"></div>' +
      '</div>';

    $('#log-sample').addEventListener('click', function () { $('#log-input').value = SAMPLE_LOG; });

    $('#log-file').addEventListener('change', function () {
      var file = this.files && this.files[0];
      if (!file) return;
      if (file.size > 2 * 1024 * 1024) { toast('File exceeds the 2 MB limit', 'error'); this.value = ''; return; }
      var reader = new FileReader();
      reader.onload = function () {
        $('#log-input').value = String(reader.result || '');
        toast('Loaded ' + file.name, 'success');
      };
      reader.onerror = function () { toast('Could not read that file', 'error'); };
      reader.readAsText(file);
    });

    $('#log-run').addEventListener('click', function () {
      var content = $('#log-input').value;
      if (!content.trim()) { toast('Paste a log or choose a file first', 'error'); return; }
      var fileEl = $('#log-file');
      var name = fileEl.files && fileEl.files[0] ? fileEl.files[0].name : 'pasted-log.txt';
      var target = $('#log-result');
      target.innerHTML = loading('Extracting indicators and screening them…');
      Api.analyseLog(content, name).then(function (report) {
        state.lastLogReport = report;
        renderLogReport(report);
        toast('Screened ' + report.screenedCount + ' of ' + report.extraction.totalUnique + ' unique indicators', 'success');
      }).catch(function (err) {
        target.innerHTML = errorBox(err.message);
      });
    });

    if (state.lastLogReport) renderLogReport(state.lastLogReport);
    else $('#log-result').innerHTML = card('No analysis yet', '',
      C.emptyState('Paste a log on the left (or click “Sample”) and run the analysis.'));
  }

  function renderLogReport(report) {
    var target = $('#log-result');
    if (!target) return;
    var e = report.extraction;
    var s = report.summary;

    var head = '<div class="grid grid-cols-2 lg:grid-cols-4 gap-3">' +
      kpiTile('Lines parsed', report.stats.lines, report.format) +
      kpiTile('Unique indicators', e.totalUnique, e.ips + ' IP · ' + e.domains + ' domain · ' + e.urls + ' URL · ' + e.hashes + ' hash') +
      kpiTile('Screened', report.screenedCount, report.notScreened ? report.notScreened + ' not screened (limit ' + report.screenLimit + ')' : 'all within limit', C.PALETTE.accent) +
      kpiTile('Flagged', s.malicious + s.suspicious, s.malicious + ' malicious · ' + s.suspicious + ' suspicious',
        (s.malicious ? C.PALETTE.malicious : s.suspicious ? C.PALETTE.suspicious : C.PALETTE.label)) +
      '</div>';

    var findings = card('Screening results', report.fileName + ' · ' + fmtDate(report.analysedAt),
      report.findings.length
        ? '<div class="overflow-x-auto"><table class="tbl"><thead><tr>' +
          '<th>Indicator</th><th>Type</th><th>Hits</th><th>Verdict</th><th>Score</th><th>ATT&amp;CK</th>' +
          '</tr></thead><tbody>' + report.findings.map(function (f) {
            return '<tr>' +
              '<td class="mono truncate-cell"><button class="hover:text-brand-400" data-lookup="' + esc(f.indicator) + '">' + esc(f.indicator) + '</button></td>' +
              '<td class="text-slate-500 uppercase text-[11px]">' + esc(f.type) + '</td>' +
              '<td class="text-slate-400 tabular-nums">' + esc(f.occurrences) + '</td>' +
              '<td>' + pill(f.verdict) + '</td>' +
              '<td class="w-20">' + scoreBar(f.score) + '</td>' +
              '<td class="text-[10px] text-slate-500">' + esc((f.techniques || []).slice(0, 3).join(', ') || '-') + '</td>' +
            '</tr>';
          }).join('') + '</tbody></table></div>'
        : C.emptyState('No indicators found in this log.'));

    var extracted = card('Everything extracted', 'Raw regex extraction before screening',
      ['ips', 'domains', 'urls', 'sha256', 'sha1', 'md5', 'cves'].map(function (key) {
        var list = (report.extracted && report.extracted[key]) || [];
        if (!list.length) return '';
        return '<div class="mb-3"><p class="text-[11px] uppercase tracking-wider text-slate-500 mb-1">' + esc(key) +
          ' <span class="text-slate-600">(' + list.length + ')</span></p><div>' +
          list.slice(0, 40).map(function (v) { return '<span class="tag mono">' + esc(v) + '</span>'; }).join('') + '</div></div>';
      }).join('') || C.emptyState('Nothing extracted.'));

    target.innerHTML = reportToolbar('Log analysis report', report.fileName) +
      head + '<div class="mt-3">' + findings + '</div><div class="mt-3">' + extracted + '</div>';
    bindLookupLinks(target);
  }

  // ======================= feeds =======================

  function renderFeeds(root) {
    root.innerHTML =
      '<div class="flex flex-wrap gap-1 p-1 rounded-lg bg-ink-850 ring-1 ring-white/10 w-fit mb-3" id="feed-tabs">' +
        ['certin', 'kev', 'otx', 'health'].map(function (key, i) {
          var labels = { certin: 'CERT-In Advisories', kev: 'CISA KEV', otx: 'OTX Pulses', health: 'Feed Health' };
          return '<button class="auth-tab rounded-md px-3 py-1.5 text-xs font-medium" data-feed="' + key + '" aria-selected="' + (i === 0) + '">' +
            labels[key] + '</button>';
        }).join('') +
      '</div>' +
      '<div id="feed-body"></div>';

    $$('#feed-tabs [data-feed]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        $$('#feed-tabs [data-feed]').forEach(function (b) { b.setAttribute('aria-selected', String(b === btn)); });
        loadFeed(btn.dataset.feed);
      });
    });

    loadFeed('certin');
  }

  function loadFeed(kind) {
    var body = $('#feed-body');
    body.innerHTML = loading('Fetching feed…');

    if (kind === 'certin') {
      Api.certin('?limit=40').then(function (data) {
        body.innerHTML = card('CERT-In advisories',
          (data.live ? 'Live from the CERT-In servlet endpoint' : 'Offline sample: CERT-In endpoint unavailable') +
          ' · fetched ' + fmtRelative(data.fetchedAt),
          (data.simulated ? '<p class="text-[11px] text-warn-400 bg-warn-500/10 rounded-lg px-3 py-2 mb-3">' +
            esc(data.reason || 'Scraper degraded. Showing a representative offline advisory set.') + '</p>' : '') +
          (data.items.length
            ? '<div class="space-y-2">' + data.items.map(function (a) {
                var sevClass = a.severity === 'Critical' ? 'pill-malicious' : a.severity === 'High' ? 'pill-suspicious' : 'pill-unknown';
                return '<div class="rounded-lg bg-ink-800 p-3">' +
                  '<div class="flex items-start justify-between gap-3 flex-wrap">' +
                    '<div class="min-w-0"><p class="text-xs font-medium text-white">' + esc(a.title) + '</p>' +
                    '<p class="mono text-[10px] text-slate-500 mt-0.5">' + esc(a.id) + ' · ' + esc(a.category) + ' · ' + esc(fmtDate(a.publishedAt)) + '</p></div>' +
                    '<span class="pill ' + sevClass + '">' + esc(a.severity) + '</span>' +
                  '</div>' +
                  '<p class="text-[11px] text-slate-400 mt-2">' + esc(a.summary) + '</p>' +
                  (a.cves && a.cves.length ? '<div class="mt-2">' + a.cves.map(function (c) {
                    return '<button class="tag mono hover:text-brand-400" data-lookup="' + esc(c) + '">' + esc(c) + '</button>';
                  }).join('') + '</div>' : '') +
                '</div>';
              }).join('') + '</div>'
            : C.emptyState('No advisories returned.')));
        bindLookupLinks(body);
      }).catch(function (err) { body.innerHTML = errorBox(err.message); });
      return;
    }

    if (kind === 'kev') {
      Api.kev('?limit=40').then(function (data) {
        body.innerHTML = card('CISA Known Exploited Vulnerabilities',
          'Catalog version ' + (data.catalogVersion || 'unknown') + ' · ' + (data.total || 0) + ' entries' +
          (data.simulated ? ' · offline sample' : ''),
          '<div class="overflow-x-auto"><table class="tbl"><thead><tr>' +
          '<th>CVE</th><th>Vendor</th><th>Product</th><th>Vulnerability</th><th>Added</th><th>Ransomware</th>' +
          '</tr></thead><tbody>' + (data.items || []).map(function (v) {
            return '<tr>' +
              '<td class="mono"><button class="hover:text-brand-400" data-lookup="' + esc(v.cveID) + '">' + esc(v.cveID) + '</button></td>' +
              '<td class="text-slate-400">' + esc(v.vendorProject) + '</td>' +
              '<td class="text-slate-400">' + esc(v.product) + '</td>' +
              '<td class="truncate-cell">' + esc(v.vulnerabilityName) + '</td>' +
              '<td class="text-slate-500 whitespace-nowrap">' + esc(v.dateAdded) + '</td>' +
              '<td>' + (String(v.knownRansomwareCampaignUse).toLowerCase() === 'known'
                ? '<span class="pill pill-malicious">known</span>' : '<span class="text-slate-600 text-[11px]">-</span>') + '</td>' +
            '</tr>';
          }).join('') + '</tbody></table></div>');
        bindLookupLinks(body);
      }).catch(function (err) { body.innerHTML = errorBox(err.message); });
      return;
    }

    if (kind === 'otx') {
      Api.otxFeed().then(function (data) {
        body.innerHTML = card('AlienVault OTX pulses',
          data.live ? 'Subscribed community pulses' : 'Simulated pulses. Add an OTX API key for live data',
          data.items.length
            ? '<div class="grid grid-cols-1 md:grid-cols-2 gap-2">' + data.items.map(function (p) {
                return '<div class="rounded-lg bg-ink-800 p-3">' +
                  '<p class="text-xs font-medium text-white">' + esc(p.name) + '</p>' +
                  '<p class="text-[10px] text-slate-500 mt-0.5">by ' + esc(p.author) + ' · ' + esc(fmtDate(p.created)) + '</p>' +
                  (p.adversary ? '<p class="text-[11px] text-danger-400 mt-1">adversary: ' + esc(p.adversary) + '</p>' : '') +
                  '<div class="mt-2">' + (p.tags || []).slice(0, 6).map(function (t) { return '<span class="tag">' + esc(t) + '</span>'; }).join('') + '</div>' +
                '</div>';
              }).join('') + '</div>'
            : C.emptyState('No pulses available.'));
      }).catch(function (err) { body.innerHTML = errorBox(err.message); });
      return;
    }

    Api.feedHealth().then(function (data) {
      body.innerHTML = card('Feed health and data quality', 'Generated ' + fmtDate(data.generatedAt),
        '<div class="grid grid-cols-1 md:grid-cols-3 gap-3">' + data.feeds.map(function (f) {
          return '<div class="card card-pad bg-ink-800">' +
            '<div class="flex items-center justify-between gap-2"><h4 class="card-title">' + esc(f.name) + '</h4>' +
            '<span class="pill ' + (f.live ? 'pill-clean' : 'pill-suspicious') + '">' + esc(f.status) + '</span></div>' +
            '<p class="mt-3 text-2xl font-semibold tabular-nums" style="color:' +
              (f.qualityScore >= 70 ? C.PALETTE.clean : f.qualityScore >= 40 ? C.PALETTE.suspicious : C.PALETTE.malicious) +
              '">' + esc(f.qualityScore) + '<span class="text-xs text-slate-600">/100</span></p>' +
            '<p class="text-[11px] text-slate-500">data-quality score</p>' +
            '<div class="mt-2">' + scoreBar(f.qualityScore) + '</div>' +
            '<dl class="mt-3 space-y-1 text-[11px]">' +
              '<div class="flex justify-between"><dt class="text-slate-500">Items</dt><dd class="text-slate-300">' + esc(f.items) + '</dd></div>' +
              '<div class="flex justify-between"><dt class="text-slate-500">Newest entry</dt><dd class="text-slate-300">' +
                (f.newestAgeDays === null ? '-' : esc(f.newestAgeDays) + ' d ago') + '</dd></div>' +
            '</dl>' +
            '<p class="text-[10px] text-slate-600 mt-2">' + esc(f.note) + '</p>' +
          '</div>';
        }).join('') + '</div>' +
        '<div class="mt-4 rounded-lg bg-ink-800 p-3">' +
          '<p class="text-[11px] text-slate-400">Cache: <span class="text-slate-200">' + esc(data.cache.entries) +
          '</span> entries · hit rate <span class="text-slate-200">' + esc(data.cache.hitRate) + '%</span> · ' +
          esc(data.cache.hits) + ' hits / ' + esc(data.cache.misses) + ' misses</p>' +
        '</div>');
    }).catch(function (err) { body.innerHTML = errorBox(err.message); });
  }

  // ======================= settings =======================

  function renderSettings(root) {
    var u = state.user || {};
    var h = state.health || { providers: {} };

    root.innerHTML = '<div class="grid grid-cols-1 lg:grid-cols-2 gap-3">' +
      card('Account', '',
        '<dl class="space-y-2 text-xs">' +
          '<div class="flex justify-between"><dt class="text-slate-500">Username</dt><dd class="text-slate-200">' + esc(u.username || '-') + '</dd></div>' +
          '<div class="flex justify-between gap-3"><dt class="text-slate-500">Email</dt><dd class="text-slate-200 truncate">' + esc(u.email || '-') + '</dd></div>' +
          '<div class="flex justify-between"><dt class="text-slate-500">Role</dt><dd class="text-slate-200">' + esc(u.role || '-') + '</dd></div>' +
          '<div class="flex justify-between"><dt class="text-slate-500">Account created</dt><dd class="text-slate-200">' + esc(fmtDate(u.createdAt)) + '</dd></div>' +
          '<div class="flex justify-between"><dt class="text-slate-500">MFA</dt><dd class="' + (u.mfaEnabled ? 'text-safe-400' : 'text-warn-400') + '">' +
            (u.mfaEnabled ? 'Enabled' : 'Not enabled') + '</dd></div>' +
        '</dl>') +
      card('Multi-factor authentication', 'TOTP (RFC 6238). Works with Google Authenticator, Authy or any TOTP app',
        '<div id="mfa-panel">' +
          (u.mfaEnabled
            ? '<p class="text-xs text-slate-400 mb-3">MFA is active on this account. You will be asked for a 6-digit code at every sign-in.</p>' +
              '<input id="mfa-password" type="password" class="field mb-2" placeholder="Confirm your password to disable" />' +
              '<button id="mfa-disable" class="btn-ghost text-xs">Disable MFA</button>'
            : '<p class="text-xs text-slate-400 mb-3">Add a second factor to your analyst account.</p>' +
              '<button id="mfa-start" class="btn-primary text-xs">Set up MFA</button>') +
        '</div>') +
      card('Platform status', 'Provider wiring and caching',
        '<dl class="space-y-2 text-xs">' +
          [['VirusTotal', h.providers.virustotal], ['AbuseIPDB', h.providers.abuseipdb], ['AlienVault OTX', h.providers.otx]]
            .map(function (p) {
              return '<div class="flex justify-between"><dt class="text-slate-500">' + esc(p[0]) + '</dt><dd class="' +
                (p[1] ? 'text-safe-400' : 'text-warn-400') + '">' + (p[1] ? 'live API key configured' : 'simulator (no key)') + '</dd></div>';
            }).join('') +
          '<div class="flex justify-between"><dt class="text-slate-500">CISA KEV</dt><dd class="text-slate-300">public feed, 6 h cache</dd></div>' +
          '<div class="flex justify-between"><dt class="text-slate-500">CERT-In</dt><dd class="text-slate-300">scraper with offline fallback</dd></div>' +
          '<div class="flex justify-between"><dt class="text-slate-500">STIX</dt><dd class="text-slate-300">version ' + esc(h.stixVersion || '2.1') + '</dd></div>' +
          '<div class="flex justify-between"><dt class="text-slate-500">Uptime</dt><dd class="text-slate-300">' + esc(h.uptimeSeconds || 0) + ' s</dd></div>' +
        '</dl>' +
        '<p class="text-[11px] text-slate-600 mt-3">Add provider API keys to <code>.env</code> and restart the server to switch a source from simulator to live.</p>') +
      card('Data', 'Flat-file JSON store. No database server required',
        '<p class="text-xs text-slate-400 mb-3">Users, lookup history, log reports and advisories are stored as JSON files under <code>data/</code>.</p>' +
        '<button id="wipe-history" class="btn-ghost text-xs">Clear my lookup history</button>') +
      card('Password', u.passwordChangedAt ? 'Last changed ' + fmtDate(u.passwordChangedAt) : 'Changing it signs out your other devices',
        '<form id="pw-form" class="space-y-3" novalidate>' +
          '<input id="pw-current" type="password" class="field" autocomplete="current-password" placeholder="Current password" />' +
          '<div><input id="pw-new" type="password" class="field" autocomplete="new-password" placeholder="New password" />' + Pw.meterHtml('pw-meter') + '</div>' +
          '<input id="pw-confirm" type="password" class="field" autocomplete="new-password" placeholder="Type the new password again" />' +
          '<button type="submit" class="btn-primary text-xs">Change password</button>' +
        '</form>') +
      card('Sessions', 'Signed in on a shared or lost device?',
        '<p class="text-xs text-slate-400 mb-3">Sign out of CIMI on every browser and device, including this one.</p>' +
        '<button id="logout-all" class="btn-ghost text-xs">Sign out everywhere</button>') +
      '</div>';

    var startBtn = $('#mfa-start');
    if (startBtn) {
      startBtn.addEventListener('click', function () {
        Api.mfaSetup().then(function (data) {
          $('#mfa-panel').innerHTML =
            '<p class="text-xs text-slate-400 mb-2">Add this secret to your authenticator app, then confirm with the generated code.</p>' +
            '<p class="mono text-xs bg-ink-800 rounded-lg p-3 break-all text-brand-400 mb-2">' + esc(data.secret) + '</p>' +
            '<p class="text-[10px] text-slate-600 break-all mb-3">' + esc(data.otpauthUrl) + '</p>' +
            '<input id="mfa-code" class="field mono tracking-[0.3em] mb-2" maxlength="6" inputmode="numeric" placeholder="000000" />' +
            '<button id="mfa-confirm" class="btn-primary text-xs">Confirm and enable</button>';
          $('#mfa-confirm').addEventListener('click', function () {
            Api.mfaConfirm($('#mfa-code').value.trim()).then(function () {
              toast('MFA enabled', 'success');
              return Api.me();
            }).then(function (res) {
              state.user = res.user;
              renderSettings(root);
            }).catch(function (err) { toast(err.message, 'error'); });
          });
        }).catch(function (err) { toast(err.message, 'error'); });
      });
    }

    var disableBtn = $('#mfa-disable');
    if (disableBtn) {
      disableBtn.addEventListener('click', function () {
        Api.mfaDisable($('#mfa-password').value).then(function () {
          toast('MFA disabled', 'success');
          return Api.me();
        }).then(function (res) {
          state.user = res.user;
          renderSettings(root);
        }).catch(function (err) { toast(err.message, 'error'); });
      });
    }

    $('#wipe-history').addEventListener('click', function () {
      if (!window.confirm('Delete every lookup you have made? Other analysts\' history is kept.')) return;
      Api.clearHistory().then(function (res) { toast(res.removed + ' lookups removed', 'success'); })
        .catch(function (err) { toast(err.message, 'error'); });
    });

    Pw.attach($('#pw-new'), $('#pw-meter'), function () { return { username: u.username, email: u.email }; });
    $('#pw-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var current = $('#pw-current').value;
      var next = $('#pw-new').value;
      var issue = Pw.problem(next, { username: u.username, email: u.email });
      if (!current) return toast('Enter your current password', 'error');
      if (issue) return toast(issue, 'error');
      if (next !== $('#pw-confirm').value) return toast('The new passwords do not match', 'error');
      Api.changePassword(current, next).then(function (res) {
        state.user = res.user;
        toast('Password changed. Other devices are signed out.', 'success');
        renderSettings(root);
      }).catch(function (err) { toast(err.message, 'error'); });
    });

    $('#logout-all').addEventListener('click', function () {
      if (!window.confirm('Sign out of CIMI on every device, including this one?')) return;
      Api.logoutAll().catch(function () {}).then(function () {
        endSession();
        toast('Signed out everywhere');
      });
    });
  }

  // ======================= watchlist =======================

  function renderWatchlist(root) {
    root.innerHTML =
      card('Watch an indicator', 'IP, domain, URL, file hash or CVE. Re-screened every hour; you get an email if its verdict gets worse',
        '<form id="watch-form" class="flex flex-col sm:flex-row gap-2" novalidate>' +
          '<input id="watch-indicator" class="field mono sm:flex-[2]" placeholder="185.220.101.44" maxlength="2048" />' +
          '<input id="watch-note" class="field sm:flex-1" placeholder="Note (optional)" maxlength="200" />' +
          '<button type="submit" class="btn-primary shrink-0">Add</button>' +
        '</form>' +
        ((state.user && !state.user.email) ? '<p class="text-[11px] text-warn-400 mt-3">Your account has no email address, so alerts are recorded in the activity log but not emailed.</p>' : '')) +
      '<div id="watch-list" class="mt-3">' + loading('Loading your watchlist…') + '</div>';

    $('#watch-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var value = $('#watch-indicator').value.trim();
      if (!value) return $('#watch-indicator').focus();
      var btn = event.target.querySelector('button');
      btn.disabled = true;
      Api.watchAdd(value, $('#watch-note').value.trim()).then(function (res) {
        toast(res.item.indicator + ' is now on your watchlist', 'success');
        event.target.reset();
        loadWatchlist();
      }).catch(function (err) { toast(err.message, 'error'); })
        .finally(function () { btn.disabled = false; });
    });
    loadWatchlist();
  }

  function sparkline(history) {
    if (!history || history.length < 2) return '<span class="text-slate-600">-</span>';
    var w = 80, h = 20;
    var pts = history.map(function (p, i) {
      return (i * (w / (history.length - 1))).toFixed(1) + ',' + (h - (p.score / 100) * h).toFixed(1);
    }).join(' ');
    return '<svg viewBox="0 0 ' + w + ' ' + h + '" width="' + w + '" height="' + h + '" aria-label="score history">' +
      '<polyline points="' + pts + '" fill="none" stroke="' + C.PALETTE.accent + '" stroke-width="1.5"/></svg>';
  }

  function loadWatchlist() {
    var target = $('#watch-list');
    if (!target) return;
    Api.watchlist().then(function (data) {
      if (!data.items.length) {
        target.innerHTML = card('', '', C.emptyState('Nothing on your watchlist yet. Add an indicator above, or use "Add to watchlist" on a lookup result.'));
        return;
      }
      target.innerHTML = card('Watched indicators', data.items.length + ' of ' + data.max,
        '<div class="overflow-x-auto"><table class="tbl"><thead><tr>' +
          '<th>Indicator</th><th>Verdict</th><th>Score</th><th>Trend</th><th>Last checked</th><th>Alerts</th><th></th>' +
        '</tr></thead><tbody>' + data.items.map(function (w) {
          return '<tr>' +
            '<td class="truncate-cell"><button class="mono hover:text-brand-400" data-lookup="' + esc(w.indicator) + '">' + esc(w.indicator) + '</button>' +
              (w.note ? '<p class="text-[11px] text-slate-500 truncate">' + esc(w.note) + '</p>' : '') + '</td>' +
            '<td>' + pill(w.verdict) + ' ' + simBadge(w.simulated) + '</td>' +
            '<td class="tabular-nums" style="color:' + scoreColor(w.score) + '">' + esc(w.score) + '</td>' +
            '<td>' + sparkline(w.history) + '</td>' +
            '<td class="text-[11px] text-slate-500">' + esc(w.lastCheckedAt ? fmtDate(w.lastCheckedAt) : 'never') +
              (w.lastError ? '<p class="text-danger-400">' + esc(w.lastError) + '</p>' : '') +
              (w.lastAlertAt ? '<p class="text-brand-400">alerted ' + esc(fmtDate(w.lastAlertAt)) + '</p>' : '') + '</td>' +
            '<td><label class="switch" title="Email me when this gets worse"><input type="checkbox" data-watch-alerts="' + esc(w.id) + '"' + (w.alerts ? ' checked' : '') + '><span></span></label></td>' +
            '<td class="whitespace-nowrap text-right">' +
              '<button class="btn-ghost text-[11px]" data-watch-check="' + esc(w.id) + '">Check now</button> ' +
              '<button class="btn-ghost text-[11px]" data-watch-remove="' + esc(w.id) + '">Remove</button></td>' +
          '</tr>';
        }).join('') + '</tbody></table></div>');

      $$('[data-watch-check]', target).forEach(function (btn) {
        btn.addEventListener('click', function () {
          btn.disabled = true;
          btn.innerHTML = '<span class="spinner"></span>';
          Api.watchCheck(btn.dataset.watchCheck).then(function () { loadWatchlist(); })
            .catch(function (err) { toast(err.message, 'error'); loadWatchlist(); });
        });
      });
      $$('[data-watch-remove]', target).forEach(function (btn) {
        btn.addEventListener('click', function () {
          Api.watchRemove(btn.dataset.watchRemove).then(function () { toast('Removed from watchlist'); loadWatchlist(); })
            .catch(function (err) { toast(err.message, 'error'); });
        });
      });
      $$('[data-watch-alerts]', target).forEach(function (input) {
        input.addEventListener('change', function () {
          Api.watchAlerts(input.dataset.watchAlerts, input.checked)
            .then(function () { toast(input.checked ? 'Email alerts on' : 'Email alerts off'); })
            .catch(function (err) { input.checked = !input.checked; toast(err.message, 'error'); });
        });
      });
      bindLookupLinks(target);
    }).catch(function (err) { target.innerHTML = errorBox(err.message); });
  }

  // ======================= admin =======================

  var AUDIT_FILTERS = [
    ['', 'All events'], ['auth.login', 'Sign-ins'], ['auth.register', 'Sign-ups'], ['auth.password', 'Password changes and resets'],
    ['auth.logout', 'Sign-outs'], ['admin.', 'Admin actions'], ['ioc.', 'Lookups'], ['watchlist.', 'Watchlist'],
  ];

  function renderAdmin(root) {
    root.innerHTML =
      '<div class="grid grid-cols-1 xl:grid-cols-3 gap-3">' +
        card('Sign-up', 'Whether visitors can create their own accounts',
          '<label class="flex items-center gap-3 text-sm text-slate-300"><span class="switch"><input id="admin-reg" type="checkbox"><span></span></span>Allow new accounts</label>' +
          '<p class="text-[11px] text-slate-500 mt-3">Overrides <code>ALLOW_REGISTRATION</code> in <code>.env</code>. New accounts still have to confirm their email.</p>') +
        card('Lookup history', 'Shared across all analysts',
          '<p class="text-xs text-slate-400 mb-3">Delete every analyst\'s lookup history. This cannot be undone and is recorded in the activity log.</p>' +
          '<button id="admin-wipe" class="btn-ghost text-xs">Clear all history</button>', 'xl:col-span-2') +
      '</div>' +
      '<div id="admin-users" class="mt-3">' + loading('Loading accounts…') + '</div>' +
      '<div class="mt-3">' + card('Activity log', 'Newest first. Passwords, tokens and codes are never recorded',
        '<div class="flex flex-wrap gap-2 mb-3 no-print">' +
          '<select id="audit-filter" class="field" style="max-width:16rem">' + AUDIT_FILTERS.map(function (f) {
            return '<option value="' + esc(f[0]) + '">' + esc(f[1]) + '</option>';
          }).join('') + '</select>' +
          '<button class="btn-ghost text-[11px]" data-print-report="CIMI activity log">Download PDF</button>' +
        '</div><div id="audit-list">' + loading('Loading activity…') + '</div>') + '</div>';

    Api.adminSettings().then(function (cfg) { $('#admin-reg').checked = cfg.registrationEnabled; }).catch(function () {});
    $('#admin-reg').addEventListener('change', function (event) {
      var on = event.target.checked;
      Api.adminSaveSettings({ registrationEnabled: on }).then(function () {
        state.site.registrationEnabled = on;
        toast(on ? 'Sign-up is open' : 'Sign-up is closed', 'success');
      }).catch(function (err) { event.target.checked = !on; toast(err.message, 'error'); });
    });
    $('#admin-wipe').addEventListener('click', function () {
      if (!window.confirm('Delete the lookup history of every analyst? This cannot be undone.')) return;
      Api.clearHistory(true).then(function (res) { toast(res.removed + ' lookups removed', 'success'); loadAudit(); })
        .catch(function (err) { toast(err.message, 'error'); });
    });
    $('#audit-filter').addEventListener('change', loadAudit);
    loadUsers();
    loadAudit();
  }

  function loadUsers() {
    var target = $('#admin-users');
    if (!target) return;
    var me = state.user || {};
    Api.adminUsers().then(function (data) {
      target.innerHTML = card('Accounts', data.items.length + ' total',
        '<div class="overflow-x-auto"><table class="tbl"><thead><tr>' +
          '<th>User</th><th>Role</th><th>Status</th><th>MFA</th><th>Last sign-in</th><th></th>' +
        '</tr></thead><tbody>' + data.items.map(function (u) {
          var status = u.disabled ? '<span class="pill pill-malicious">disabled</span>'
            : !u.emailVerified ? '<span class="pill pill-suspicious">unconfirmed</span>'
              : '<span class="pill pill-clean">active</span>';
          var self = u.id === me.id;
          var actions = self ? '<span class="text-[11px] text-slate-600">you</span>' :
            (!u.emailVerified && !u.disabled ? '<button class="btn-ghost text-[11px]" data-user-action="resend-verification" data-user="' + esc(u.id) + '">Resend link</button> ' : '') +
            '<button class="btn-ghost text-[11px]" data-user-action="' + (u.disabled ? 'enable' : 'disable') + '" data-user="' + esc(u.id) + '">' + (u.disabled ? 'Enable' : 'Disable') + '</button> ' +
            '<button class="btn-ghost text-[11px]" data-user-delete="' + esc(u.id) + '" data-name="' + esc(u.username) + '">Delete</button>';
          return '<tr>' +
            '<td><p class="text-slate-200">' + esc(u.username) + '</p><p class="text-[11px] text-slate-500">' + esc(u.email || 'no email') + '</p></td>' +
            '<td class="text-xs">' + esc(u.role) + '</td>' +
            '<td>' + status + '</td>' +
            '<td class="text-xs">' + (u.mfaEnabled ? 'on' : '<span class="text-slate-600">off</span>') + '</td>' +
            '<td class="text-[11px] text-slate-500">' + esc(u.lastLoginAt ? fmtDate(u.lastLoginAt) : 'never') + '</td>' +
            '<td class="whitespace-nowrap text-right">' + actions + '</td>' +
          '</tr>';
        }).join('') + '</tbody></table></div>');

      $$('[data-user-action]', target).forEach(function (btn) {
        btn.addEventListener('click', function () {
          var action = btn.dataset.userAction;
          Api.adminUserAction(btn.dataset.user, action).then(function () {
            toast({ disable: 'Account disabled and signed out', enable: 'Account enabled', 'resend-verification': 'Confirmation link sent' }[action], 'success');
            loadUsers(); loadAudit();
          }).catch(function (err) { toast(err.message, 'error'); });
        });
      });
      $$('[data-user-delete]', target).forEach(function (btn) {
        btn.addEventListener('click', function () {
          if (!window.confirm('Delete the account "' + btn.dataset.name + '"? This cannot be undone.')) return;
          Api.adminDeleteUser(btn.dataset.userDelete).then(function () {
            toast('Account deleted', 'success');
            loadUsers(); loadAudit();
          }).catch(function (err) { toast(err.message, 'error'); });
        });
      });
    }).catch(function (err) { target.innerHTML = errorBox(err.message); });
  }

  function loadAudit() {
    var target = $('#audit-list');
    if (!target) return;
    Api.adminAudit($('#audit-filter').value).then(function (data) {
      if (!data.items.length) { target.innerHTML = C.emptyState('No matching activity yet.'); return; }
      target.innerHTML = '<div class="overflow-x-auto"><table class="tbl"><thead><tr>' +
        '<th>When</th><th>Event</th><th>Who</th><th>Target</th><th>Detail</th><th>IP</th>' +
        '</tr></thead><tbody>' + data.items.map(function (e) {
          return '<tr>' +
            '<td class="text-[11px] text-slate-500 whitespace-nowrap">' + esc(fmtDate(e.at)) + '</td>' +
            '<td class="mono text-[11px]' + (e.outcome === 'failure' ? ' text-danger-400' : '') + '">' + esc(e.event) + (e.outcome === 'failure' ? ' ✕' : '') + '</td>' +
            '<td class="text-xs">' + esc(e.actor || '-') + '</td>' +
            '<td class="mono text-[11px] truncate-cell">' + esc(e.target || '') + '</td>' +
            '<td class="text-[11px] text-slate-400">' + esc(e.detail || '') + '</td>' +
            '<td class="mono text-[11px] text-slate-600">' + esc(e.ip || '') + '</td>' +
          '</tr>';
        }).join('') + '</tbody></table></div>';
    }).catch(function (err) { target.innerHTML = errorBox(err.message); });
  }

  // ======================= theme =======================

  var THEME_KEY = 'cimi-theme';

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function applyTheme(theme, remember) {
    var root = document.documentElement;
    root.classList.add('theme-switching');
    root.setAttribute('data-theme', theme);
    if (remember) { try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* private mode */ } }
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'light' ? '#ffffff' : '#000000');
    $$('[data-theme-toggle]').forEach(function (btn) {
      var label = theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
      btn.title = label;
      btn.setAttribute('aria-label', label);
    });
    window.dispatchEvent(new CustomEvent('cimi:theme', { detail: theme }));
    setTimeout(function () { root.classList.remove('theme-switching'); }, 300);
  }

  function toggleTheme() {
    applyTheme(currentTheme() === 'light' ? 'dark' : 'light', true);
    // SVG charts bake colours in when drawn, so redraw the open page.
    if (state.user && !$('#app-view').classList.contains('hidden')) renderPage();
  }

  // ======================= scroll effects =======================

  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var revealObserver = null;

  /** Header progress bar: how far down the page you are. */
  function updateScrollProgress() {
    var doc = document.documentElement;
    var max = doc.scrollHeight - window.innerHeight;
    var progress = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 1;
    doc.style.setProperty('--scroll-progress', progress.toFixed(3));
  }

  /** Cards ease in once, the first time they scroll into view. */
  function revealCards(root) {
    if (reduceMotion || !window.IntersectionObserver) return;
    if (!revealObserver) {
      revealObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('in-view');
          revealObserver.unobserve(entry.target);
          countUp(entry.target);
        });
      }, { rootMargin: '0px 0px -40px 0px', threshold: 0.05 });
    }
    $$('.card:not([data-revealed])', root).forEach(function (el, i) {
      el.setAttribute('data-revealed', '1');
      el.classList.add('reveal');
      el.style.transitionDelay = Math.min(i, 6) * 40 + 'ms';
      revealObserver.observe(el);
    });
  }

  /** KPI numbers count up from zero when their card appears. */
  function countUp(scope) {
    $$('[data-count]', scope).forEach(function (el) {
      var target = Number(el.getAttribute('data-count'));
      el.removeAttribute('data-count');
      if (!isFinite(target) || target <= 0 || reduceMotion) return;
      var start = performance.now(), duration = 700;
      (function tick(now) {
        var t = Math.min(1, (now - start) / duration);
        el.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
        if (t < 1) requestAnimationFrame(tick);
      })(start);
    });
  }

  function initScrollEffects() {
    window.addEventListener('scroll', updateScrollProgress, { passive: true });
    window.addEventListener('resize', updateScrollProgress);
    // Pages render asynchronously, so watch for new cards as they arrive.
    var pageRoot = $('#page-root');
    if (window.MutationObserver) {
      new MutationObserver(function () {
        revealCards(pageRoot);
        updateScrollProgress();
      }).observe(pageRoot, { childList: true, subtree: true });
    }
    updateScrollProgress();
  }

  // ======================= boot =======================

  /** Drops everything held in memory about the signed-in analyst. */
  function endSession() {
    showAuthPanel('form');
    state.user = null;
    state.lastLookup = state.lastCorrelation = state.lastLogReport = null;
    $('#page-root').innerHTML = '';
    showLogin();
  }

  function boot() {
    $('#tab-signin').addEventListener('click', function () { setAuthMode('signin'); });
    $('#tab-signup').addEventListener('click', function () { setAuthMode('signup'); });
    $('#login-form').addEventListener('submit', handleLoginSubmit);
    $('#login-resend').addEventListener('click', function () { resendVerification($('#login-username').value.trim()); });
    $('#verify-resend').addEventListener('click', function () { resendVerification(pendingVerification); });
    $('#verify-back').addEventListener('click', function () { hideVerifyNotice(); setAuthMode('signin'); });
    $('#forgot-link').addEventListener('click', showForgot);
    $('#forgot-form').addEventListener('submit', handleForgotSubmit);
    $('#forgot-back').addEventListener('click', function () { showAuthPanel('form'); setAuthMode('signin'); });
    $('#force-change-form').addEventListener('submit', handleForceChange);
    $('#force-cancel').addEventListener('click', function () {
      Api.logout().catch(function () {});
      showAuthPanel('form');
      endSession();
    });
    $('#signup-meter-slot').innerHTML = Pw.meterHtml('signup-meter');
    Pw.attach($('#login-password'), $('#signup-meter'), function () {
      return { username: $('#login-username').value.trim(), email: $('#login-email').value.trim() };
    });
    $('#force-meter-slot').innerHTML = Pw.meterHtml('force-meter');
    Pw.attach($('#force-new'), $('#force-meter'), function () { return { username: (state.user || {}).username }; });
    document.addEventListener('click', function (event) {
      var btn = event.target.closest && event.target.closest('[data-print-report]');
      if (btn) printReport(btn.getAttribute('data-print-report'), btn.getAttribute('data-print-sub'));
    });
    window.addEventListener('cimi:session-ended', function () {
      if (!state.user) return;
      endSession();
      toast('Your session ended. Sign in again.', 'error');
    });

    $$('.nav-item').forEach(function (btn) {
      btn.addEventListener('click', function () { navigate(btn.dataset.page); });
    });

    $('#logout-btn').addEventListener('click', function () {
      Api.logout().catch(function () { /* cookie is cleared server-side; nothing else to undo */ });
      endSession();
      toast('Signed out');
    });

    $('#sidebar-toggle').addEventListener('click', openSidebar);
    $('#sidebar-backdrop').addEventListener('click', closeSidebar);
    $('#refresh-btn').addEventListener('click', function () { renderPage(); });
    $$('[data-theme-toggle]').forEach(function (btn) { btn.addEventListener('click', toggleTheme); });
    applyTheme(currentTheme(), false);
    // Follow the device setting live, unless the person picked a theme here.
    if (window.matchMedia) {
      var mq = window.matchMedia('(prefers-color-scheme: light)');
      var follow = function (e) {
        var saved = null;
        try { saved = localStorage.getItem(THEME_KEY); } catch (err) { /* ignore */ }
        if (saved) return;
        applyTheme(e.matches ? 'light' : 'dark', false);
        if (state.user && !$('#app-view').classList.contains('hidden')) renderPage();
      };
      if (mq.addEventListener) mq.addEventListener('change', follow);
    }
    initScrollEffects();

    window.addEventListener('hashchange', function () {
      var page = location.hash.replace('#', '');
      if (PAGE_META[page] && page !== state.page) navigate(page);
    });

    var initial = location.hash.replace('#', '');
    if (PAGE_META[initial]) state.page = initial;

    loadSiteConfig();

    // The browser cannot see the HttpOnly cookie, so ask the server whether a session exists.
    Api.me().then(function (res) {
      state.user = res.user;
      if (res.user.mustChangePassword) return showForceChange();
      showApp();
    }).catch(function () {
      showLogin();
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
