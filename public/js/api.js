/* CIMI thin REST client.
   The session lives in an HttpOnly cookie set by the server. This file never
   sees, stores or forwards the session token, and nothing about the signed-in
   user is written to localStorage or sessionStorage. */
(function (global) {
  'use strict';

  var Api = {
    request: function (path, options) {
      options = options || {};
      var headers = { Accept: 'application/json' };
      if (options.body !== undefined) headers['Content-Type'] = 'application/json';

      return fetch('/api' + path, {
        method: options.method || 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: Object.assign(headers, options.headers || {}),
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      }).then(function (res) {
        var isJson = (res.headers.get('content-type') || '').indexOf('json') !== -1;
        return (isJson ? res.json().catch(function () { return {}; }) : res.text()).then(function (data) {
          if (!res.ok) {
            var err = new Error((data && data.error) || ('Request failed (' + res.status + ')'));
            err.status = res.status;
            err.code = data && data.code;
            err.payload = data;
            // A signed-in call that comes back 401 means the session ended (expired or signed out elsewhere).
            if (res.status === 401 && path.indexOf('/auth/') !== 0) {
              global.dispatchEvent(new CustomEvent('cimi:session-ended'));
            }
            throw err;
          }
          return data;
        });
      });
    },

    get: function (path) { return Api.request(path); },
    post: function (path, body) { return Api.request(path, { method: 'POST', body: body }); },
    del: function (path) { return Api.request(path, { method: 'DELETE' }); },

    // --- endpoints ---------------------------------------------------------
    health: function () { return Api.get('/health'); },
    login: function (payload) { return Api.post('/auth/login', payload); },
    logout: function () { return Api.post('/auth/logout', {}); },
    registerUser: function (payload) { return Api.post('/auth/register', payload); },
    verifyEmail: function (token) { return Api.post('/auth/verify-email', { token: token }); },
    resendVerification: function (login) { return Api.post('/auth/resend-verification', { login: login }); },
    forgotPassword: function (login) { return Api.post('/auth/forgot-password', { login: login }); },
    changePassword: function (currentPassword, newPassword) {
      return Api.post('/auth/change-password', { currentPassword: currentPassword, newPassword: newPassword });
    },
    logoutAll: function () { return Api.post('/auth/logout-all', {}); },

    watchlist: function () { return Api.get('/watchlist'); },
    watchAdd: function (indicator, note) { return Api.post('/watchlist', { indicator: indicator, note: note }); },
    watchCheck: function (id) { return Api.post('/watchlist/' + encodeURIComponent(id) + '/check', {}); },
    watchAlerts: function (id, alerts) {
      return Api.request('/watchlist/' + encodeURIComponent(id), { method: 'PATCH', body: { alerts: alerts } });
    },
    watchRemove: function (id) { return Api.del('/watchlist/' + encodeURIComponent(id)); },

    adminUsers: function () { return Api.get('/admin/users'); },
    adminUserAction: function (id, action) { return Api.post('/admin/users/' + encodeURIComponent(id) + '/' + action, {}); },
    adminDeleteUser: function (id) { return Api.del('/admin/users/' + encodeURIComponent(id)); },
    adminAudit: function (event) { return Api.get('/admin/audit?limit=300' + (event ? '&event=' + encodeURIComponent(event) : '')); },
    adminSettings: function () { return Api.get('/admin/settings'); },
    adminSaveSettings: function (patch) { return Api.request('/admin/settings', { method: 'PUT', body: patch }); },
    me: function () { return Api.get('/auth/me'); },
    mfaSetup: function () { return Api.post('/auth/mfa/setup', {}); },
    mfaConfirm: function (token) { return Api.post('/auth/mfa/confirm', { token: token }); },
    mfaDisable: function (password) { return Api.post('/auth/mfa/disable', { password: password }); },

    lookup: function (indicator, type) { return Api.post('/ioc/lookup', { indicator: indicator, type: type }); },
    bulk: function (list) { return Api.post('/ioc/bulk', { indicators: list }); },
    history: function (limit) { return Api.get('/ioc/history?limit=' + (limit || 50)); },
    clearHistory: function (all) { return Api.del('/ioc/history' + (all ? '?scope=all' : '')); },

    dashboard: function (days) { return Api.get('/dashboard?days=' + (days || 14)); },
    correlate: function (list) { return Api.post('/correlation', { indicators: list }); },
    correlateHistory: function (limit) { return Api.get('/correlation/history?limit=' + (limit || 15)); },

    analyseLog: function (content, fileName) {
      return Api.post('/logs/analyse', { content: content, fileName: fileName });
    },
    logReports: function () { return Api.get('/logs/reports'); },

    certin: function (params) { return Api.get('/feeds/certin' + (params || '')); },
    kev: function (params) { return Api.get('/feeds/kev' + (params || '')); },
    otxFeed: function () { return Api.get('/feeds/otx'); },
    feedHealth: function () { return Api.get('/feeds/health'); },

    /** Triggers a browser download of a STIX 2.1 bundle. */
    downloadStix: function (list) {
      return Api.request('/ioc/stix', { method: 'POST', body: { indicators: list } })
        .then(function (bundle) {
          var blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = 'cimi-stix-bundle.json';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
          return bundle;
        });
    },
  };

  global.CimiApi = Api;
})(window);
