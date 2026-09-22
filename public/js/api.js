/* CIMI thin REST client with session-token handling. */
(function (global) {
  'use strict';

  var TOKEN_KEY = 'cimi.token';
  var USER_KEY = 'cimi.user';

  function readStorage(key) {
    try { return global.localStorage.getItem(key); } catch (e) { return null; }
  }
  function writeStorage(key, value) {
    try {
      if (value === null) global.localStorage.removeItem(key);
      else global.localStorage.setItem(key, value);
    } catch (e) { /* private mode: session stays in memory only */ }
  }

  var memoryToken = null;
  var memoryUser = null;

  var Api = {
    getToken: function () { return memoryToken || readStorage(TOKEN_KEY); },
    getUser: function () {
      if (memoryUser) return memoryUser;
      var raw = readStorage(USER_KEY);
      if (!raw) return null;
      try { return JSON.parse(raw); } catch (e) { return null; }
    },
    setSession: function (token, user) {
      memoryToken = token;
      memoryUser = user;
      writeStorage(TOKEN_KEY, token);
      writeStorage(USER_KEY, JSON.stringify(user));
    },
    clearSession: function () {
      memoryToken = null;
      memoryUser = null;
      writeStorage(TOKEN_KEY, null);
      writeStorage(USER_KEY, null);
    },

    request: function (path, options) {
      options = options || {};
      var headers = { Accept: 'application/json' };
      if (options.body !== undefined) headers['Content-Type'] = 'application/json';
      var token = Api.getToken();
      if (token) headers.Authorization = 'Bearer ' + token;

      return fetch('/api' + path, {
        method: options.method || 'GET',
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
    registerUser: function (payload) { return Api.post('/auth/register', payload); },
    me: function () { return Api.get('/auth/me'); },
    mfaSetup: function () { return Api.post('/auth/mfa/setup', {}); },
    mfaConfirm: function (token) { return Api.post('/auth/mfa/confirm', { token: token }); },
    mfaDisable: function (password) { return Api.post('/auth/mfa/disable', { password: password }); },

    lookup: function (indicator, type) { return Api.post('/ioc/lookup', { indicator: indicator, type: type }); },
    bulk: function (list) { return Api.post('/ioc/bulk', { indicators: list }); },
    history: function (limit) { return Api.get('/ioc/history?limit=' + (limit || 50)); },
    clearHistory: function () { return Api.del('/ioc/history'); },

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
