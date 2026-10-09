/* Password strength meter. Mirrors the server's rules in src/utils/password.js
   so people see problems while typing; the server still has the final say. */
(function (global) {
  'use strict';

  var COMMON = ['password', 'password1', 'password123', '12345678', '123456789', '1234567890', 'qwerty123',
    'qwertyuiop', '11111111', '00000000', 'iloveyou', 'admin123', 'administrator', 'welcome1', 'welcome123',
    'letmein1', 'abc12345', 'abcd1234', 'passw0rd', 'p@ssw0rd', 'p@ssword', 'changeme', 'trustno1',
    'sunshine1', 'football1', 'baseball1', 'monkey123', 'dragon123', 'india123', 'india@123', 'cimi2026',
    'cimi@2026', 'analyst1', 'analyst123', 'security1'];

  function classes(pw) {
    return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(function (re) { return re.test(pw); }).length;
  }

  /** Returns the first rule the password breaks, or null. Same wording as the server. */
  function problem(pw, ctx) {
    ctx = ctx || {};
    var lower = pw.toLowerCase();
    if (pw.length < 8) return 'At least 8 characters';
    if (COMMON.indexOf(lower) !== -1) return 'Too common, pick something less guessable';
    if (ctx.username && ctx.username.length >= 3 && lower.indexOf(ctx.username.toLowerCase()) !== -1) return 'Must not contain your username';
    var local = ctx.email ? ctx.email.split('@')[0].toLowerCase() : '';
    if (local.length >= 3 && lower.indexOf(local) !== -1) return 'Must not contain your email address';
    if (pw.length < 16 && classes(pw) < 3) return 'Mix three of: lowercase, uppercase, numbers, symbols (or use 16+ characters)';
    return null;
  }

  /** 0 (unacceptable) to 4 (strong). */
  function score(pw, ctx) {
    if (!pw) return { score: 0, label: '', problem: null };
    var issue = problem(pw, ctx);
    if (issue) return { score: pw.length >= 8 ? 1 : 0, label: 'Too weak', problem: issue };
    var points = 2;
    if (pw.length >= 12) points += 1;
    if (pw.length >= 16 || classes(pw) === 4) points += 1;
    return { score: Math.min(points, 4), label: ['', 'Too weak', 'Fair', 'Good', 'Strong'][Math.min(points, 4)], problem: null };
  }

  /** Markup for a meter; pair it with attach(). */
  function meterHtml(id) {
    return '<div id="' + id + '" class="pw-meter" aria-live="polite">' +
      '<div class="pw-bars"><span></span><span></span><span></span><span></span></div>' +
      '<p class="pw-label"></p></div>';
  }

  function attach(input, meter, getContext) {
    if (!input || !meter) return;
    function update() {
      var result = score(input.value, getContext ? getContext() : {});
      meter.setAttribute('data-score', String(result.score));
      meter.querySelector('.pw-label').textContent = input.value
        ? (result.problem ? result.label + ': ' + result.problem : result.label)
        : '';
    }
    input.addEventListener('input', update);
    update();
  }

  global.CimiPassword = { score: score, problem: problem, meterHtml: meterHtml, attach: attach };
})(window);
