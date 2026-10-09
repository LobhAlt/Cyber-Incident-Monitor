/* Password reset page. Like the confirmation page, the token arrives in the
   URL fragment (#token=…), is read once, and is removed from the address bar. */
(function () {
  'use strict';

  var P = window.CimiPassword;
  var form = document.getElementById('reset-form');
  var input = document.getElementById('reset-password');
  var confirmInput = document.getElementById('reset-confirm');
  var errorEl = document.getElementById('reset-error');
  var button = document.getElementById('reset-submit');

  var match = /(?:^|[#&])token=([^&]+)/.exec(location.hash);
  var token = match ? decodeURIComponent(match[1]) : '';
  try { history.replaceState(null, '', location.pathname); } catch (e) { /* ignore */ }

  function finish(heading, text, ok) {
    document.getElementById('reset-title').textContent = heading;
    document.getElementById('reset-message').textContent = text;
    form.hidden = true;
    document.getElementById('reset-done').hidden = !ok;
  }

  if (!token) {
    finish('Link incomplete', 'This reset link is missing its code. Open the link from the email again, or request a new one from the sign-in page.', false);
    return;
  }

  document.getElementById('reset-meter-slot').innerHTML = P.meterHtml('reset-meter');
  P.attach(input, document.getElementById('reset-meter'));

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var issue = P.problem(input.value);
    if (issue) return showError(issue + '.');
    if (input.value !== confirmInput.value) return showError('The two passwords do not match.');
    showError('');
    button.disabled = true;
    button.textContent = 'Saving…';

    fetch('/api/auth/reset-password', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ token: token, password: input.value }),
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.ok) {
          input.value = confirmInput.value = '';
          finish('Password changed', 'Your new password is saved and every device has been signed out. Sign in with the new password.', true);
        } else if (data.code === 'WEAK_PASSWORD') {
          showError(data.error + '.');
        } else {
          finish('Could not reset', data.error || 'This link did not work. Request a new one from the sign-in page.', false);
        }
      });
    }).catch(function () {
      showError('Could not reach CIMI. Check that the server is running.');
    }).finally(function () {
      button.disabled = false;
      button.textContent = 'Save new password';
    });
  });
})();
