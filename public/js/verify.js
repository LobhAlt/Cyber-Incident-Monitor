/* Email confirmation page. The token arrives in the URL fragment (#token=…),
   which browsers never send to any server or put in a Referer header. It is
   read once, removed from the address bar, and posted to the API. */
(function () {
  'use strict';

  var title = document.getElementById('verify-title');
  var message = document.getElementById('verify-message');
  var action = document.getElementById('verify-action');

  function finish(heading, text) {
    title.textContent = heading;
    message.textContent = text;
    action.hidden = false;
  }

  var match = /(?:^|[#&])token=([^&]+)/.exec(location.hash);
  var token = match ? decodeURIComponent(match[1]) : '';
  // Drop the token from the address bar and history straight away.
  try { history.replaceState(null, '', location.pathname); } catch (e) { /* ignore */ }

  if (!token) {
    finish('Link incomplete', 'This confirmation link is missing its code. Open the link from the email again, or request a new one from the sign-in page.');
    return;
  }

  fetch('/api/auth/verify-email', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ token: token }),
  }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (data) {
      if (res.ok) {
        finish('Email confirmed', 'Your account ' + (data.username ? '"' + data.username + '" ' : '') + 'is active. You can sign in now.');
      } else {
        finish('Could not confirm', data.error || 'This link did not work. Request a new one from the sign-in page.');
      }
    });
  }).catch(function () {
    finish('Could not reach CIMI', 'Check that the server is running, then open the link again.');
  });
})();
