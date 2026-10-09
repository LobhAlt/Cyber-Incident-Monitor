'use strict';

/**
 * Password policy shared by sign-up, password reset and password change.
 * The browser shows the same rules through its strength meter, but the
 * server is the one that enforces them.
 */

// A short list of passwords that show up first in every breach dictionary.
const COMMON = new Set([
  'password', 'password1', 'password123', '12345678', '123456789', '1234567890', 'qwerty123',
  'qwertyuiop', '11111111', '00000000', 'iloveyou', 'admin123', 'administrator', 'welcome1',
  'welcome123', 'letmein1', 'abc12345', 'abcd1234', 'passw0rd', 'p@ssw0rd', 'p@ssword',
  'changeme', 'trustno1', 'sunshine1', 'football1', 'baseball1', 'monkey123', 'dragon123',
  'india123', 'india@123', 'cimi2026', 'cimi@2026', 'analyst1', 'analyst123', 'security1',
]);

function classes(password) {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
}

/** Returns an error message, or null when the password is acceptable. */
function check(password, { username, email } = {}) {
  const pw = String(password || '');
  if (pw.length < 8) return 'Password must be at least 8 characters';
  if (pw.length > 200) return 'Password is too long';
  if (COMMON.has(pw.toLowerCase())) return 'That password is too common. Choose something less guessable';
  const lower = pw.toLowerCase();
  if (username && String(username).length >= 3 && lower.includes(String(username).toLowerCase())) {
    return 'Password must not contain your username';
  }
  const local = email ? String(email).split('@')[0].toLowerCase() : '';
  if (local.length >= 3 && lower.includes(local)) return 'Password must not contain your email address';
  if (pw.length < 16 && classes(pw) < 3) {
    return 'Use at least three of: lowercase, uppercase, numbers, symbols (or 16+ characters)';
  }
  return null;
}

module.exports = { check };
