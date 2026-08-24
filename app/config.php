<?php
// Central config. This file lives outside public/, so it is never
// directly web-reachable regardless of routing bugs.

define('SITE_NAME', 'PHP5 Secure Suite');
define('APP_ROOT', dirname(__DIR__));
define('STORAGE_PATH', APP_ROOT . DIRECTORY_SEPARATOR . 'storage');
define('KEYS_PATH', STORAGE_PATH . DIRECTORY_SEPARATOR . 'keys');
define('UPLOADS_PATH', STORAGE_PATH . DIRECTORY_SEPARATOR . 'uploads');
define('LOGS_PATH', STORAGE_PATH . DIRECTORY_SEPARATOR . 'logs');

define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'php5_secure_suite');
define('DB_USER', 'root');
define('DB_PASS', '');

// Session hardening baseline (see app/session_security.php for the
// hijacking demo/fix module, which builds on top of this).
define('SESSION_IDLE_TIMEOUT', 900); // 15 minutes

// Rate limiting.
define('RATE_LIMIT_LOGIN_MAX', 5);
define('RATE_LIMIT_LOGIN_WINDOW', 300);   // 5 min
define('RATE_LIMIT_API_MAX', 30);
define('RATE_LIMIT_API_WINDOW', 60);      // 1 min

// API gateway replay protection.
define('API_TIMESTAMP_SKEW', 300); // reject requests signed more than 5 min off server time

// Uploads.
define('UPLOAD_MAX_BYTES', 2 * 1024 * 1024); // 2MB
define('UPLOAD_ALLOWED_EXT', serialize(array('jpg', 'jpeg', 'png', 'pdf', 'txt')));
define('UPLOAD_ALLOWED_MIME', serialize(array(
    'image/jpeg', 'image/png', 'application/pdf', 'text/plain',
)));

// Item 1: account lockout (persistent per-account lock, distinct from
// the sliding-window rate limiter above).
define('LOCKOUT_MAX_ATTEMPTS', 5);
define('LOCKOUT_DURATION_MINUTES', 15);

// Item 2: remember-me.
define('REMEMBER_ME_DAYS', 30);
define('REMEMBER_COOKIE_NAME', 'p5ss_remember');

// Item 6: math CAPTCHA gate, triggered after this many failed logins
// in the current browser session (tracked in $_SESSION, separate
// from the DB-backed lockout/rate-limit counters above).
define('CAPTCHA_TRIGGER_AFTER', 3);

// Item 17: IP allowlist for /admin. Empty (default) = disabled, so
// this ships non-breaking; set e.g. serialize(array('127.0.0.1')) to
// enable.
define('ADMIN_IP_ALLOWLIST', serialize(array()));

date_default_timezone_set('UTC');

error_reporting(E_ALL);
ini_set('display_errors', '1'); // demo/teaching site: OK to show errors locally; flip off for any real deployment
