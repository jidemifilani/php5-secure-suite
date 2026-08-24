<?php
// Every public/ entry point requires this first. Order matters:
// config.php must load before session_configure_secure() touches
// session.* ini settings or calls session_start() - PHP rejects
// changing session ini directives once a session is active.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/security_headers.php';
require_once __DIR__ . '/session_security.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/rbac.php';
require_once __DIR__ . '/audit.php';
require_once __DIR__ . '/rate_limit.php';
require_once __DIR__ . '/waf.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/totp.php';
require_once __DIR__ . '/upload.php';
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/password_reset.php';
require_once __DIR__ . '/password_strength.php';
require_once __DIR__ . '/remember.php';
require_once __DIR__ . '/admin_guard.php';
require_once __DIR__ . '/view.php';
require_once __DIR__ . '/hijack_demo.php';
require_once __DIR__ . '/demo_gadget.php';

apply_security_headers();
session_configure_secure('P5SS_SESSION');

if (current_user_id() !== null) {
    if (!session_enforce_fingerprint()) {
        session_configure_secure('P5SS_SESSION');
        flash_set('error', 'Your session was ended because it looked like it moved to a different device/browser.');
    }
}

attempt_remember_login();

waf_inspect_request();
