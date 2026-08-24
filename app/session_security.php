<?php
// Item 9: session hijacking fix, used as the REAL session handling
// for every page in this app (secure-by-default). The vulnerable
// side of the demo is a deliberately separate, isolated session
// (see public/session-hijack-demo.php) so playing with it can never
// weaken the real login session.

function session_configure_secure($name) {
    $https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    session_name($name);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');

    // PHP 5.6 has no native SameSite support (that arrived in 7.3's
    // options-array signature for session_set_cookie_params/setcookie).
    // The documented legacy workaround: PHP <7.3 writes the cookie
    // "path" segment into the Set-Cookie header without validating
    // it, so appending "; SameSite=Lax" after the real path smuggles
    // the attribute through verbatim.
    session_set_cookie_params(0, '/; SameSite=Lax', '', $https, true);

    session_start();
    session_enforce_idle_timeout();
}

function session_fingerprint() {
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    return hash('sha256', client_ip() . '|' . $ua);
}

// Call once, right after a successful login. Rotates the session ID
// (defeats session fixation) and (re)binds the IP/UA fingerprint.
function session_regenerate_on_login() {
    session_regenerate_id(true);
    $_SESSION['_fp'] = session_fingerprint();
    $_SESSION['_last_activity'] = time();
}

// Call on every authenticated request. If the fingerprint stored at
// login no longer matches the current request, the session is
// treated as hijacked (or at least too risky to trust) and killed.
function session_enforce_fingerprint() {
    if (!isset($_SESSION['_fp'])) { return true; }
    if (!hash_equals($_SESSION['_fp'], session_fingerprint())) {
        session_unset();
        session_destroy();
        return false;
    }
    return true;
}

function session_enforce_idle_timeout() {
    $now = time();
    if (isset($_SESSION['_last_activity']) && ($now - $_SESSION['_last_activity']) > SESSION_IDLE_TIMEOUT) {
        session_unset();
        session_destroy();
        session_start();
    }
    $_SESSION['_last_activity'] = $now;
}
