<?php
// Item 15: site-wide security headers, applied to every response by
// default. public/clickjacking-target.php is the one deliberate
// exception (item 14's demo) - it calls header_remove() on the
// framing-related headers below to show the vulnerable case, the
// same "opt-out constant/call" pattern used for the file-upload and
// command-injection labs on this machine's other PHP project.

function csp_nonce() {
    static $nonce = null;
    if ($nonce === null) { $nonce = random_token_hex(16); }
    return $nonce;
}

function apply_security_headers() {
    $https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $nonce = csp_nonce();

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header(
        "Content-Security-Policy: default-src 'self'; " .
        "script-src 'self' 'nonce-$nonce'; " .
        "style-src 'self' 'unsafe-inline'; " . // inline <style> blocks/attrs only - no remote stylesheets
        "img-src 'self' data:; " .
        "frame-ancestors 'none'; " .
        "base-uri 'self'; form-action 'self'"
    );
    if ($https) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    // X-XSS-Protection is deliberately omitted: it's deprecated/removed
    // in modern browsers and the CSP above is the real mitigation.
}
