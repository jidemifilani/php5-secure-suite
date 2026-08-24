<?php
// Item 2: remember-me, selector/validator pattern (never store the
// raw token, only a hash of the validator half - identical shape to
// the password-reset tokens in app/password_reset.php). Rotates on
// every use: a captured-then-replayed cookie only works once before
// the legitimate owner's next visit invalidates it.

function issue_remember_cookie($userId) {
    $selector = random_token_hex(12);
    $validator = random_token_hex(32);
    $hash = hash('sha256', $validator);

    $stmt = db()->prepare(
        'INSERT INTO remember_tokens (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, NOW() + INTERVAL ? DAY)'
    );
    $stmt->execute(array($userId, $selector, $hash, REMEMBER_ME_DAYS));

    $https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    setcookie(REMEMBER_COOKIE_NAME, $selector . '.' . $validator, time() + REMEMBER_ME_DAYS * 86400, '/; SameSite=Lax', '', $https, true);
}

function clear_remember_cookie() {
    if (isset($_COOKIE[REMEMBER_COOKIE_NAME])) {
        $parts = explode('.', $_COOKIE[REMEMBER_COOKIE_NAME], 2);
        if (isset($parts[0]) && $parts[0] !== '') {
            $stmt = db()->prepare('DELETE FROM remember_tokens WHERE selector = ?');
            $stmt->execute(array($parts[0]));
        }
    }
    setcookie(REMEMBER_COOKIE_NAME, '', time() - 3600, '/; SameSite=Lax', '', false, true);
}

// Called from bootstrap.php on every request where no session is
// already active. Silently does nothing if there's no cookie, or if
// it's invalid/expired.
function attempt_remember_login() {
    if (current_user_id() !== null) { return; }
    if (!isset($_COOKIE[REMEMBER_COOKIE_NAME])) { return; }

    $parts = explode('.', $_COOKIE[REMEMBER_COOKIE_NAME], 2);
    if (count($parts) !== 2) { return; }
    list($selector, $validator) = $parts;

    $stmt = db()->prepare('SELECT * FROM remember_tokens WHERE selector = ? AND expires_at > NOW()');
    $stmt->execute(array($selector));
    $row = $stmt->fetch();
    if (!$row) {
        clear_remember_cookie();
        return;
    }

    if (!hash_equals($row['validator_hash'], hash('sha256', $validator))) {
        // Selector matched but the validator didn't - the selector
        // alone is not secret (it's a DB lookup key), so this shape
        // of mismatch is the signature of a guessed/tampered cookie
        // rather than an expired one. Kill the token outright rather
        // than just rejecting this one request.
        $del = db()->prepare('DELETE FROM remember_tokens WHERE id = ?');
        $del->execute(array($row['id']));
        audit_log_event('remember_token_mismatch', $row['user_id'], 'selector=' . $selector);
        clear_remember_cookie();
        return;
    }

    $del = db()->prepare('DELETE FROM remember_tokens WHERE id = ?');
    $del->execute(array($row['id']));

    log_in_user($row['user_id']);
    issue_remember_cookie($row['user_id']);
    audit_log_event('login_via_remember_me', $row['user_id'], '');
}
