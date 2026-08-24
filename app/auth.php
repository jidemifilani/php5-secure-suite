<?php
// Foundation login system that items 7 (2FA), 8 (password reset) and
// 9 (session hijack fix) hang off. password_hash()/password_verify()
// have been available since PHP 5.5, but PASSWORD_DEFAULT on PHP 5.6
// resolves to bcrypt - Argon2id wasn't added until PHP 7.2, so this
// stays on bcrypt, unlike newer projects on this machine that use
// Argon2id.

function find_user_by_username($username) {
    $stmt = db()->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute(array($username));
    return $stmt->fetch();
}

function find_user_by_id($id) {
    $stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute(array($id));
    return $stmt->fetch();
}

function register_user($username, $email, $password) {
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
        $stmt->execute(array($username, $email, $hash));
        $userId = (int) $pdo->lastInsertId();

        $roleStmt = $pdo->prepare('SELECT id FROM roles WHERE name = ?');
        $roleStmt->execute(array('user'));
        $roleId = $roleStmt->fetchColumn();
        if ($roleId) {
            $assign = $pdo->prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)');
            $assign->execute(array($userId, $roleId));
        }

        // Item 10 (IDOR playground): every account gets one private
        // note automatically, so there's always something for the
        // vulnerable viewer to leak across accounts.
        $note = $pdo->prepare('INSERT INTO demo_idor_notes (user_id, title, body) VALUES (?, ?, ?)');
        $note->execute(array($userId, 'My private note', 'This note belongs to ' . $username . ' and should only be readable by ' . $username . '.'));

        $pdo->commit();
    } catch (Exception $ex) {
        $pdo->rollBack();
        throw $ex;
    }
    return $userId;
}

// Item 1: account lockout. Returns seconds remaining if locked, or
// null if not - computed entirely in MySQL (NOW()/TIMESTAMPDIFF) so a
// PHP/MySQL clock skew can't silently defeat it, same lesson as the
// rate limiter in app/rate_limit.php.
function account_lock_remaining_seconds($userId) {
    $stmt = db()->prepare(
        'SELECT TIMESTAMPDIFF(SECOND, NOW(), locked_until) FROM users WHERE id = ? AND locked_until IS NOT NULL AND locked_until > NOW()'
    );
    $stmt->execute(array($userId));
    $secs = $stmt->fetchColumn();
    return $secs !== false ? (int) $secs : null;
}

function register_failed_login($userId) {
    $pdo = db();
    $upd = $pdo->prepare('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?');
    $upd->execute(array($userId));
    $stmt = $pdo->prepare('SELECT failed_attempts FROM users WHERE id = ?');
    $stmt->execute(array($userId));
    $count = (int) $stmt->fetchColumn();
    if ($count >= LOCKOUT_MAX_ATTEMPTS) {
        $lock = $pdo->prepare('UPDATE users SET locked_until = NOW() + INTERVAL ? MINUTE WHERE id = ?');
        $lock->execute(array(LOCKOUT_DURATION_MINUTES, $userId));
        audit_log_event('account_locked', $userId, 'after ' . $count . ' failed attempts');
    }
}

function register_successful_login($userId) {
    $upd = db()->prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?');
    $upd->execute(array($userId));
}

// Item 5: new-device/new-IP login notice. Returns true the first time
// this (user, ip) pair is ever seen.
function check_and_record_known_ip($userId) {
    $ip = client_ip();
    $stmt = db()->prepare('SELECT 1 FROM user_known_ips WHERE user_id = ? AND ip_address = ?');
    $stmt->execute(array($userId, $ip));
    if ($stmt->fetchColumn()) { return false; }
    $ins = db()->prepare('INSERT IGNORE INTO user_known_ips (user_id, ip_address) VALUES (?, ?)');
    $ins->execute(array($userId, $ip));
    audit_log_event('login_new_ip', $userId, $ip);
    return true;
}

// Enumeration-resistant: always runs password_verify() against
// something (a dummy hash for unknown usernames) so response timing
// doesn't reveal whether the username exists.
function verify_credentials($username, $password) {
    $user = find_user_by_username($username);
    static $dummyHash = null;
    if ($dummyHash === null) {
        $dummyHash = password_hash('not-a-real-password', PASSWORD_DEFAULT);
    }
    if (!$user) {
        password_verify($password, $dummyHash);
        return null;
    }
    if (!$user['is_active']) {
        password_verify($password, $dummyHash);
        return null;
    }
    if (!password_verify($password, $user['password_hash'])) {
        return null;
    }
    if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
        $newHash = password_hash($password, PASSWORD_DEFAULT);
        $upd = db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $upd->execute(array($newHash, $user['id']));
    }
    return $user;
}

function log_in_user($userId) {
    $_SESSION['user_id'] = $userId;
    session_regenerate_on_login();
    rbac_refresh_session($userId);
    if (check_and_record_known_ip($userId)) {
        $_SESSION['_new_ip_notice'] = client_ip();
    }
}

function log_out_user() {
    audit_log_event('logout', current_user_id(), '');
    $_SESSION = array();
    session_unset();
    session_destroy();
}
