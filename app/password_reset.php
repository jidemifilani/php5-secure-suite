<?php
// Item 8: password reset - time-limited, single-use, HMAC-signed
// tokens. Token shape: "<selector>.<validator>.<hmac>".
//   - selector: a lookup key (not secret) used to find the row.
//   - validator: the actual secret; only its SHA-256 hash is stored,
//     so a stolen DB row alone can't be replayed as a valid token.
//   - hmac: signs selector+validator with a server-only key so a
//     malformed/guessed token is rejected before ever touching the DB.

function create_password_reset_token($userId) {
    $selector = random_token_hex(12);
    $validator = random_token_hex(32);
    $validatorHash = hash('sha256', $validator);

    $pdo = db();
    $del = $pdo->prepare('DELETE FROM password_resets WHERE user_id = ? AND used_at IS NULL');
    $del->execute(array($userId));

    $stmt = $pdo->prepare(
        'INSERT INTO password_resets (user_id, selector, validator_hash, expires_at) VALUES (?, ?, ?, NOW() + INTERVAL 1 HOUR)'
    );
    $stmt->execute(array($userId, $selector, $validatorHash));

    $payload = $selector . '.' . $validator;
    $sig = hash_hmac('sha256', $payload, app_secret());
    return $payload . '.' . $sig;
}

// Returns the password_resets row if the token is authentic,
// unexpired, and unused - null otherwise. Expiry is checked with
// MySQL's own NOW(), not PHP's time(), so a clock skew between the
// PHP host and the DB host can never make an expired token look
// valid (or a valid one look expired).
function verify_password_reset_token($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) { return null; }
    list($selector, $validator, $sig) = $parts;

    $expectedSig = hash_hmac('sha256', $selector . '.' . $validator, app_secret());
    if (!hash_equals($expectedSig, $sig)) { return null; }

    $stmt = db()->prepare(
        'SELECT * FROM password_resets WHERE selector = ? AND used_at IS NULL AND expires_at > NOW()'
    );
    $stmt->execute(array($selector));
    $row = $stmt->fetch();
    if (!$row) { return null; }
    if (!hash_equals($row['validator_hash'], hash('sha256', $validator))) { return null; }
    return $row;
}

function consume_password_reset_token($resetId, $userId, $newPassword) {
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $mark = $pdo->prepare('UPDATE password_resets SET used_at = NOW() WHERE id = ? AND used_at IS NULL');
        $mark->execute(array($resetId));
        if ($mark->rowCount() !== 1) {
            throw new Exception('This reset link was already used.');
        }
        $hash = password_hash($newPassword, PASSWORD_DEFAULT);
        $upd = $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $upd->execute(array($hash, $userId));
        $pdo->commit();
    } catch (Exception $ex) {
        $pdo->rollBack();
        throw $ex;
    }
}
