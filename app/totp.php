<?php
// Item 7: TOTP 2FA, hand-rolled RFC 6238 - no external library, only
// hash_hmac()/pack()/unpack(), all present in PHP 5.6.

function totp_generate_secret() {
    $bytes = random_token_bytes(20); // 160-bit, standard TOTP secret size
    return base32_encode($bytes);
}

function base32_encode($data) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $bits .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
    }
    $output = '';
    foreach (str_split($bits, 5) as $chunk) {
        if (strlen($chunk) < 5) { $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT); }
        $output .= $alphabet[bindec($chunk)];
    }
    return $output;
}

function base32_decode($b32) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper($b32);
    $bits = '';
    for ($i = 0; $i < strlen($b32); $i++) {
        $pos = strpos($alphabet, $b32[$i]);
        if ($pos === false) { continue; }
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) < 8) { continue; }
        $bytes .= chr(bindec($byte));
    }
    return $bytes;
}

function totp_code_at($secret, $timeSlice) {
    $key = base32_decode($secret);
    $time = pack('N*', 0) . pack('N*', $timeSlice); // 8-byte big-endian counter
    $hmac = hash_hmac('sha1', $time, $key, true);
    $offset = ord(substr($hmac, -1)) & 0x0F;
    $truncated =
        ((ord($hmac[$offset]) & 0x7F) << 24) |
        ((ord($hmac[$offset + 1]) & 0xFF) << 16) |
        ((ord($hmac[$offset + 2]) & 0xFF) << 8) |
        (ord($hmac[$offset + 3]) & 0xFF);
    return str_pad((string) ($truncated % 1000000), 6, '0', STR_PAD_LEFT);
}

// Accepts the current 30s slice plus one slice of drift each way,
// to tolerate small clock skew between server and phone.
function totp_verify($secret, $code, $window = 1) {
    $code = preg_replace('/\s+/', '', $code);
    $slice = (int) floor(time() / 30);
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(totp_code_at($secret, $slice + $i), $code)) {
            return true;
        }
    }
    return false;
}

function totp_provisioning_uri($secret, $accountLabel) {
    return 'otpauth://totp/' . rawurlencode(SITE_NAME . ':' . $accountLabel)
        . '?secret=' . $secret
        . '&issuer=' . rawurlencode(SITE_NAME)
        . '&algorithm=SHA1&digits=6&period=30';
}

// Item 4: 2FA backup/recovery codes - a standard companion to any TOTP
// setup, for when the user loses their authenticator device. Each
// code is single-use; only its hash is stored, exactly like the
// password-reset validator pattern.

function generate_backup_codes($userId, $count = 8) {
    $pdo = db();
    $del = $pdo->prepare('DELETE FROM totp_backup_codes WHERE user_id = ?');
    $del->execute(array($userId));

    $plainCodes = array();
    $ins = $pdo->prepare('INSERT INTO totp_backup_codes (user_id, code_hash) VALUES (?, ?)');
    for ($i = 0; $i < $count; $i++) {
        $code = strtoupper(substr(random_token_hex(5), 0, 4) . '-' . substr(random_token_hex(5), 0, 4));
        $ins->execute(array($userId, hash('sha256', $code)));
        $plainCodes[] = $code;
    }
    return $plainCodes;
}

function verify_and_consume_backup_code($userId, $code) {
    $code = strtoupper(trim($code));
    $hash = hash('sha256', $code);
    $pdo = db();
    $stmt = $pdo->prepare('SELECT id FROM totp_backup_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL');
    $stmt->execute(array($userId, $hash));
    $id = $stmt->fetchColumn();
    if (!$id) { return false; }
    $upd = $pdo->prepare('UPDATE totp_backup_codes SET used_at = NOW() WHERE id = ?');
    $upd->execute(array($id));
    return true;
}

function count_unused_backup_codes($userId) {
    $stmt = db()->prepare('SELECT COUNT(*) FROM totp_backup_codes WHERE user_id = ? AND used_at IS NULL');
    $stmt->execute(array($userId));
    return (int) $stmt->fetchColumn();
}
