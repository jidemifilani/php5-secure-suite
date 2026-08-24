<?php
// Item 11: AES-256 data-at-rest encryption with key rotation.
// Key material never touches the database - only storage/keys/*.bin
// (outside web root) holds it, so a DB dump alone decrypts nothing.
//
// This is AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC, NOT AES-GCM.
// GCM was the original plan, but openssl_encrypt()'s $tag output
// parameter (needed to retrieve the AEAD auth tag) was only added in
// PHP 7.1 - confirmed the hard way against this real PHP 5.6.40
// build ("openssl_encrypt() expects at most 5 parameters, 6 given").
// PHP 5.6 can still request the aes-256-gcm cipher by name via
// openssl_get_cipher_methods(), which is what made this look
// available until it was actually exercised. Encrypt-then-MAC gives
// the same authenticated-encryption guarantee (tamper-evident
// ciphertext) using only primitives PHP 5.6 actually has: a 32-byte
// master key per version is expanded into an independent encryption
// key and MAC key via HMAC (a minimal HKDF-Expand), so the same two
// keys are never reused for both purposes.

function derive_subkeys($masterKey) {
    return array(
        'enc' => hash_hmac('sha256', 'enc', $masterKey, true),
        'mac' => hash_hmac('sha256', 'mac', $masterKey, true),
    );
}

function key_file_path($version) {
    return KEYS_PATH . DIRECTORY_SEPARATOR . 'key_' . (int) $version . '.bin';
}

function ensure_active_key() {
    $stmt = db()->query('SELECT MAX(key_version) FROM encryption_keys WHERE is_active = 1');
    $version = $stmt->fetchColumn();
    if ($version) { return (int) $version; }
    return create_new_key();
}

function create_new_key() {
    $pdo = db();
    $pdo->exec('INSERT INTO encryption_keys (is_active) VALUES (1)');
    $version = (int) $pdo->lastInsertId();
    $material = random_token_bytes(32); // 256-bit key
    file_put_contents(key_file_path($version), $material);
    chmod(key_file_path($version), 0600);
    return $version;
}

function get_key_material($version) {
    $path = key_file_path($version);
    if (!is_file($path)) {
        throw new Exception('Missing key material for version ' . $version);
    }
    return file_get_contents($path);
}

function get_active_key_version() {
    return ensure_active_key();
}

// Returns array(ciphertext, iv, tag, key_version) - all raw binary
// except key_version. "tag" here is an HMAC-SHA256 MAC (32 bytes)
// over iv||ciphertext, not a GCM auth tag - see the note above.
function crypto_encrypt($plaintext) {
    $version = get_active_key_version();
    $sub = derive_subkeys(get_key_material($version));
    $iv = random_token_bytes(16); // AES block size, CBC IV
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $sub['enc'], OPENSSL_RAW_DATA, $iv);
    if ($ciphertext === false) {
        throw new Exception('Encryption failed');
    }
    $mac = hash_hmac('sha256', $iv . $ciphertext, $sub['mac'], true);
    return array(
        'ciphertext' => $ciphertext,
        'iv' => $iv,
        'tag' => $mac,
        'key_version' => $version,
    );
}

function crypto_decrypt($ciphertext, $iv, $tag, $keyVersion) {
    $sub = derive_subkeys(get_key_material($keyVersion));
    $expectedMac = hash_hmac('sha256', $iv . $ciphertext, $sub['mac'], true);
    if (!hash_equals($expectedMac, $tag)) {
        throw new Exception('Decryption failed - MAC verification failed (tampered ciphertext or wrong key)');
    }
    $plaintext = openssl_decrypt($ciphertext, 'aes-256-cbc', $sub['enc'], OPENSSL_RAW_DATA, $iv);
    if ($plaintext === false) {
        throw new Exception('Decryption failed - openssl_decrypt rejected the ciphertext');
    }
    return $plaintext;
}

// Rotates to a brand new key: re-encrypts every row that used an
// older key under the new one, then destroys the old key material -
// after this returns, decrypting any row no longer requires (or
// works with) the retired key at all.
function rotate_encryption_key() {
    $pdo = db();
    $oldVersion = get_active_key_version();
    $newVersion = create_new_key();

    $pdo->beginTransaction();
    try {
        $newSub = derive_subkeys(get_key_material($newVersion));

        $stmt = $pdo->query('SELECT id, ciphertext, iv, auth_tag, key_version FROM secure_profile_data WHERE key_version < ' . (int) $newVersion);
        $upd = $pdo->prepare('UPDATE secure_profile_data SET ciphertext = ?, iv = ?, auth_tag = ?, key_version = ? WHERE id = ?');
        foreach ($stmt->fetchAll() as $row) {
            $plain = crypto_decrypt($row['ciphertext'], $row['iv'], $row['auth_tag'], $row['key_version']);
            $newIv = random_token_bytes(16);
            $newCipher = openssl_encrypt($plain, 'aes-256-cbc', $newSub['enc'], OPENSSL_RAW_DATA, $newIv);
            $newMac = hash_hmac('sha256', $newIv . $newCipher, $newSub['mac'], true);
            $upd->execute(array($newCipher, $newIv, $newMac, $newVersion, $row['id']));
        }

        $stmt2 = $pdo->query('SELECT id, secret_ciphertext, secret_iv, secret_tag, key_version FROM api_keys WHERE key_version < ' . (int) $newVersion);
        $upd2 = $pdo->prepare('UPDATE api_keys SET secret_ciphertext = ?, secret_iv = ?, secret_tag = ?, key_version = ? WHERE id = ?');
        foreach ($stmt2->fetchAll() as $row) {
            $plain = crypto_decrypt($row['secret_ciphertext'], $row['secret_iv'], $row['secret_tag'], $row['key_version']);
            $newIv = random_token_bytes(16);
            $newCipher = openssl_encrypt($plain, 'aes-256-cbc', $newSub['enc'], OPENSSL_RAW_DATA, $newIv);
            $newMac = hash_hmac('sha256', $newIv . $newCipher, $newSub['mac'], true);
            $upd2->execute(array($newCipher, $newIv, $newMac, $newVersion, $row['id']));
        }

        $retire = $pdo->prepare('UPDATE encryption_keys SET is_active = 0, retired_at = NOW() WHERE key_version = ?');
        $retire->execute(array($oldVersion));

        $pdo->commit();
    } catch (Exception $ex) {
        $pdo->rollBack();
        throw $ex;
    }

    // Only safe to destroy the old key material after every row that
    // used it has been re-encrypted and committed above.
    $oldPath = key_file_path($oldVersion);
    if (is_file($oldPath)) { unlink($oldPath); }

    audit_log_event('encryption_key_rotated', current_user_id(), 'retired v' . $oldVersion . ', active v' . $newVersion);
    return $newVersion;
}

// Sensitive-field helpers built on the primitives above (item 11's
// user-facing demo: NIN/BVN fields, encrypted per row).

function secure_field_set($userId, $fieldName, $plaintext) {
    $enc = crypto_encrypt($plaintext);
    $stmt = db()->prepare(
        'INSERT INTO secure_profile_data (user_id, field_name, ciphertext, iv, auth_tag, key_version)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE ciphertext = VALUES(ciphertext), iv = VALUES(iv), auth_tag = VALUES(auth_tag), key_version = VALUES(key_version)'
    );
    $stmt->execute(array($userId, $fieldName, $enc['ciphertext'], $enc['iv'], $enc['tag'], $enc['key_version']));
}

function secure_fields_for_user($userId) {
    $stmt = db()->prepare('SELECT field_name, ciphertext, iv, auth_tag, key_version FROM secure_profile_data WHERE user_id = ?');
    $stmt->execute(array($userId));
    $out = array();
    foreach ($stmt->fetchAll() as $row) {
        $out[$row['field_name']] = crypto_decrypt($row['ciphertext'], $row['iv'], $row['auth_tag'], $row['key_version']);
    }
    return $out;
}
