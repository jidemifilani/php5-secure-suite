<?php
// Item 14: secure API gateway - HMAC-SHA256 request signing.
// Signature covers method + path + timestamp + nonce + body, so it's
// bound to this exact request; timestamp skew + single-use nonce
// (unique DB constraint) together stop replay of a captured request.

function api_get_header($headers, $name) {
    foreach ($headers as $key => $value) {
        if (strcasecmp($key, $name) === 0) { return $value; }
    }
    return null;
}

function api_request_headers() {
    if (function_exists('getallheaders')) {
        $h = getallheaders();
        if (is_array($h)) { return $h; }
    }
    $headers = array();
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $name = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
            $headers[$name] = $value;
        }
    }
    return $headers;
}

// Creates a new API key. Returns the ONE-TIME-VISIBLE plaintext
// secret alongside the public key id; only the encrypted form is
// ever persisted, matching how item 11's encryption module is used
// elsewhere in this app.
function api_create_key($label) {
    $apiKey = random_token_hex(16);
    $secret = random_token_hex(32);
    $enc = crypto_encrypt($secret);

    $stmt = db()->prepare(
        'INSERT INTO api_keys (label, api_key, secret_ciphertext, secret_iv, secret_tag, key_version)
         VALUES (?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute(array($label, $apiKey, $enc['ciphertext'], $enc['iv'], $enc['tag'], $enc['key_version']));

    return array('api_key' => $apiKey, 'secret' => $secret);
}

function api_find_key($apiKey) {
    $stmt = db()->prepare('SELECT * FROM api_keys WHERE api_key = ? AND is_active = 1');
    $stmt->execute(array($apiKey));
    return $stmt->fetch();
}

function api_compute_signature($secret, $method, $path, $timestamp, $nonce, $body) {
    $payload = strtoupper($method) . "\n" . $path . "\n" . $timestamp . "\n" . $nonce . "\n" . $body;
    return hash_hmac('sha256', $payload, $secret);
}

// Verifies the current request against the standard headers. Returns
// array('ok' => bool, 'error' => string|null, 'api_key_row' => array|null).
function api_verify_request($method, $path, $rawBody) {
    $headers = api_request_headers();
    $apiKey = api_get_header($headers, 'X-Api-Key');
    $timestamp = api_get_header($headers, 'X-Timestamp');
    $nonce = api_get_header($headers, 'X-Nonce');
    $signature = api_get_header($headers, 'X-Signature');

    if (!$apiKey || !$timestamp || !$nonce || !$signature) {
        return array('ok' => false, 'error' => 'Missing one of X-Api-Key/X-Timestamp/X-Nonce/X-Signature.', 'api_key_row' => null);
    }

    if (!ctype_digit((string) $timestamp) || abs(time() - (int) $timestamp) > API_TIMESTAMP_SKEW) {
        return array('ok' => false, 'error' => 'Timestamp missing/too far from server time - request rejected as stale or replayed.', 'api_key_row' => null);
    }

    $row = api_find_key($apiKey);
    if (!$row) {
        return array('ok' => false, 'error' => 'Unknown or inactive API key.', 'api_key_row' => null);
    }

    try {
        $secret = crypto_decrypt($row['secret_ciphertext'], $row['secret_iv'], $row['secret_tag'], $row['key_version']);
    } catch (Exception $ex) {
        return array('ok' => false, 'error' => 'Server could not decrypt key secret.', 'api_key_row' => null);
    }

    $expected = api_compute_signature($secret, $method, $path, $timestamp, $nonce, $rawBody);
    if (!hash_equals($expected, strtolower($signature))) {
        return array('ok' => false, 'error' => 'Signature mismatch.', 'api_key_row' => null);
    }

    try {
        $stmt = db()->prepare('INSERT INTO api_nonces (api_key_id, nonce) VALUES (?, ?)');
        $stmt->execute(array($row['id'], $nonce));
    } catch (PDOException $ex) {
        // Unique (api_key_id, nonce) violation = this exact request was already used once.
        return array('ok' => false, 'error' => 'Nonce already used - possible replay.', 'api_key_row' => null);
    }

    return array('ok' => true, 'error' => null, 'api_key_row' => $row);
}
