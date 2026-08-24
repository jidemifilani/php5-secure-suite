<?php
// General helpers. PHP 5.6-safe only: no ??, no spaceship, no scalar
// type hints, no random_bytes()/random_int() (those are PHP 7+).

function e($value) {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function random_token_bytes($length) {
    // openssl_random_pseudo_bytes is the CSPRNG available on PHP 5.6
    // (random_bytes() itself didn't exist until PHP 7.0).
    $strong = false;
    $bytes = openssl_random_pseudo_bytes($length, $strong);
    if ($bytes === false || $strong === false) {
        throw new Exception('CSPRNG unavailable');
    }
    return $bytes;
}

function random_token_hex($length) {
    return bin2hex(random_token_bytes($length));
}

// Server-side signing key for HMAC-signed tokens (password resets,
// API-adjacent uses). Generated once, persisted outside the web root
// - never hardcoded in source.
function app_secret() {
    static $secret = null;
    if ($secret !== null) { return $secret; }
    $path = KEYS_PATH . DIRECTORY_SEPARATOR . 'app_secret.bin';
    if (!is_file($path)) {
        if (!is_dir(KEYS_PATH)) { mkdir(KEYS_PATH, 0700, true); }
        file_put_contents($path, random_token_bytes(32));
        chmod($path, 0600);
    }
    $secret = file_get_contents($path);
    return $secret;
}

// Clean-URL helper: given "login" or "admin/users", returns the
// extension-less site-relative URL. Old *.php URLs keep working
// (router.php falls back to serving the real file). This app runs
// on its own dedicated PHP 5.6 dev server port, not nested under a
// shared docroot subpath, so it always owns "/" - no need to derive
// a base path from SCRIPT_NAME (which is unreliable across routed
// vs. direct requests under the built-in server's router mode).
function base_url($path) {
    return '/' . ltrim($path, '/');
}

function redirect($path) {
    header('Location: ' . base_url($path));
    exit;
}

function flash_set($key, $message) {
    if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }
    $_SESSION['_flash'][$key] = $message;
}

function flash_get($key) {
    if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }
    if (!isset($_SESSION['_flash'][$key])) { return null; }
    $msg = $_SESSION['_flash'][$key];
    unset($_SESSION['_flash'][$key]);
    return $msg;
}

function json_response($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

// Item 11: open-redirect guard. Only allows a single-leading-slash,
// same-site relative path - rejects protocol-relative ("//evil.com",
// parsed by browsers as https://evil.com), absolute URLs, and
// backslash tricks some browsers still normalize into a host.
function is_safe_relative_redirect($url) {
    if (!is_string($url) || $url === '') { return false; }
    if ($url[0] !== '/') { return false; }
    if (isset($url[1]) && ($url[1] === '/' || $url[1] === '\\')) { return false; }
    if (strpos($url, '://') !== false) { return false; }
    return true;
}

function client_ip() {
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

function current_user_id() {
    return isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
}

function require_login() {
    if (!current_user_id()) {
        flash_set('error', 'Please log in to continue.');
        redirect('login');
    }
}
