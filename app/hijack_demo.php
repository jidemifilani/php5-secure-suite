<?php
// Shared helpers for the item-9 session hijacking demo
// (public/session-hijack-demo.php + public/session-hijack-check.php).
// Deliberately isolated from the real app session and from
// app/session_security.php - see the comment at the top of
// session-hijack-demo.php for why.

function hijack_store_path() { return LOGS_PATH . DIRECTORY_SEPARATOR . 'hijack_demo.json'; }

function hijack_store_load() {
    $f = hijack_store_path();
    if (!is_file($f)) { return array(); }
    $data = json_decode(file_get_contents($f), true);
    return is_array($data) ? $data : array();
}

function hijack_store_save($data) {
    if (!is_dir(LOGS_PATH)) { mkdir(LOGS_PATH, 0700, true); }
    file_put_contents(hijack_store_path(), json_encode($data), LOCK_EX);
}

function hijack_demo_fingerprint() {
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    return hash('sha256', client_ip() . '|' . $ua);
}
