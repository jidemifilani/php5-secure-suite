<?php
require_once __DIR__ . '/../app/bootstrap.php';
header('Content-Type: text/plain');

$mode = isset($_GET['mode']) ? $_GET['mode'] : '';
$store = hijack_store_load();

if ($mode === 'vuln') {
    $sid = isset($_COOKIE['vuln_demo_sid']) ? $_COOKIE['vuln_demo_sid'] : null;
    if (!$sid || !isset($store['vuln'][$sid])) {
        echo "DENIED: no matching vulnerable-mode session found.\n";
        exit;
    }
    // VULNERABLE on purpose: the cookie alone is treated as proof of
    // identity. No IP/User-Agent check at all - this is exactly what
    // lets a stolen cookie value work from any client.
    echo "GRANTED (vulnerable mode): session accepted from IP " . client_ip()
        . " with User-Agent \"" . (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '') . "\"\n";
    echo "This is the vulnerability: no check was made that this is the same client that started the session.\n";
    exit;
}

if ($mode === 'safe') {
    $sid = isset($_COOKIE['safe_demo_sid']) ? $_COOKIE['safe_demo_sid'] : null;
    if (!$sid || !isset($store['safe'][$sid])) {
        echo "DENIED: no matching patched-mode session found.\n";
        exit;
    }
    $expectedFp = $store['safe'][$sid]['fp'];
    $actualFp = hijack_demo_fingerprint();
    if (!hash_equals($expectedFp, $actualFp)) {
        unset($store['safe'][$sid]);
        hijack_store_save($store);
        echo "BLOCKED: fingerprint mismatch (IP/User-Agent changed since this session was created).\n";
        echo "Expected fingerprint: " . $expectedFp . "\n";
        echo "Actual fingerprint:   " . $actualFp . "\n";
        echo "The session record has been destroyed - this cookie is now worthless.\n";
        exit;
    }
    echo "GRANTED (patched mode): fingerprint matches. Same client that created the session.\n";
    exit;
}

echo "Usage: ?mode=vuln or ?mode=safe\n";
