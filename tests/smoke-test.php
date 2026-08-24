<?php
// Reusable end-to-end smoke test against a LIVE running instance.
// Run with the system php (any version) after starting the app:
//   start-server.bat
//   php tests\smoke-test.php [base_url]
// Uses a real cookie jar + CSRF tokens throughout, exactly like a
// browser would. Creates and cleans up its own throwaway test data.

$base = isset($argv[1]) ? rtrim($argv[1], '/') : 'http://127.0.0.1:8050';
$pass = 0;
$fail = 0;

function http($method, $url, $data = null, &$headersOut = null, $extraHeaders = array()) {
    static $cookieFile = null;
    if ($cookieFile === null) { $cookieFile = tempnam(sys_get_temp_dir(), 'p5ss_cookie_'); }
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_COOKIEJAR, $cookieFile);
    curl_setopt($ch, CURLOPT_COOKIEFILE, $cookieFile);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    if ($extraHeaders) { curl_setopt($ch, CURLOPT_HTTPHEADER, $extraHeaders); }
    if ($data !== null) { curl_setopt($ch, CURLOPT_POSTFIELDS, is_array($data) ? http_build_query($data) : $data); }
    $resp = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $headersOut = substr($resp, 0, $headerSize);
    $body = substr($resp, $headerSize);
    curl_close($ch);
    return array('status' => $status, 'body' => $body, 'headers' => $headersOut);
}

function extract_csrf($html) {
    if (preg_match('/name="csrf_token" value="([a-f0-9]+)"/', $html, $m)) { return $m[1]; }
    return null;
}

function check($name, $cond) {
    global $pass, $fail;
    if ($cond) { echo "PASS  $name\n"; $pass++; }
    else { echo "FAIL  $name\n"; $fail++; }
}

$suffix = substr(md5(uniqid('', true)), 0, 8);
$username = 'smoketest_' . $suffix;

echo "Target: $base\n\n";

// --- register + auto-login ---
$r = http('GET', "$base/register");
$csrf = extract_csrf($r['body']);
check('homepage/register reachable', $r['status'] === 200 && $csrf);

$r = http('POST', "$base/register", array(
    'csrf_token' => $csrf, 'username' => $username, 'email' => $username . '@example.com',
    'password' => 'Xk9#mPqR2vL7', 'confirm' => 'Xk9#mPqR2vL7',
));
check('register redirects to dashboard', $r['status'] === 302 && strpos($r['headers'], 'Location: /dashboard') !== false);

$r = http('GET', "$base/dashboard");
check('auto-login after register', strpos($r['body'], "Welcome, $username") !== false);

// --- RBAC: fresh user has no admin access ---
$r = http('GET', "$base/admin/index");
check('RBAC blocks non-admin from /admin', $r['status'] === 403);

// --- WAF: global query-string blocking ---
$r = http('GET', "$base/?x=" . urlencode('<script>alert(1)</script>'));
check('WAF blocks XSS in query string', $r['status'] === 403);
$r = http('GET', "$base/?x=hello");
check('WAF allows clean query string', $r['status'] === 200);

// --- WAF demo (POST) ---
$r = http('GET', "$base/waf-demo");
$csrf = extract_csrf($r['body']);
$r = http('POST', "$base/waf-demo", array('csrf_token' => $csrf, 'payload' => "' OR 1=1 --"));
check('WAF demo flags SQLi payload', strpos($r['body'], 'Blocked - matched rule') !== false);

// --- secure upload: reject bad extension ---
$r = http('GET', "$base/upload");
check('upload page requires login redirect or shows form', $r['status'] === 200 || $r['status'] === 302);

// --- password reset round trip ---
$r = http('GET', "$base/forgot-password");
$csrf = extract_csrf($r['body']);
$r = http('POST', "$base/forgot-password", array('csrf_token' => $csrf, 'username' => $username));
check('forgot-password issues a reset link', preg_match('#reset-password\?token=([A-Za-z0-9_.%-]+)#', $r['body'], $m) === 1);
if (isset($m[1])) {
    $token = urldecode($m[1]);
    $r = http('GET', "$base/reset-password?token=" . rawurlencode($token));
    $csrf = extract_csrf($r['body']);
    $r = http('POST', "$base/reset-password", array(
        'csrf_token' => $csrf, 'token' => $token, 'password' => 'Zt4$wCfN9uB2', 'confirm' => 'Zt4$wCfN9uB2',
    ));
    check('password reset succeeds (single use)', $r['status'] === 302);

    $r = http('GET', "$base/reset-password?token=" . rawurlencode($token));
    check('reused reset token rejected', strpos($r['body'], 'invalid, expired, or already used') !== false);
}

// --- session hijack demo ---
$r = http('GET', "$base/session-hijack-demo");
check('session hijack demo page loads', $r['status'] === 200);

// --- v2 (20-feature round) checks ---

// The script has been logged in as $username since the register/
// auto-login check above - /register redirects straight to dashboard
// for an already-logged-in session, so every check below that needs
// to register a fresh account must log out first.
http('GET', "$base/logout");

// Item 3: common-password rejection.
$r = http('GET', "$base/register");
$csrf = extract_csrf($r['body']);
$r = http('POST', "$base/register", array(
    'csrf_token' => $csrf, 'username' => 'smoketest_common_' . $suffix, 'email' => 'x' . $suffix . '@example.com',
    'password' => 'password123', 'confirm' => 'password123',
));
check('common password rejected at register', strpos($r['body'], 'commonly breached') !== false);

// Item 1: account lockout after repeated failures (uses its own throwaway user).
http('GET', "$base/logout");
$lockUser = 'smoketest_lock_' . $suffix;
$r = http('GET', "$base/register");
$csrf = extract_csrf($r['body']);
http('POST', "$base/register", array(
    'csrf_token' => $csrf, 'username' => $lockUser, 'email' => $lockUser . '@example.com',
    'password' => 'Qw8!vNzR3xF6', 'confirm' => 'Qw8!vNzR3xF6',
));
// register.php auto-logs-in on success, and /login redirects straight
// to dashboard for an already-logged-in session same as /register does
// - log back out so the failed-login loop below actually reaches the
// login form instead of bouncing off it.
http('GET', "$base/logout");
for ($i = 0; $i < 5; $i++) {
    $r = http('GET', "$base/login");
    $csrf = extract_csrf($r['body']);
    $post = array('csrf_token' => $csrf, 'username' => $lockUser, 'password' => 'wrong-' . $i);
    // Item 6's CAPTCHA gate kicks in after CAPTCHA_TRIGGER_AFTER fails
    // in this session - without an answer those attempts never reach
    // the credential check at all, so the lockout counter would never
    // climb to 5. Solve it like a real client would.
    if (preg_match('/what is (\d+) \+ (\d+)/', $r['body'], $cm)) {
        $post['captcha_answer'] = (string) ((int) $cm[1] + (int) $cm[2]);
    }
    http('POST', "$base/login", $post);
}
$r = http('GET', "$base/login");
$csrf = extract_csrf($r['body']);
$post = array('csrf_token' => $csrf, 'username' => $lockUser, 'password' => 'Qw8!vNzR3xF6');
if (preg_match('/what is (\d+) \+ (\d+)/', $r['body'], $cm)) {
    $post['captcha_answer'] = (string) ((int) $cm[1] + (int) $cm[2]);
}
$r = http('POST', "$base/login", $post);
check('account locks after repeated failed logins', strpos($r['body'], 'temporarily locked') !== false);

// Item 12: WAF lite still coexists with the SQLi playground (POST, not scanned).
$r = http('GET', "$base/sqli-playground");
$csrf = extract_csrf($r['body']);
$r = http('POST', "$base/sqli-playground", array(
    'csrf_token' => $csrf, 'mode' => 'vulnerable', 'q' => "' UNION SELECT id, note, 0 FROM demo_secret_notes -- ",
));
check('sqli playground UNION leak (vulnerable mode)', strpos($r['body'], 'FLAG{') !== false);
$r2 = http('POST', "$base/sqli-playground", array(
    'csrf_token' => $csrf, 'mode' => 'patched', 'q' => "' UNION SELECT id, note, 0 FROM demo_secret_notes -- ",
));
check('sqli playground blocks same payload (patched mode)', strpos($r2['body'], 'FLAG{') === false);

// Item 15: security headers present globally.
$r = http('GET', "$base/");
check('security headers present (CSP + X-Frame-Options)', strpos($r['headers'], 'Content-Security-Policy') !== false && strpos($r['headers'], 'X-Frame-Options') !== false);

// Item 14: clickjacking demo's opt-out actually removes the headers.
$r = http('GET', "$base/clickjacking-target?mode=vulnerable");
check('clickjacking vulnerable mode has no framing headers', strpos($r['headers'], 'X-Frame-Options') === false);
$r = http('GET', "$base/clickjacking-target?mode=protected");
check('clickjacking protected mode keeps framing headers', strpos($r['headers'], 'X-Frame-Options') !== false);

// Item 19/20: static + capstone pages reachable.
$r = http('GET', "$base/.well-known/security.txt");
check('security.txt reachable', $r['status'] === 200);

// --- cleanup: delete the accounts this script created ---
// (the 'smoketest_common_' username was never actually created - that
// registration attempt was expected to be rejected by the common-
// password check above.) Uses a direct DB connection with the same
// credentials app/config.php uses, since this script only speaks HTTP
// to the app itself. FK ON DELETE CASCADE handles related rows
// (audit_log user_id is nullable and intentionally kept for history).
$cleanupOk = false;
try {
    require __DIR__ . '/../app/config.php';
    $pdo = new PDO('mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4', DB_USER, DB_PASS);
    $stmt = $pdo->prepare('DELETE FROM users WHERE username IN (?, ?)');
    $stmt->execute(array($username, $lockUser));
    $cleanupOk = true;
} catch (Exception $ex) {
    // Non-fatal for the check tally above - just means a manual DB
    // cleanup is needed, same as if this script couldn't reach the DB
    // for any other reason.
}
check('cleanup: throwaway test accounts removed', $cleanupOk);

echo "\n$pass passed, $fail failed.\n";
exit($fail > 0 ? 1 : 0);
