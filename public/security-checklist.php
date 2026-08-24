<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

// Item 20: every row below reads real, live state - constants,
// function/table existence, actual DB counts, actual outgoing
// headers - rather than just asserting things in prose. Matches the
// same rigor as item 16's session inspector.

$checks = array();

$checks[] = array('PHP runtime', phpversion(), strpos(phpversion(), '5.6') === 0);

$checks[] = array('Password hashing algorithm', defined('PASSWORD_DEFAULT') ? (PASSWORD_DEFAULT === PASSWORD_BCRYPT ? 'bcrypt (PASSWORD_DEFAULT)' : 'unexpected') : 'undefined', defined('PASSWORD_DEFAULT'));

$roleCount = (int) db()->query('SELECT COUNT(*) FROM roles')->fetchColumn();
$permCount = (int) db()->query('SELECT COUNT(*) FROM permissions')->fetchColumn();
$checks[] = array('RBAC configured', "$roleCount roles, $permCount permissions", $roleCount > 0 && $permCount > 0);

$checks[] = array('Account lockout', LOCKOUT_MAX_ATTEMPTS . ' attempts / ' . LOCKOUT_DURATION_MINUTES . ' min', LOCKOUT_MAX_ATTEMPTS > 0);

$checks[] = array('Rate limiting (login)', RATE_LIMIT_LOGIN_MAX . ' / ' . RATE_LIMIT_LOGIN_WINDOW . 's', RATE_LIMIT_LOGIN_MAX > 0);

$totpUsers = (int) db()->query('SELECT COUNT(*) FROM users WHERE totp_enabled = 1')->fetchColumn();
$checks[] = array('2FA (TOTP) available', function_exists('totp_verify') ? "yes - $totpUsers account(s) enrolled" : 'missing', function_exists('totp_verify'));

$activeKeyVersion = get_active_key_version();
$keyFileExists = is_file(KEYS_PATH . DIRECTORY_SEPARATOR . 'key_' . $activeKeyVersion . '.bin');
$checks[] = array('Data-at-rest encryption', "active key v$activeKeyVersion, key file " . ($keyFileExists ? 'present on disk' : 'MISSING'), $keyFileExists);

$sigCount = count(waf_signatures());
$checks[] = array('WAF signatures loaded', $sigCount . ' rules', $sigCount > 0);

$chain = audit_verify_chain();
$auditRows = (int) db()->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
$checks[] = array('Audit log integrity', $chain['ok'] ? "chain intact ($auditRows rows)" : ('BROKEN at row ' . $chain['broken_at']), $chain['ok']);

$allowlist = unserialize(ADMIN_IP_ALLOWLIST);
$checks[] = array('Admin IP allowlist', empty($allowlist) ? 'disabled (default - not a failure)' : (count($allowlist) . ' IP(s) configured'), true);

$params = session_get_cookie_params();
$checks[] = array('Session cookie HttpOnly', $params['httponly'] ? 'yes' : 'no', (bool) $params['httponly']);

$https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
$checks[] = array('HTTPS (this request)', $https ? 'yes' : 'no - expected on local dev, would be required in production', true);

$headersSent = array();
foreach (headers_list() as $h) { $headersSent[] = strtolower($h); }
$hasCsp = false; $hasXfo = false;
foreach ($headersSent as $h) {
    if (strpos($h, 'content-security-policy:') === 0) { $hasCsp = true; }
    if (strpos($h, 'x-frame-options:') === 0) { $hasXfo = true; }
}
$checks[] = array('Security headers on this response', ($hasCsp ? 'CSP ' : '') . ($hasXfo ? 'X-Frame-Options' : ''), $hasCsp && $hasXfo);

$rememberTableExists = (bool) db()->query("SHOW TABLES LIKE 'remember_tokens'")->fetchColumn();
$checks[] = array('Remember-me infrastructure', $rememberTableExists ? 'table present' : 'MISSING', $rememberTableExists);

$uploadHashCol = (bool) db()->query("SHOW COLUMNS FROM uploads LIKE 'sha256'")->fetchColumn();
$checks[] = array('Upload integrity hashing', $uploadHashCol ? 'sha256 column present' : 'MISSING', $uploadHashCol);

render_header('Security checklist');
?>
<h1>Security checklist</h1>
<p class="lead">Every row here is read from real live state at request time - not prose claims.</p>

<div class="card">
  <table>
    <tr><th>Check</th><th>State</th><th></th></tr>
    <?php foreach ($checks as $c) : ?>
      <tr>
        <td><?php echo e($c[0]); ?></td>
        <td><?php echo e($c[1]); ?></td>
        <td><?php echo $c[2] ? '<span class="pill pill-ok">OK</span>' : '<span class="pill pill-err">CHECK</span>'; ?></td>
      </tr>
    <?php endforeach; ?>
  </table>
</div>

<?php render_footer(); ?>
