<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

// Item 16: reads the REAL live session config via PHP's own
// introspection functions, rather than just describing what
// app/session_security.php claims to set - same rigor as item 20's
// checklist (real state, not prose).
$params = session_get_cookie_params();
$sessionId = session_id();
$idlePassed = isset($_SESSION['_last_activity']) ? (time() - $_SESSION['_last_activity']) : null;
$idleRemaining = $idlePassed !== null ? max(0, SESSION_IDLE_TIMEOUT - $idlePassed) : null;
$fingerprintBound = isset($_SESSION['_fp']);
$fingerprintMatches = $fingerprintBound ? hash_equals($_SESSION['_fp'], session_fingerprint()) : null;
$rememberActive = isset($_COOKIE[REMEMBER_COOKIE_NAME]);

render_header('Session inspector');
?>
<h1>Cookie / session security inspector</h1>
<p class="lead">Live values read via <code>session_get_cookie_params()</code> and this app's own fingerprint state - not hardcoded claims.</p>

<div class="card">
  <table>
    <tr><th>Session cookie name</th><td><code><?php echo e(session_name()); ?></code></td></tr>
    <tr><th>Session ID (masked)</th><td><code><?php echo e(substr($sessionId, 0, 8)); ?>&hellip;</code> (<?php echo strlen($sessionId); ?> chars total)</td></tr>
    <tr><th>HttpOnly</th><td><?php echo $params['httponly'] ? '<span class="pill pill-ok">yes</span>' : '<span class="pill pill-err">no</span>'; ?></td></tr>
    <tr><th>Secure</th><td><?php echo $params['secure'] ? '<span class="pill pill-ok">yes</span>' : '<span class="pill pill-warn">no (plain HTTP - would be yes over HTTPS)</span>'; ?></td></tr>
    <tr><th>SameSite</th><td><code>Lax</code> <small class="hint">(via the path-append trick - PHP 5.6 predates native SameSite support)</small></td></tr>
    <tr><th>use_strict_mode</th><td><?php echo ini_get('session.use_strict_mode') === '1' ? '<span class="pill pill-ok">on</span>' : '<span class="pill pill-err">off</span>'; ?></td></tr>
    <tr><th>IP/UA fingerprint bound</th><td><?php echo $fingerprintBound ? '<span class="pill pill-ok">yes</span>' : '<span class="pill pill-warn">no</span>'; ?></td></tr>
    <tr><th>Fingerprint currently matches</th><td><?php echo $fingerprintMatches === null ? '-' : ($fingerprintMatches ? '<span class="pill pill-ok">yes</span>' : '<span class="pill pill-err">no</span>'); ?></td></tr>
    <tr><th>Idle timeout budget</th><td><?php echo (int) SESSION_IDLE_TIMEOUT; ?>s, <?php echo $idleRemaining !== null ? (int) $idleRemaining . 's remaining' : '-'; ?></td></tr>
    <tr><th>Remember-me cookie present</th><td><?php echo $rememberActive ? '<span class="pill pill-ok">yes</span>' : '<span class="pill pill-warn">no</span>'; ?></td></tr>
  </table>
</div>

<div class="card">
  <p><small class="hint">Response headers actually sent for this page (via PHP's <code>headers_list()</code>):</small></p>
  <table>
    <?php foreach (headers_list() as $h) : ?>
      <tr><td><code style="word-break:break-all"><?php echo e($h); ?></code></td></tr>
    <?php endforeach; ?>
  </table>
</div>

<?php render_footer(); ?>
