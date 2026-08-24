<?php
require_once __DIR__ . '/../app/bootstrap.php';

// Item 9: session hijacking demo + fix. This uses its OWN cookies
// ("vuln_demo_sid" / "safe_demo_sid") and its own tiny JSON-file
// store - entirely separate from the real app session
// (P5SS_SESSION, secured in app/session_security.php and used for
// every other page). That keeps the deliberately-insecure "vuln"
// code path fully contained: nothing here can ever touch a real
// login session, matching how this project's other vulnerable-vs-
// patched demos (WAF signatures aside) stay sandboxed.

$action = isset($_GET['action']) ? $_GET['action'] : (isset($_POST['action']) ? $_POST['action'] : '');
$message = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'start_vuln') {
    csrf_require();
    $sid = bin2hex(openssl_random_pseudo_bytes(16));
    // VULNERABLE on purpose: HttpOnly off (JS-readable, like a real
    // XSS-assisted theft), no fingerprint binding recorded at all.
    setcookie('vuln_demo_sid', $sid, 0, '/', '', false, false);
    $store = hijack_store_load();
    $store['vuln'][$sid] = array('created' => time());
    hijack_store_save($store);
    $message = 'Vulnerable demo session started. Its cookie has no HttpOnly flag and no IP/UA binding.';
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'start_safe') {
    csrf_require();
    $sid = bin2hex(openssl_random_pseudo_bytes(32));
    setcookie('safe_demo_sid', $sid, 0, '/; SameSite=Lax', '', false, true); // HttpOnly on
    $store = hijack_store_load();
    $store['safe'][$sid] = array('created' => time(), 'fp' => hijack_demo_fingerprint());
    hijack_store_save($store);
    $message = 'Patched demo session started. HttpOnly cookie + IP/User-Agent fingerprint bound server-side.';
}

$vulnCookie = isset($_COOKIE['vuln_demo_sid']) ? $_COOKIE['vuln_demo_sid'] : null;
$safeCookie = isset($_COOKIE['safe_demo_sid']) ? $_COOKIE['safe_demo_sid'] : null;

render_header('Session hijacking demo');
?>
<h1>Session hijacking: vulnerable vs. patched</h1>
<p class="lead">This demo runs two independent mini-sessions side by side, each with its own cookie. The real login session used everywhere else on this site always uses the patched approach (<code>app/session_security.php</code>): HttpOnly + a manually-appended <code>SameSite=Lax</code> (PHP 5.6 predates native SameSite support, added in 7.3), <code>session_regenerate_id(true)</code> on login, and an IP/User-Agent fingerprint checked on every request.</p>

<?php if ($message) : ?><div class="flash flash-success"><?php echo e($message); ?></div><?php endif; ?>

<div class="two-col">
  <div class="card">
    <h2>Vulnerable</h2>
    <p>No <code>HttpOnly</code>, no fingerprint binding. Whoever holds the cookie value is treated as authenticated, from anywhere, with any User-Agent.</p>
    <form method="post" action="<?php echo e(base_url('session-hijack-demo')); ?>">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="start_vuln">
      <button type="submit">Start vulnerable session</button>
    </form>
    <?php if ($vulnCookie) : ?>
      <p><small class="hint">Cookie value:</small><br><code class="mono" style="word-break:break-all"><?php echo e($vulnCookie); ?></code></p>
      <p><a class="btn secondary" href="<?php echo e(base_url('session-hijack-check')); ?>?mode=vuln">Check status &rarr;</a></p>
      <p><small class="hint">Simulate theft from a different client:<br>
        <code class="mono">curl -H "User-Agent: EvilBot" --cookie "vuln_demo_sid=<?php echo e($vulnCookie); ?>" "<?php echo e(base_url('session-hijack-check')); ?>?mode=vuln"</code>
      </small></p>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2>Patched</h2>
    <p><code>HttpOnly</code> set, and the session is bound to <code>hash(IP + User-Agent)</code> at creation. A request presenting the same cookie from a different IP or User-Agent is rejected and the record is destroyed.</p>
    <form method="post" action="<?php echo e(base_url('session-hijack-demo')); ?>">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="start_safe">
      <button type="submit">Start patched session</button>
    </form>
    <?php if ($safeCookie) : ?>
      <p><small class="hint">Cookie value:</small><br><code class="mono" style="word-break:break-all"><?php echo e($safeCookie); ?></code></p>
      <p><a class="btn secondary" href="<?php echo e(base_url('session-hijack-check')); ?>?mode=safe">Check status &rarr;</a></p>
      <p><small class="hint">Try the same stolen-cookie attack here - it gets blocked:<br>
        <code class="mono">curl -H "User-Agent: EvilBot" --cookie "safe_demo_sid=<?php echo e($safeCookie); ?>" "<?php echo e(base_url('session-hijack-check')); ?>?mode=safe"</code>
      </small></p>
    <?php endif; ?>
  </div>
</div>

<div class="card">
  <p><small class="hint">Your current fingerprint basis: IP <code><?php echo e(client_ip()); ?></code>, User-Agent <code><?php echo e(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''); ?></code></small></p>
</div>

<?php render_footer(); ?>
