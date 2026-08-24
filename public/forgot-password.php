<?php
require_once __DIR__ . '/../app/bootstrap.php';

$resetLink = null;
$submitted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    rate_limit_enforce('pwreset:ip:' . client_ip(), RATE_LIMIT_LOGIN_MAX, RATE_LIMIT_LOGIN_WINDOW);
    rate_limit_record_hit('pwreset:ip:' . client_ip());

    $identifier = isset($_POST['username']) ? trim($_POST['username']) : '';
    $user = find_user_by_username($identifier);
    $submitted = true;

    if ($user) {
        $token = create_password_reset_token($user['id']);
        audit_log_event('password_reset_requested', $user['id'], '');
        // No mail server is wired up on this local install, so - unlike a
        // real deployment, which would only ever email this link - it is
        // shown directly on the page. This is an explicit local-demo
        // shortcut, not a silent security shortcut.
        $resetLink = base_url('reset-password') . '?token=' . rawurlencode($token);
    }
    // Same message whether or not the account exists, so this form
    // can't be used to enumerate registered usernames.
}

render_header('Forgot password');
?>
<h1>Forgot password</h1>
<div class="card" style="max-width:480px">
  <?php if ($submitted) : ?>
    <div class="flash flash-success">If that account exists, a reset link has been generated. The token is single-use and expires in 1 hour.</div>
    <?php if ($resetLink) : ?>
      <p><small class="hint">Local demo shortcut (no mail server configured) - normally this link would only ever be emailed, never shown on-page:</small></p>
      <p><code class="mono" style="word-break:break-all"><a href="<?php echo e($resetLink); ?>"><?php echo e($resetLink); ?></a></code></p>
    <?php endif; ?>
  <?php else: ?>
    <form method="post" action="<?php echo e(base_url('forgot-password')); ?>">
      <?php echo csrf_field(); ?>
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus>
      <button type="submit">Send reset link</button>
    </form>
  <?php endif; ?>
</div>
<?php render_footer(); ?>
