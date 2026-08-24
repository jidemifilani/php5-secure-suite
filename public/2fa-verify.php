<?php
require_once __DIR__ . '/../app/bootstrap.php';

$pendingUserId = isset($_SESSION['2fa_pending_user']) ? (int) $_SESSION['2fa_pending_user'] : null;
if (!$pendingUserId) { redirect('login'); }

$errors = array();
$useBackup = isset($_GET['backup']) || (isset($_POST['use_backup']) && $_POST['use_backup'] === '1');

function complete_2fa_login($userId) {
    unset($_SESSION['2fa_pending_user']);
    $remember = !empty($_SESSION['2fa_pending_remember']);
    unset($_SESSION['2fa_pending_remember']);
    log_in_user($userId);
    if ($remember) { issue_remember_cookie($userId); }
    audit_log_event('login_success', $userId, '2fa verified');
    redirect('dashboard');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $bucket = '2fa:user:' . $pendingUserId;
    rate_limit_enforce($bucket, RATE_LIMIT_LOGIN_MAX, RATE_LIMIT_LOGIN_WINDOW);
    rate_limit_record_hit($bucket);

    $user = find_user_by_id($pendingUserId);

    if ($useBackup) {
        $code = isset($_POST['backup_code']) ? $_POST['backup_code'] : '';
        if ($user && $user['totp_enabled'] && verify_and_consume_backup_code($user['id'], $code)) {
            audit_log_event('login_success_via_backup_code', $user['id'], 'remaining=' . count_unused_backup_codes($user['id']));
            complete_2fa_login($user['id']);
        }
        audit_log_event('login_backup_code_failed', $pendingUserId, '');
        $errors[] = 'Invalid or already-used backup code.';
    } else {
        $code = isset($_POST['code']) ? $_POST['code'] : '';
        if ($user && $user['totp_enabled'] && totp_verify($user['totp_secret'], $code)) {
            complete_2fa_login($user['id']);
        }
        audit_log_event('login_2fa_failed', $pendingUserId, '');
        $errors[] = 'Invalid or expired code.';
    }
}

render_header('Verify 2FA code');
?>
<h1><?php echo $useBackup ? 'Enter a backup code' : 'Enter your 6-digit code'; ?></h1>
<div class="card" style="max-width:380px">
  <?php foreach ($errors as $err) : ?>
    <div class="flash flash-error"><?php echo e($err); ?></div>
  <?php endforeach; ?>

  <?php if ($useBackup) : ?>
    <form method="post" action="<?php echo e(base_url('2fa-verify')); ?>">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="use_backup" value="1">
      <label for="backup_code">Backup code (format XXXX-XXXX)</label>
      <input type="text" id="backup_code" name="backup_code" required autofocus>
      <button type="submit">Verify</button>
    </form>
    <p><small class="hint"><a href="<?php echo e(base_url('2fa-verify')); ?>">Use my authenticator app instead</a></small></p>
  <?php else : ?>
    <form method="post" action="<?php echo e(base_url('2fa-verify')); ?>">
      <?php echo csrf_field(); ?>
      <label for="code">Authenticator code</label>
      <input type="text" id="code" name="code" pattern="[0-9]{6}" maxlength="6" required autofocus>
      <button type="submit">Verify</button>
    </form>
    <p><small class="hint"><a href="<?php echo e(base_url('2fa-verify')); ?>?backup=1">Use a backup code instead</a></small></p>
  <?php endif; ?>
</div>
<?php render_footer(); ?>
