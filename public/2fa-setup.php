<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

$user = find_user_by_id(current_user_id());
$errors = array();
$newBackupCodes = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $action = isset($_POST['action']) ? $_POST['action'] : '';

    if ($action === 'enable') {
        $pending = isset($_SESSION['pending_totp_secret']) ? $_SESSION['pending_totp_secret'] : null;
        $code = isset($_POST['code']) ? $_POST['code'] : '';
        if (!$pending || !totp_verify($pending, $code)) {
            $errors[] = 'That code did not match. Scan/enter the secret again and try the current code.';
        } else {
            $stmt = db()->prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?');
            $stmt->execute(array($pending, $user['id']));
            unset($_SESSION['pending_totp_secret']);
            $newBackupCodes = generate_backup_codes($user['id']);
            audit_log_event('totp_enabled', $user['id'], '');
            $user = find_user_by_id(current_user_id());
        }
    } elseif ($action === 'disable') {
        $password = isset($_POST['password']) ? $_POST['password'] : '';
        if (!password_verify($password, $user['password_hash'])) {
            $errors[] = 'Incorrect password.';
        } else {
            $stmt = db()->prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?');
            $stmt->execute(array($user['id']));
            $del = db()->prepare('DELETE FROM totp_backup_codes WHERE user_id = ?');
            $del->execute(array($user['id']));
            audit_log_event('totp_disabled', $user['id'], '');
            flash_set('success', 'Two-factor authentication disabled.');
            redirect('dashboard');
        }
    } elseif ($action === 'regenerate_backup_codes') {
        $password = isset($_POST['password']) ? $_POST['password'] : '';
        if (!password_verify($password, $user['password_hash'])) {
            $errors[] = 'Incorrect password.';
        } else {
            $newBackupCodes = generate_backup_codes($user['id']);
            audit_log_event('totp_backup_codes_regenerated', $user['id'], '');
        }
    }
    $user = find_user_by_id(current_user_id());
}

render_header('Two-Factor Authentication');
?>
<h1>Two-factor authentication (TOTP)</h1>

<?php foreach ($errors as $err) : ?>
  <div class="flash flash-error"><?php echo e($err); ?></div>
<?php endforeach; ?>

<?php if ($newBackupCodes) : ?>
  <div class="card" style="max-width:480px;border-color:var(--ok)">
    <p><strong>Backup codes - each works once, shown only this one time. Save them somewhere safe:</strong></p>
    <p>
      <?php foreach ($newBackupCodes as $c) : ?>
        <code class="mono" style="display:block;margin-bottom:4px"><?php echo e($c); ?></code>
      <?php endforeach; ?>
    </p>
  </div>
<?php endif; ?>

<?php if ($user['totp_enabled']) : ?>
  <div class="card" style="max-width:480px">
    <p><span class="pill pill-ok">Enabled</span> Two-factor authentication is protecting this account. Unused backup codes: <strong><?php echo (int) count_unused_backup_codes($user['id']); ?></strong></p>
    <form method="post" action="<?php echo e(base_url('2fa-setup')); ?>" style="display:inline-block;margin-right:12px">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="regenerate_backup_codes">
      <label for="password_regen">Confirm password to regenerate backup codes (invalidates old ones)</label>
      <input type="password" id="password_regen" name="password" required>
      <button type="submit" class="secondary">Regenerate backup codes</button>
    </form>
    <form method="post" action="<?php echo e(base_url('2fa-setup')); ?>">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="disable">
      <label for="password">Confirm your password to disable 2FA</label>
      <input type="password" id="password" name="password" required>
      <button type="submit" class="danger">Disable 2FA</button>
    </form>
  </div>
<?php else :
    if (empty($_SESSION['pending_totp_secret'])) {
        $_SESSION['pending_totp_secret'] = totp_generate_secret();
    }
    $secret = $_SESSION['pending_totp_secret'];
    $uri = totp_provisioning_uri($secret, $user['username']);
?>
  <div class="card" style="max-width:520px">
    <p>Add this secret to any TOTP app (Google Authenticator, Authy, etc.), or enter it manually. No external QR service is used - this is a hand-rolled RFC 6238 implementation.</p>
    <p><strong>Secret:</strong><br><code class="mono"><?php echo e($secret); ?></code></p>
    <p><strong>otpauth URI:</strong><br><code class="mono" style="word-break:break-all"><?php echo e($uri); ?></code></p>
    <form method="post" action="<?php echo e(base_url('2fa-setup')); ?>">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="enable">
      <label for="code">Enter the current 6-digit code to activate</label>
      <input type="text" id="code" name="code" pattern="[0-9]{6}" maxlength="6" required autofocus>
      <button type="submit">Activate 2FA</button>
    </form>
  </div>
<?php endif; ?>

<?php render_footer(); ?>
