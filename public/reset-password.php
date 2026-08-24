<?php
require_once __DIR__ . '/../app/bootstrap.php';

$token = isset($_GET['token']) ? $_GET['token'] : (isset($_POST['token']) ? $_POST['token'] : '');
$reset = $token ? verify_password_reset_token($token) : null;
$errors = array();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $reset) {
    csrf_require();
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $confirm = isset($_POST['confirm']) ? $_POST['confirm'] : '';

    $user = find_user_by_id($reset['user_id']);
    $pwError = password_policy_error($password, $user ? $user['username'] : null);
    if ($pwError) {
        $errors[] = $pwError;
    } elseif ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    } else {
        try {
            consume_password_reset_token($reset['id'], $reset['user_id'], $password);
            audit_log_event('password_reset_completed', $reset['user_id'], '');
            flash_set('success', 'Password updated. You can log in now.');
            redirect('login');
        } catch (Exception $ex) {
            $errors[] = $ex->getMessage();
            $reset = null; // token already consumed, e.g. a double-submit
        }
    }
}

render_header('Reset password');
?>
<h1>Reset password</h1>
<div class="card" style="max-width:420px">
  <?php foreach ($errors as $err) : ?>
    <div class="flash flash-error"><?php echo e($err); ?></div>
  <?php endforeach; ?>

  <?php if (!$reset) : ?>
    <div class="flash flash-error">This reset link is invalid, expired, or already used.</div>
    <p><a href="<?php echo e(base_url('forgot-password')); ?>">Request a new one</a></p>
  <?php else : ?>
    <form method="post" action="<?php echo e(base_url('reset-password')); ?>">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="token" value="<?php echo e($token); ?>">
      <label for="password">New password</label>
      <input type="password" id="password" name="password" required autofocus>
      <label for="confirm">Confirm new password</label>
      <input type="password" id="confirm" name="confirm" required>
      <button type="submit">Set new password</button>
    </form>
  <?php endif; ?>
</div>
<?php render_footer(); ?>
