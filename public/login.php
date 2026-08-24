<?php
require_once __DIR__ . '/../app/bootstrap.php';

if (current_user_id()) { redirect('dashboard'); }

$errors = array();

// Item 6: math CAPTCHA gate, tracked per-browser-session (separate
// from the DB-backed lockout/rate-limit counters), shown only after
// repeated failures in this session.
$failCount = isset($_SESSION['login_fail_count']) ? $_SESSION['login_fail_count'] : 0;
$captchaRequired = $failCount >= CAPTCHA_TRIGGER_AFTER;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $remember = isset($_POST['remember']) && $_POST['remember'] === '1';

    if ($captchaRequired) {
        $answer = isset($_POST['captcha_answer']) ? trim($_POST['captcha_answer']) : '';
        $expected = isset($_SESSION['captcha_expected']) ? $_SESSION['captcha_expected'] : null;
        if ($expected === null || $answer !== (string) $expected) {
            $errors[] = 'Incorrect CAPTCHA answer.';
        }
    }

    if (empty($errors)) {
        // Item 1: account lockout - checked before spending a rate-limit
        // slot or a password_verify() call on an account already locked.
        $lockUser = find_user_by_username($username);
        $lockRemaining = $lockUser ? account_lock_remaining_seconds($lockUser['id']) : null;

        if ($lockRemaining !== null) {
            audit_log_event('login_blocked_locked', $lockUser['id'], '');
            $errors[] = 'This account is temporarily locked after repeated failed attempts. Try again in ' . ceil($lockRemaining / 60) . ' minute(s).';
        } else {
            // Item 10: rate limiter, both per-IP and per-account.
            $ipBucket = 'login:ip:' . client_ip();
            $userBucket = 'login:user:' . strtolower($username);
            rate_limit_enforce($ipBucket, RATE_LIMIT_LOGIN_MAX, RATE_LIMIT_LOGIN_WINDOW);
            rate_limit_enforce($userBucket, RATE_LIMIT_LOGIN_MAX, RATE_LIMIT_LOGIN_WINDOW);
            rate_limit_record_hit($ipBucket);
            rate_limit_record_hit($userBucket);

            $user = verify_credentials($username, $password);
            if (!$user) {
                if ($lockUser) { register_failed_login($lockUser['id']); }
                $_SESSION['login_fail_count'] = $failCount + 1;
                audit_log_event('login_failed', null, 'username=' . $username);
                $errors[] = 'Invalid username or password.';
            } else {
                register_successful_login($user['id']);
                unset($_SESSION['login_fail_count']);

                if ($user['totp_enabled']) {
                    $_SESSION['2fa_pending_user'] = $user['id'];
                    $_SESSION['2fa_pending_remember'] = $remember;
                    audit_log_event('login_password_ok_2fa_pending', $user['id'], '');
                    redirect('2fa-verify');
                }
                log_in_user($user['id']);
                if ($remember) { issue_remember_cookie($user['id']); }
                audit_log_event('login_success', $user['id'], '');
                redirect('dashboard');
            }
        }
    }
}

// (Re-)read after a possible increment above, and generate a fresh
// CAPTCHA challenge whenever one is needed for the form about to render.
$failCount = isset($_SESSION['login_fail_count']) ? $_SESSION['login_fail_count'] : 0;
$captchaRequired = $failCount >= CAPTCHA_TRIGGER_AFTER;
if ($captchaRequired) {
    $captchaA = mt_rand(1, 9);
    $captchaB = mt_rand(1, 9);
    $_SESSION['captcha_expected'] = $captchaA + $captchaB;
}

render_header('Log in');
?>
<h1>Log in</h1>
<div class="card" style="max-width:420px">
  <?php foreach ($errors as $err) : ?>
    <div class="flash flash-error"><?php echo e($err); ?></div>
  <?php endforeach; ?>
  <form method="post" action="<?php echo e(base_url('login')); ?>">
    <?php echo csrf_field(); ?>
    <label for="username">Username</label>
    <input type="text" id="username" name="username" required autofocus>

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>

    <label style="display:flex;align-items:center;gap:8px;margin-top:12px">
      <input type="checkbox" name="remember" value="1" style="width:auto"> Remember me for <?php echo (int) REMEMBER_ME_DAYS; ?> days
    </label>

    <?php if ($captchaRequired) : ?>
      <label for="captcha_answer">Repeated failures detected - what is <?php echo (int) $captchaA; ?> + <?php echo (int) $captchaB; ?>?</label>
      <input type="text" id="captcha_answer" name="captcha_answer" required>
    <?php endif; ?>

    <button type="submit">Log in</button>
  </form>
  <p><small class="hint">
    <a href="<?php echo e(base_url('forgot-password')); ?>">Forgot password?</a>
    &middot; No account? <a href="<?php echo e(base_url('register')); ?>">Register</a>
  </small></p>
  <p><small class="hint">Rate limited: <?php echo (int) RATE_LIMIT_LOGIN_MAX; ?> attempts per <?php echo (int) (RATE_LIMIT_LOGIN_WINDOW / 60); ?> min, per IP and per username. Accounts lock for <?php echo (int) LOCKOUT_DURATION_MINUTES; ?> min after <?php echo (int) LOCKOUT_MAX_ATTEMPTS; ?> failed attempts.</small></p>
</div>
<?php render_footer(); ?>
