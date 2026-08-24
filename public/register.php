<?php
require_once __DIR__ . '/../app/bootstrap.php';

if (current_user_id()) { redirect('dashboard'); }

$errors = array();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $email = isset($_POST['email']) ? trim($_POST['email']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $confirm = isset($_POST['confirm']) ? $_POST['confirm'] : '';

    if (!preg_match('/^[A-Za-z0-9_]{3,30}$/', $username)) {
        $errors[] = 'Username must be 3-30 characters: letters, numbers, underscore.';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Enter a valid email address.';
    }
    $pwError = password_policy_error($password, $username);
    if ($pwError) { $errors[] = $pwError; }
    if ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    }

    if (empty($errors) && find_user_by_username($username)) {
        $errors[] = 'That username is taken.';
    }

    if (empty($errors)) {
        try {
            $userId = register_user($username, $email, $password);
            audit_log_event('register', $userId, 'username=' . $username);
            log_in_user($userId);
            flash_set('success', 'Welcome! Your account was created.');
            redirect('dashboard');
        } catch (Exception $ex) {
            $errors[] = 'Could not create account (username/email may already be in use).';
        }
    }
}

render_header('Register');
?>
<h1>Create account</h1>
<div class="card" style="max-width:420px">
  <?php foreach ($errors as $err) : ?>
    <div class="flash flash-error"><?php echo e($err); ?></div>
  <?php endforeach; ?>
  <form method="post" action="<?php echo e(base_url('register')); ?>">
    <?php echo csrf_field(); ?>
    <label for="username">Username</label>
    <input type="text" id="username" name="username" value="<?php echo isset($username) ? e($username) : ''; ?>" required>

    <label for="email">Email</label>
    <input type="email" id="email" name="email" value="<?php echo isset($email) ? e($email) : ''; ?>" required>

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required oninput="p5ssStrength(this.value)">
    <div style="background:var(--panel-2);border-radius:4px;height:6px;margin-top:6px;overflow:hidden">
      <div id="pw-bar" style="height:100%;width:0%;background:var(--err);transition:width .15s"></div>
    </div>
    <small class="hint" id="pw-label">Item 3: server-side rejects the ~100 most common breached passwords too, not just weak ones.</small>

    <label for="confirm">Confirm password</label>
    <input type="password" id="confirm" name="confirm" required>

    <button type="submit">Create account</button>
  </form>
</div>
<script nonce="<?php echo e(csp_nonce()); ?>">
// Item 3: client-side strength meter, mirrors app/password_strength.php's
// heuristic loosely for instant feedback. Server-side check is authoritative.
function p5ssStrength(pw) {
  var score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  var labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];
  var colors = ['#ff5d6c', '#ff5d6c', '#f2b155', '#f2b155', '#35c98f', '#35c98f'];
  var bar = document.getElementById('pw-bar');
  var label = document.getElementById('pw-label');
  bar.style.width = (score / 5 * 100) + '%';
  bar.style.background = colors[score];
  label.textContent = pw.length ? ('Strength: ' + labels[score]) : 'Item 3: server-side rejects the ~100 most common breached passwords too, not just weak ones.';
}
</script>
<?php render_footer(); ?>
