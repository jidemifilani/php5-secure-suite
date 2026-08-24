<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'refresh_rbac') {
    csrf_require();
    rbac_refresh_session(current_user_id());
    flash_set('success', 'Permissions refreshed from the database into your session.');
    redirect('dashboard');
}

$user = find_user_by_id(current_user_id());
$roles = user_roles($user['id']);
$perms = user_permissions($user['id']);

$newIp = isset($_SESSION['_new_ip_notice']) ? $_SESSION['_new_ip_notice'] : null;
unset($_SESSION['_new_ip_notice']);

render_header('Dashboard');
?>
<h1>Welcome, <?php echo e($user['username']); ?></h1>

<?php if ($newIp) : ?>
  <div class="flash flash-error">Item 5: this is the first time we've seen your account log in from <strong><?php echo e($newIp); ?></strong>. If this wasn't you, change your password and check the <a href="<?php echo e(base_url('admin/audit-log')); ?>">audit log</a> (if you have access) or contact an admin.</div>
<?php endif; ?>

<div class="two-col">
  <div class="card">
    <h2>Account</h2>
    <table>
      <tr><th>Username</th><td><?php echo e($user['username']); ?></td></tr>
      <tr><th>Email</th><td><?php echo e($user['email']); ?></td></tr>
      <tr><th>2FA</th><td><?php echo $user['totp_enabled']
          ? '<span class="pill pill-ok">Enabled</span>'
          : '<span class="pill pill-warn">Disabled</span> - <a href="' . e(base_url('2fa-setup')) . '">enable it</a>'; ?></td></tr>
      <tr><th>Member since</th><td><?php echo e($user['created_at']); ?></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Roles &amp; permissions (RBAC)</h2>
    <p><strong>Roles:</strong>
      <?php echo $roles ? e(implode(', ', $roles)) : '<span class="pill pill-warn">none</span>'; ?>
    </p>
    <p><strong>Permissions:</strong></p>
    <p>
      <?php foreach ($perms as $p): ?>
        <span class="pill pill-ok" style="margin:2px"><?php echo e($p); ?></span>
      <?php endforeach; ?>
      <?php if (!$perms) : ?><span class="pill pill-warn">none granted</span><?php endif; ?>
    </p>
    <form method="post" action="<?php echo e(base_url('dashboard')); ?>">
      <?php echo csrf_field(); ?>
      <input type="hidden" name="action" value="refresh_rbac">
      <button type="submit" class="secondary">Refresh my permissions</button>
    </form>
    <small class="hint">Permissions are cached in your session at login (item 5's "session-based permissions") - use this if an admin just changed your roles.</small>
  </div>
</div>

<div class="card">
  <h2>Quick links</h2>
  <p>
    <a class="btn secondary" href="<?php echo e(base_url('profile')); ?>">Encrypted profile fields</a>
    <a class="btn secondary" href="<?php echo e(base_url('upload')); ?>">My uploads</a>
    <a class="btn secondary" href="<?php echo e(base_url('session-hijack-demo')); ?>">Session hijack demo</a>
    <a class="btn secondary" href="<?php echo e(base_url('waf-demo')); ?>">WAF lite demo</a>
    <a class="btn secondary" href="<?php echo e(base_url('session-inspector')); ?>">Session inspector</a>
    <a class="btn secondary" href="<?php echo e(base_url('security-checklist')); ?>">Security checklist</a>
  </p>
</div>

<div class="card">
  <h2>Vulnerability playgrounds</h2>
  <p>
    <a class="btn secondary" href="<?php echo e(base_url('xss-playground')); ?>">XSS</a>
    <a class="btn secondary" href="<?php echo e(base_url('csrf-playground')); ?>">CSRF</a>
    <a class="btn secondary" href="<?php echo e(base_url('sqli-playground')); ?>">SQL injection</a>
    <a class="btn secondary" href="<?php echo e(base_url('idor-playground')); ?>">IDOR</a>
    <a class="btn secondary" href="<?php echo e(base_url('redirect-playground')); ?>">Open redirect</a>
    <a class="btn secondary" href="<?php echo e(base_url('cmd-playground')); ?>">Command injection</a>
    <a class="btn secondary" href="<?php echo e(base_url('deserialize-playground')); ?>">Deserialization</a>
    <a class="btn secondary" href="<?php echo e(base_url('clickjacking-demo')); ?>">Clickjacking</a>
  </p>
</div>

<?php render_footer(); ?>
