<?php
require_once __DIR__ . '/../../app/bootstrap.php';
require_permission('view_admin_panel');
require_admin_ip_allowed();

render_header('Admin');
?>
<h1>Admin panel</h1>
<p class="lead">Access to each section below is enforced by RBAC (item 5) - <code>require_permission()</code> re-checks the DB on every request.</p>
<div class="grid">
  <div class="card module-card">
    <h3>Users &amp; roles</h3>
    <p>Assign/remove roles per account.</p>
    <a href="<?php echo e(base_url('admin/users')); ?>">Open &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>Audit log</h3>
    <p>Tamper-evident hash-chained event log, with an integrity verifier.</p>
    <a href="<?php echo e(base_url('admin/audit-log')); ?>">Open &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>WAF log</h3>
    <p>Requests blocked by the request filter.</p>
    <a href="<?php echo e(base_url('admin/waf-log')); ?>">Open &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>Uploads</h3>
    <p>Every user's uploaded files.</p>
    <a href="<?php echo e(base_url('admin/uploads')); ?>">Open &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>Encryption keys</h3>
    <p>Rotate the AES-256 data-at-rest key.</p>
    <a href="<?php echo e(base_url('admin/encryption')); ?>">Open &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>API keys</h3>
    <p>Issue/revoke HMAC credentials for the API gateway.</p>
    <a href="<?php echo e(base_url('admin/api-keys')); ?>">Open &rarr;</a>
  </div>
</div>
<?php render_footer(); ?>
