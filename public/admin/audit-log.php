<?php
require_once __DIR__ . '/../../app/bootstrap.php';
require_permission('view_audit_log');
require_admin_ip_allowed();

$verifyResult = null;
if (isset($_GET['verify'])) {
    $verifyResult = audit_verify_chain();
}

$rows = db()->query('SELECT * FROM audit_log ORDER BY id DESC LIMIT 100')->fetchAll();

render_header('Audit log');
?>
<h1>Tamper-evident audit log</h1>
<p class="lead">Each row's <code>row_hash</code> commits to the previous row's hash. Editing or deleting any historical row breaks every hash computed after it, which the verifier below detects.</p>

<div class="card">
  <a class="btn" href="<?php echo e(base_url('admin/audit-log')); ?>?verify=1">Verify chain integrity</a>
  <?php if ($verifyResult) : ?>
    <?php if ($verifyResult['ok']) : ?>
      <div class="flash flash-success" style="margin-top:12px">Chain intact - every row verifies against genesis.</div>
    <?php else : ?>
      <div class="flash flash-error" style="margin-top:12px">TAMPERING DETECTED at row id <?php echo (int) $verifyResult['broken_at']; ?> - hash chain broken.</div>
    <?php endif; ?>
  <?php endif; ?>
</div>

<div class="card">
  <table>
    <tr><th>ID</th><th>Event</th><th>User</th><th>IP</th><th>Details</th><th>When</th></tr>
    <?php foreach ($rows as $row) : ?>
      <tr>
        <td><?php echo (int) $row['id']; ?></td>
        <td><?php echo e($row['event_type']); ?></td>
        <td><?php echo $row['user_id'] !== null ? (int) $row['user_id'] : '-'; ?></td>
        <td><?php echo e($row['ip_address']); ?></td>
        <td><?php echo e($row['details']); ?></td>
        <td><?php echo e($row['created_at']); ?></td>
      </tr>
    <?php endforeach; ?>
  </table>
</div>
<?php render_footer(); ?>
