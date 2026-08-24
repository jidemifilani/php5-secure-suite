<?php
require_once __DIR__ . '/../../app/bootstrap.php';
require_permission('manage_uploads');
require_admin_ip_allowed();

$rows = db()->query(
    'SELECT u.*, us.username FROM uploads u JOIN users us ON us.id = u.user_id ORDER BY u.created_at DESC'
)->fetchAll();

render_header('All uploads');
?>
<h1>All uploads</h1>
<div class="card">
  <table>
    <tr><th>Owner</th><th>File</th><th>Type</th><th>Size</th><th>Uploaded</th><th></th></tr>
    <?php foreach ($rows as $u) : ?>
      <tr>
        <td><?php echo e($u['username']); ?></td>
        <td><?php echo e($u['original_name']); ?></td>
        <td><?php echo e($u['mime_type']); ?></td>
        <td><?php echo number_format($u['size_bytes'] / 1024, 1); ?> KB</td>
        <td><?php echo e($u['created_at']); ?></td>
        <td><a href="<?php echo e(base_url('download')); ?>?id=<?php echo (int) $u['id']; ?>">Download</a></td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$rows) : ?><tr><td colspan="6">No uploads yet.</td></tr><?php endif; ?>
  </table>
</div>
<?php render_footer(); ?>
