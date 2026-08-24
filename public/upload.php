<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_permission('upload_files');

$errors = array();
$userId = current_user_id();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    if (!isset($_FILES['file'])) {
        $errors[] = 'No file received.';
    } else {
        $check = upload_validate($_FILES['file']);
        if (!$check['ok']) {
            $errors[] = $check['error'];
            audit_log_event('upload_rejected', $userId, $check['error']);
        } else {
            $id = upload_store($_FILES['file'], $check['ext'], $check['mime'], $userId);
            audit_log_event('upload_stored', $userId, 'upload_id=' . $id);
            flash_set('success', 'File uploaded and stored outside the web root.');
            redirect('upload');
        }
    }
}

$allowedExt = unserialize(UPLOAD_ALLOWED_EXT);
$myUploads = uploads_for_user($userId);

render_header('Uploads');
?>
<h1>Secure file upload</h1>
<p class="lead">Extension whitelist + real MIME sniffing via <code>finfo</code> (the client-sent MIME type is never trusted). Files are stored in <code>storage/uploads/</code>, a sibling of <code>public/</code> - outside the web root, unreachable by direct URL under any routing.</p>

<div class="card" style="max-width:480px">
  <?php foreach ($errors as $err) : ?>
    <div class="flash flash-error"><?php echo e($err); ?></div>
  <?php endforeach; ?>
  <form method="post" action="<?php echo e(base_url('upload')); ?>" enctype="multipart/form-data">
    <?php echo csrf_field(); ?>
    <label for="file">File (allowed: <?php echo e(implode(', ', $allowedExt)); ?>, max <?php echo (int) (UPLOAD_MAX_BYTES / 1024 / 1024); ?>MB)</label>
    <input type="file" id="file" name="file" required>
    <button type="submit">Upload</button>
  </form>
</div>

<div class="card">
  <h2>Your uploads</h2>
  <?php if (!$myUploads) : ?>
    <p class="lead">No uploads yet.</p>
  <?php else : ?>
    <table>
      <tr><th>File</th><th>Type</th><th>Size</th><th>Uploaded</th><th></th></tr>
      <?php foreach ($myUploads as $u) : ?>
        <tr>
          <td><?php echo e($u['original_name']); ?></td>
          <td><?php echo e($u['mime_type']); ?></td>
          <td><?php echo number_format($u['size_bytes'] / 1024, 1); ?> KB</td>
          <td><?php echo e($u['created_at']); ?></td>
          <td><a href="<?php echo e(base_url('download')); ?>?id=<?php echo (int) $u['id']; ?>">Download</a></td>
        </tr>
      <?php endforeach; ?>
    </table>
  <?php endif; ?>
</div>

<?php render_footer(); ?>
