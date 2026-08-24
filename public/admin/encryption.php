<?php
require_once __DIR__ . '/../../app/bootstrap.php';
require_permission('manage_encryption_keys');
require_admin_ip_allowed();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'rotate') {
    csrf_require();
    $newVersion = rotate_encryption_key();
    flash_set('success', 'Rotated to key v' . $newVersion . '. All existing encrypted rows were re-encrypted; the old key material was destroyed.');
    redirect('admin/encryption');
}

$keys = db()->query('SELECT * FROM encryption_keys ORDER BY key_version DESC')->fetchAll();
$activeVersion = get_active_key_version();
$fieldCount = (int) db()->query('SELECT COUNT(*) FROM secure_profile_data')->fetchColumn();
$apiKeyCount = (int) db()->query('SELECT COUNT(*) FROM api_keys')->fetchColumn();

render_header('Encryption keys');
?>
<h1>Encrypted data-at-rest (AES-256-CBC + HMAC-SHA256)</h1>
<p class="lead">Key material lives only in <code>storage/keys/key_&lt;version&gt;.bin</code>, outside the web root and never in the database. Rotating re-encrypts every row that used an older key, then deletes that key's file - old ciphertexts stop being decryptable with anything that still exists.</p>

<div class="card">
  <p>Currently protecting <strong><?php echo $fieldCount; ?></strong> encrypted profile field(s) and <strong><?php echo $apiKeyCount; ?></strong> API key secret(s).</p>
  <form method="post" action="<?php echo e(base_url('admin/encryption')); ?>" onsubmit="return confirm('Rotate the encryption key now? This re-encrypts all data and destroys the old key.');">
    <?php echo csrf_field(); ?>
    <input type="hidden" name="action" value="rotate">
    <button type="submit">Rotate key now (currently v<?php echo (int) $activeVersion; ?>)</button>
  </form>
</div>

<div class="card">
  <table>
    <tr><th>Version</th><th>Status</th><th>Created</th><th>Retired</th></tr>
    <?php foreach ($keys as $k) : ?>
      <tr>
        <td>v<?php echo (int) $k['key_version']; ?></td>
        <td><?php echo $k['is_active'] ? '<span class="pill pill-ok">active</span>' : '<span class="pill pill-warn">retired</span>'; ?></td>
        <td><?php echo e($k['created_at']); ?></td>
        <td><?php echo $k['retired_at'] ? e($k['retired_at']) : '-'; ?></td>
      </tr>
    <?php endforeach; ?>
  </table>
</div>
<?php render_footer(); ?>
