<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_permission('view_encrypted_data');

$userId = current_user_id();
$errors = array();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $nin = isset($_POST['nin']) ? trim($_POST['nin']) : '';
    $bvn = isset($_POST['bvn']) ? trim($_POST['bvn']) : '';

    if ($nin !== '' && !preg_match('/^\d{11}$/', $nin)) {
        $errors[] = 'NIN must be exactly 11 digits.';
    }
    if ($bvn !== '' && !preg_match('/^\d{11}$/', $bvn)) {
        $errors[] = 'BVN must be exactly 11 digits.';
    }

    if (empty($errors)) {
        if ($nin !== '') { secure_field_set($userId, 'nin', $nin); }
        if ($bvn !== '') { secure_field_set($userId, 'bvn', $bvn); }
        audit_log_event('secure_profile_updated', $userId, '');
        flash_set('success', 'Encrypted and saved (AES-256-CBC + HMAC-SHA256).');
        redirect('profile');
    }
}

$tamperDetected = false;
try {
    $fields = secure_fields_for_user($userId);
} catch (Exception $ex) {
    // MAC verification failed - the ciphertext (or its stored IV/MAC)
    // was altered after the fact. Fail closed: never fall back to
    // showing partially-decrypted or unverified data.
    audit_log_event('secure_profile_tamper_detected', $userId, $ex->getMessage());
    $tamperDetected = true;
    $fields = array();
}
$keyVersion = get_active_key_version();
$canRotate = user_has_permission($userId, 'manage_encryption_keys');

render_header('Profile');
?>
<h1>Encrypted profile fields</h1>
<p class="lead">Demo sensitive fields (NIN/BVN) stored with AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC). The key never touches the database - it lives only in <code>storage/keys/</code>. Current key version: <span class="pill pill-ok">v<?php echo (int) $keyVersion; ?></span></p>

<?php foreach ($errors as $err) : ?>
  <div class="flash flash-error"><?php echo e($err); ?></div>
<?php endforeach; ?>

<div class="two-col">
  <div class="card">
    <h2>Set values</h2>
    <form method="post" action="<?php echo e(base_url('profile')); ?>">
      <?php echo csrf_field(); ?>
      <label for="nin">NIN (11 digits)</label>
      <input type="text" id="nin" name="nin" pattern="\d{11}" maxlength="11" placeholder="leave blank to keep unchanged">
      <label for="bvn">BVN (11 digits)</label>
      <input type="text" id="bvn" name="bvn" pattern="\d{11}" maxlength="11" placeholder="leave blank to keep unchanged">
      <button type="submit">Encrypt &amp; save</button>
    </form>
  </div>

  <div class="card">
    <h2>Decrypted (server-side, on demand)</h2>
    <?php if ($tamperDetected) : ?>
      <div class="flash flash-error">Integrity check failed: stored ciphertext/MAC does not match. Data is being treated as tampered and withheld rather than shown. (Logged to the audit trail.)</div>
    <?php endif; ?>
    <table>
      <tr><th>Field</th><th>Value</th></tr>
      <tr><td>NIN</td><td><?php echo isset($fields['nin']) ? '<code class="mono">' . e($fields['nin']) . '</code>' : '<em>not set</em>'; ?></td></tr>
      <tr><td>BVN</td><td><?php echo isset($fields['bvn']) ? '<code class="mono">' . e($fields['bvn']) . '</code>' : '<em>not set</em>'; ?></td></tr>
    </table>
    <?php if ($canRotate) : ?>
      <p><small class="hint"><a href="<?php echo e(base_url('admin/encryption')); ?>">Manage encryption keys / rotate &rarr;</a></small></p>
    <?php endif; ?>
  </div>
</div>

<?php render_footer(); ?>
