<?php
require_once __DIR__ . '/../../app/bootstrap.php';
require_permission('manage_api_keys');
require_admin_ip_allowed();

$newKey = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $action = isset($_POST['action']) ? $_POST['action'] : '';

    if ($action === 'create') {
        $label = isset($_POST['label']) ? trim($_POST['label']) : '';
        if ($label !== '') {
            $newKey = api_create_key($label);
            audit_log_event('api_key_created', current_user_id(), 'label=' . $label . ' api_key=' . $newKey['api_key']);
        }
    } elseif ($action === 'revoke') {
        $id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
        $stmt = db()->prepare('UPDATE api_keys SET is_active = 0 WHERE id = ?');
        $stmt->execute(array($id));
        audit_log_event('api_key_revoked', current_user_id(), 'id=' . $id);
        flash_set('success', 'API key revoked.');
        redirect('admin/api-keys');
    }
}

$keys = db()->query('SELECT * FROM api_keys ORDER BY created_at DESC')->fetchAll();

render_header('API keys');
?>
<h1>Secure API gateway credentials</h1>
<p class="lead">Requests to <code><?php echo e(base_url('api/ping')); ?></code> / <code><?php echo e(base_url('api/echo')); ?></code> must include <code>X-Api-Key</code>, <code>X-Timestamp</code>, <code>X-Nonce</code> and <code>X-Signature</code> headers (HMAC-SHA256 over method+path+timestamp+nonce+body). Timestamps outside a 5-minute window and reused nonces are both rejected.</p>

<?php if ($newKey) : ?>
  <div class="card" style="border-color:var(--ok)">
    <p><strong>New key created - the secret is shown once, right now, and never again:</strong></p>
    <p>API key: <code class="mono"><?php echo e($newKey['api_key']); ?></code></p>
    <p>Secret: <code class="mono"><?php echo e($newKey['secret']); ?></code></p>
  </div>
<?php endif; ?>

<div class="card" style="max-width:420px">
  <form method="post" action="<?php echo e(base_url('admin/api-keys')); ?>">
    <?php echo csrf_field(); ?>
    <input type="hidden" name="action" value="create">
    <label for="label">Label (what/who is this for)</label>
    <input type="text" id="label" name="label" required>
    <button type="submit">Create API key</button>
  </form>
</div>

<div class="card">
  <table>
    <tr><th>Label</th><th>API key</th><th>Status</th><th>Created</th><th></th></tr>
    <?php foreach ($keys as $k) : ?>
      <tr>
        <td><?php echo e($k['label']); ?></td>
        <td><code class="mono"><?php echo e($k['api_key']); ?></code></td>
        <td><?php echo $k['is_active'] ? '<span class="pill pill-ok">active</span>' : '<span class="pill pill-err">revoked</span>'; ?></td>
        <td><?php echo e($k['created_at']); ?></td>
        <td>
          <?php if ($k['is_active']) : ?>
          <form method="post" action="<?php echo e(base_url('admin/api-keys')); ?>">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="action" value="revoke">
            <input type="hidden" name="id" value="<?php echo (int) $k['id']; ?>">
            <button type="submit" class="danger">Revoke</button>
          </form>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
  </table>
</div>
<?php render_footer(); ?>
