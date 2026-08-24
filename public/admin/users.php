<?php
require_once __DIR__ . '/../../app/bootstrap.php';
require_permission('manage_users');
require_admin_ip_allowed();

$errors = array();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    require_permission('manage_roles');
    $userId = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
    $roleId = isset($_POST['role_id']) ? (int) $_POST['role_id'] : 0;
    $action = isset($_POST['action']) ? $_POST['action'] : '';

    if ($action === 'assign') {
        assign_role($userId, $roleId);
        audit_log_event('role_assigned', current_user_id(), 'user_id=' . $userId . ' role_id=' . $roleId);
    } elseif ($action === 'remove') {
        remove_role($userId, $roleId);
        audit_log_event('role_removed', current_user_id(), 'user_id=' . $userId . ' role_id=' . $roleId);
    }
    flash_set('success', 'Updated. Takes effect for that user on their next login (session-based RBAC).');
    redirect('admin/users');
}

$users = all_users_with_roles();
$roles = all_roles();

render_header('Manage users');
?>
<h1>Users &amp; roles</h1>
<div class="card">
  <table>
    <tr><th>User</th><th>Email</th><th>Roles</th><th>Assign</th></tr>
    <?php foreach ($users as $u) : ?>
      <tr>
        <td><?php echo e($u['username']); ?></td>
        <td><?php echo e($u['email']); ?></td>
        <td>
          <?php foreach ($u['roles'] as $rname) : ?>
            <?php
              $rid = null;
              foreach ($roles as $r) { if ($r['name'] === $rname) { $rid = $r['id']; break; } }
            ?>
            <form method="post" action="<?php echo e(base_url('admin/users')); ?>" style="display:inline">
              <?php echo csrf_field(); ?>
              <input type="hidden" name="action" value="remove">
              <input type="hidden" name="user_id" value="<?php echo (int) $u['id']; ?>">
              <input type="hidden" name="role_id" value="<?php echo (int) $rid; ?>">
              <button type="submit" class="pill pill-ok" style="border:none;cursor:pointer" title="Remove role"><?php echo e($rname); ?> &times;</button>
            </form>
          <?php endforeach; ?>
        </td>
        <td>
          <form method="post" action="<?php echo e(base_url('admin/users')); ?>" style="display:flex;gap:6px">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="action" value="assign">
            <input type="hidden" name="user_id" value="<?php echo (int) $u['id']; ?>">
            <select name="role_id">
              <?php foreach ($roles as $r) : ?>
                <option value="<?php echo (int) $r['id']; ?>"><?php echo e($r['name']); ?></option>
              <?php endforeach; ?>
            </select>
            <button type="submit" class="secondary">Assign</button>
          </form>
        </td>
      </tr>
    <?php endforeach; ?>
  </table>
</div>
<?php render_footer(); ?>
