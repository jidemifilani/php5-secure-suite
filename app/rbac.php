<?php
// Item 5: RBAC with session-based permissions. Roles/permissions are
// resolved from the DB once, at login, and cached into $_SESSION -
// every require_permission() check for the rest of that session reads
// the cache, not the DB. That means a role change made by an admin
// takes effect for the affected user on their NEXT login, not
// immediately - the standard tradeoff of session-based RBAC (cheap,
// consistent-for-the-session checks) vs. always-live DB checks.
// dashboard.php exposes a manual "refresh my permissions" action for
// anyone who wants the new grants without logging out first.

function user_roles_from_db($userId) {
    $stmt = db()->prepare(
        'SELECT r.name FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = ?'
    );
    $stmt->execute(array($userId));
    return $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
}

function user_permissions_from_db($userId) {
    $stmt = db()->prepare(
        'SELECT DISTINCT p.name FROM permissions p
         JOIN role_permissions rp ON rp.permission_id = p.id
         JOIN user_roles ur ON ur.role_id = rp.role_id
         WHERE ur.user_id = ?'
    );
    $stmt->execute(array($userId));
    return $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
}

// Populates the session RBAC cache. Call at login, and any time a
// user's own session should pick up fresh grants without re-login.
function rbac_refresh_session($userId) {
    $_SESSION['_rbac_roles'] = user_roles_from_db($userId);
    $_SESSION['_rbac_perms'] = user_permissions_from_db($userId);
}

function user_roles($userId) {
    if ($userId == current_user_id() && isset($_SESSION['_rbac_roles'])) {
        return $_SESSION['_rbac_roles'];
    }
    return user_roles_from_db($userId);
}

function user_permissions($userId) {
    if ($userId == current_user_id() && isset($_SESSION['_rbac_perms'])) {
        return $_SESSION['_rbac_perms'];
    }
    return user_permissions_from_db($userId);
}

function user_has_permission($userId, $permissionName) {
    return in_array($permissionName, user_permissions($userId), true);
}

function require_permission($permissionName) {
    require_login();
    $userId = current_user_id();
    if (!user_has_permission($userId, $permissionName)) {
        audit_log_event('rbac_denied', $userId, 'missing permission: ' . $permissionName);
        http_response_code(403);
        exit('403 Forbidden: your account lacks the "' . e($permissionName) . '" permission. If this was just granted, it will take effect on your next login (or use "refresh my permissions" on the dashboard).');
    }
}

function assign_role($userId, $roleId) {
    $stmt = db()->prepare('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
    $stmt->execute(array($userId, $roleId));
}

function remove_role($userId, $roleId) {
    $stmt = db()->prepare('DELETE FROM user_roles WHERE user_id = ? AND role_id = ?');
    $stmt->execute(array($userId, $roleId));
}

function all_roles() {
    return db()->query('SELECT id, name, description FROM roles ORDER BY name')->fetchAll();
}

function all_users_with_roles() {
    $users = db()->query('SELECT id, username, email, is_active, created_at FROM users ORDER BY username')->fetchAll();
    foreach ($users as &$u) {
        $u['roles'] = user_roles_from_db($u['id']);
    }
    return $users;
}
