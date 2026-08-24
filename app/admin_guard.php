<?php
// Item 17: IP allowlist for /admin - a network-layer check on top of
// RBAC, not a replacement for it. Every admin/*.php page still calls
// require_permission() first; this is an additional gate. Disabled
// by default (empty ADMIN_IP_ALLOWLIST in app/config.php), so it
// ships non-breaking.

function require_admin_ip_allowed() {
    $list = unserialize(ADMIN_IP_ALLOWLIST);
    if (empty($list)) { return; }
    if (!in_array(client_ip(), $list, true)) {
        audit_log_event('admin_ip_blocked', current_user_id(), client_ip());
        http_response_code(403);
        exit('403 Forbidden: your IP address is not on the admin allowlist.');
    }
}
