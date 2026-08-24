<?php
require_once __DIR__ . '/../app/bootstrap.php';

$url = isset($_GET['url']) ? $_GET['url'] : '/dashboard';
audit_log_event('redirect_demo_vulnerable', current_user_id(), 'url=' . $url);

// VULNERABLE ON PURPOSE: whatever was in the query string, verbatim.
header('Location: ' . $url);
exit;
