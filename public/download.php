<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
$upload = $id ? upload_find($id) : null;
$userId = current_user_id();

if (!$upload) {
    http_response_code(404);
    exit('404 Not Found');
}

$isOwner = ($upload['user_id'] == $userId);
if (!$isOwner && !user_has_permission($userId, 'manage_uploads')) {
    audit_log_event('upload_download_denied', $userId, 'upload_id=' . $id);
    http_response_code(403);
    exit('403 Forbidden: not your file.');
}

$path = UPLOADS_PATH . DIRECTORY_SEPARATOR . $upload['stored_name'];
if (!is_file($path)) {
    http_response_code(410);
    exit('410 Gone: file missing from storage.');
}

// Item 18: recompute the hash taken at upload time and compare
// before ever streaming a byte - if the stored file was modified out
// from under the app (or corrupted), this refuses to serve it.
if ($upload['sha256'] !== null && !hash_equals($upload['sha256'], hash_file('sha256', $path))) {
    audit_log_event('upload_integrity_mismatch', $userId, 'upload_id=' . $id);
    http_response_code(409);
    exit('409 Conflict: this file failed an integrity check and was withheld rather than served.');
}

audit_log_event('upload_downloaded', $userId, 'upload_id=' . $id);

header('Content-Type: ' . $upload['mime_type']);
header('Content-Length: ' . filesize($path));
header('Content-Disposition: attachment; filename="' . str_replace('"', '', $upload['original_name']) . '"');
header('X-Content-Type-Options: nosniff');
readfile($path);
exit;
