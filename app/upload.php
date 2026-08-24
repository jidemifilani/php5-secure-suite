<?php
// Item 6: secure file upload.
// - extension whitelist (not blacklist)
// - real MIME sniffing via fileinfo, never trust $_FILES[...]['type']
//   (that value is client-supplied and trivially spoofable)
// - stored under a random filename, outside the web root entirely
//   (storage/uploads/, a sibling of public/, not inside it) so even
//   a misconfigured server can't ever execute an uploaded file

function upload_validate($file) {
    if (!isset($file['error']) || is_array($file['error'])) {
        return array('ok' => false, 'error' => 'Malformed upload.');
    }
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return array('ok' => false, 'error' => 'Upload error code ' . $file['error']);
    }
    if ($file['size'] > UPLOAD_MAX_BYTES) {
        return array('ok' => false, 'error' => 'File exceeds the ' . (UPLOAD_MAX_BYTES / 1024 / 1024) . 'MB limit.');
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        return array('ok' => false, 'error' => 'Invalid upload (not a real HTTP upload).');
    }

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedExt = unserialize(UPLOAD_ALLOWED_EXT);
    if (!in_array($ext, $allowedExt, true)) {
        return array('ok' => false, 'error' => 'Extension .' . e($ext) . ' is not on the whitelist.');
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $realMime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    $allowedMime = unserialize(UPLOAD_ALLOWED_MIME);
    if (!in_array($realMime, $allowedMime, true)) {
        return array('ok' => false, 'error' => 'Detected content type "' . e($realMime) . '" is not on the whitelist (extension can lie; this check can\'t).');
    }

    return array('ok' => true, 'ext' => $ext, 'mime' => $realMime);
}

function upload_store($file, $ext, $mime, $userId) {
    if (!is_dir(UPLOADS_PATH)) { mkdir(UPLOADS_PATH, 0700, true); }
    $storedName = random_token_hex(24) . '.' . $ext;
    $dest = UPLOADS_PATH . DIRECTORY_SEPARATOR . $storedName;

    if (!move_uploaded_file($file['tmp_name'], $dest)) {
        throw new Exception('Failed to move uploaded file into storage.');
    }

    // Item 18: integrity hash computed once, right after the file
    // lands in storage - download.php recomputes and compares this
    // on every download, so any modification to the file on disk
    // (or a corrupted transfer) is caught before it's ever served.
    $sha256 = hash_file('sha256', $dest);

    $stmt = db()->prepare(
        'INSERT INTO uploads (user_id, original_name, stored_name, mime_type, size_bytes, sha256) VALUES (?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute(array($userId, $file['name'], $storedName, $mime, $file['size'], $sha256));
    return (int) db()->lastInsertId();
}

function upload_find($id) {
    $stmt = db()->prepare('SELECT * FROM uploads WHERE id = ?');
    $stmt->execute(array($id));
    return $stmt->fetch();
}

function uploads_for_user($userId) {
    $stmt = db()->prepare('SELECT * FROM uploads WHERE user_id = ? ORDER BY created_at DESC');
    $stmt->execute(array($userId));
    return $stmt->fetchAll();
}
