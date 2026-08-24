<?php
// Item 13: tamper-evident audit log. Each row's hash commits to the
// previous row's hash (like a mini blockchain) - editing or deleting
// any historical row breaks every row_hash computed after it, which
// audit_verify_chain() below can detect.

define('AUDIT_GENESIS_HASH', str_repeat('0', 64));

function audit_log_event($eventType, $userId, $details) {
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE');
        $stmt->execute();
        $prevHash = $stmt->fetchColumn();
        if ($prevHash === false) { $prevHash = AUDIT_GENESIS_HASH; }

        $createdAt = date('Y-m-d H:i:s');
        $ip = client_ip();
        $rowHash = hash('sha256', implode('|', array(
            $prevHash, $eventType, (string) $userId, $ip, (string) $details, $createdAt,
        )));

        $ins = $pdo->prepare(
            'INSERT INTO audit_log (event_type, user_id, ip_address, details, prev_hash, row_hash, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $ins->execute(array($eventType, $userId, $ip, $details, $prevHash, $rowHash, $createdAt));
        $pdo->commit();
    } catch (Exception $ex) {
        $pdo->rollBack();
        throw $ex;
    }
}

// Recomputes the whole chain from genesis and compares it against
// what's stored. Returns array('ok' => bool, 'broken_at' => id|null).
function audit_verify_chain() {
    $rows = db()->query('SELECT id, event_type, user_id, ip_address, details, prev_hash, row_hash, created_at FROM audit_log ORDER BY id ASC')->fetchAll();
    $expectedPrev = AUDIT_GENESIS_HASH;
    foreach ($rows as $row) {
        if ($row['prev_hash'] !== $expectedPrev) {
            return array('ok' => false, 'broken_at' => $row['id']);
        }
        $recomputed = hash('sha256', implode('|', array(
            $row['prev_hash'], $row['event_type'], (string) $row['user_id'], $row['ip_address'],
            (string) $row['details'], $row['created_at'],
        )));
        if (!hash_equals($recomputed, $row['row_hash'])) {
            return array('ok' => false, 'broken_at' => $row['id']);
        }
        $expectedPrev = $row['row_hash'];
    }
    return array('ok' => true, 'broken_at' => null);
}
