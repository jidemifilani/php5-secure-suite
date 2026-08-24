<?php
// Item 10: rate limiter / brute-force protection. The window
// boundary is computed inside MySQL (NOW() - INTERVAL ? SECOND), not
// in PHP with time() - $window - a prior project on this machine hit
// a bug where the PHP host's clock and MySQL's clock silently
// disagreed by an hour, so a PHP-side comparison against
// CURRENT_TIMESTAMP-stamped rows never matched and the limiter never
// blocked anything. Keeping both sides of the comparison on MySQL's
// own clock avoids that class of bug entirely.

function rate_limit_hit_count($bucketKey, $windowSeconds) {
    $stmt = db()->prepare(
        'SELECT COUNT(*) FROM rate_limit_hits WHERE bucket_key = ? AND hit_at >= NOW() - INTERVAL ? SECOND'
    );
    $stmt->execute(array($bucketKey, $windowSeconds));
    return (int) $stmt->fetchColumn();
}

function rate_limit_record_hit($bucketKey) {
    $stmt = db()->prepare('INSERT INTO rate_limit_hits (bucket_key) VALUES (?)');
    $stmt->execute(array($bucketKey));
}

// Returns true if the caller is still under the limit. Does NOT
// record a hit by itself - call rate_limit_record_hit() for the
// attempts that should count (e.g. every login POST, successful or
// not; only successful calls for some API buckets, by design choice).
function rate_limit_allowed($bucketKey, $max, $windowSeconds) {
    return rate_limit_hit_count($bucketKey, $windowSeconds) < $max;
}

function rate_limit_enforce($bucketKey, $max, $windowSeconds) {
    if (!rate_limit_allowed($bucketKey, $max, $windowSeconds)) {
        audit_log_event('rate_limited', current_user_id(), 'bucket=' . $bucketKey);
        http_response_code(429);
        header('Retry-After: ' . $windowSeconds);
        exit('429 Too Many Requests: try again in a few minutes.');
    }
}
