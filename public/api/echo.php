<?php
require_once __DIR__ . '/../../app/bootstrap.php';

rate_limit_enforce('api:ip:' . client_ip(), RATE_LIMIT_API_MAX, RATE_LIMIT_API_WINDOW);
rate_limit_record_hit('api:ip:' . client_ip());

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$body = file_get_contents('php://input');

$result = api_verify_request($method, $path, $body);

if (!$result['ok']) {
    audit_log_event('api_auth_failed', null, $result['error']);
    json_response(array('ok' => false, 'error' => $result['error']), 401);
}

$row = $result['api_key_row'];
rate_limit_enforce('api:key:' . $row['id'], RATE_LIMIT_API_MAX, RATE_LIMIT_API_WINDOW);
rate_limit_record_hit('api:key:' . $row['id']);

$parsed = json_decode($body, true);
audit_log_event('api_request', null, 'endpoint=echo key=' . $row['label']);
json_response(array(
    'ok' => true,
    'authenticated_as' => $row['label'],
    'you_sent' => $parsed === null ? $body : $parsed,
));
