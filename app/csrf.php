<?php

function csrf_token() {
    if (empty($_SESSION['_csrf'])) {
        $_SESSION['_csrf'] = random_token_hex(32);
    }
    return $_SESSION['_csrf'];
}

function csrf_field() {
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function csrf_require() {
    $sent = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
    $expected = isset($_SESSION['_csrf']) ? $_SESSION['_csrf'] : '';
    if ($expected === '' || !hash_equals($expected, $sent)) {
        http_response_code(403);
        exit('Forbidden: invalid or missing CSRF token.');
    }
}
