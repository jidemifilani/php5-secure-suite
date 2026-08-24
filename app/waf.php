<?php
// Item 12: WAF lite - regex signatures for common attack patterns.
// Applied globally to the URL/query string (cheap, near-zero false
// positives - legitimate URLs don't contain SQL/script syntax).
// POST bodies are NOT globally scanned here, since real form fields
// on this site (passwords, free-text comments) can legitimately
// contain characters that overlap with these signatures; instead
// public/waf-demo.php lets you run arbitrary text through the same
// engine on demand so the filtering itself is still fully visible.

function waf_signatures() {
    return array(
        'sqli_union_select'  => '/\bunion\b[\s\S]{0,40}\bselect\b/i',
        'sqli_boolean'       => '/\b(or|and)\b\s*[\'"]?\s*\d+\s*=\s*\d+/i',
        'sqli_comment'       => '/(--|#|\/\*)\s*$/',
        'sqli_stacked'       => '/;\s*(drop|delete|update|insert)\b/i',
        'xss_script_tag'     => '/<\s*script\b/i',
        'xss_event_handler'  => '/\bon(error|load|click|mouseover)\s*=/i',
        'xss_js_uri'         => '/javascript\s*:/i',
        'path_traversal'     => '/\.\.[\/\\\\]/',
        'cmd_injection'      => '/[;&|`]\s*(cat|ls|dir|whoami|net|ping|type|del|rm)\b/i',
        'null_byte'          => '/%00/',
    );
}

function waf_scan_value($value) {
    if (!is_string($value)) { return null; }
    foreach (waf_signatures() as $rule => $pattern) {
        if (preg_match($pattern, $value)) {
            return $rule;
        }
    }
    return null;
}

// Non-exiting check, reusable by both the global inspector and the
// interactive demo page. Always logs a match to waf_log; $block
// controls whether the row is recorded as 'blocked' or 'logged'.
function waf_check_value($value, $block = true) {
    $rule = waf_scan_value($value);
    if ($rule === null) {
        return array('matched' => false, 'rule' => null);
    }
    $snippet = mb_substr($value, 0, 200);
    $stmt = db()->prepare(
        'INSERT INTO waf_log (ip_address, request_uri, matched_rule, payload_snippet, action) VALUES (?, ?, ?, ?, ?)'
    );
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $stmt->execute(array(client_ip(), $uri, $rule, $snippet, $block ? 'blocked' : 'logged'));
    return array('matched' => true, 'rule' => $rule);
}

function waf_inspect_request() {
    $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $result = waf_check_value(urldecode($uri));
    if ($result['matched']) {
        http_response_code(403);
        exit('403 Forbidden: request blocked by WAF (rule: ' . e($result['rule']) . ')');
    }
    foreach ($_GET as $value) {
        if (!is_string($value)) { continue; }
        $result = waf_check_value($value);
        if ($result['matched']) {
            http_response_code(403);
            exit('403 Forbidden: request blocked by WAF (rule: ' . e($result['rule']) . ')');
        }
    }
}
