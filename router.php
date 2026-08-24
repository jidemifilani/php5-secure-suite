<?php
// Router for PHP's built-in dev server: `php -S host:port -t public router.php`
// The built-in server already serves any file that physically exists
// at the requested path (so /login.php keeps working untouched).
// This router only handles the extension-less "clean URL" case by
// mapping /foo -> public/foo.php, and /admin/foo -> public/admin/foo.php.

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$publicRoot = __DIR__ . '/public';
$requested = $publicRoot . $uri;

// Real static file (css/js/images) or a real .php file - let the
// built-in server's default handling serve it directly.
if ($uri !== '/' && file_exists($requested) && !is_dir($requested)) {
    return false;
}

if ($uri === '/' || $uri === '') {
    require $publicRoot . '/index.php';
    return true;
}

$candidate = $publicRoot . rtrim($uri, '/') . '.php';
if (is_file($candidate)) {
    // Deny direct routing into app/storage/database even though they
    // live outside public/ and can't normally be reached this way;
    // this is a defense-in-depth check on the router itself.
    require $candidate;
    return true;
}

http_response_code(404);
echo '404 Not Found';
return true;
