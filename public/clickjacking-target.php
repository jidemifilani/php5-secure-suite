<?php
require_once __DIR__ . '/../app/bootstrap.php';

// Item 14: the one deliberate exception to item 15's site-wide
// X-Frame-Options/CSP frame-ancestors headers - same "explicit
// opt-out" pattern as this machine's other PHP project's
// ALLOW_FRAMING constant for its own clickjacking lab.
$mode = (isset($_GET['mode']) && $_GET['mode'] === 'vulnerable') ? 'vulnerable' : 'protected';
if ($mode === 'vulnerable') {
    header_remove('X-Frame-Options');
    header_remove('Content-Security-Policy');
}
?>
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Target page</title>
<style>body{font-family:sans-serif;background:#fff;color:#111;padding:16px;margin:0}
.btn{background:#c0392b;color:#fff;border:none;padding:12px 20px;border-radius:6px;font-size:1rem;cursor:pointer}</style>
</head><body>
<p>Mode: <strong><?php echo e($mode); ?></strong></p>
<button class="btn" id="dangerbtn">Delete my account</button>
<p id="r"></p>
<script<?php echo $mode === 'protected' ? ' nonce="' . e(csp_nonce()) . '"' : ''; ?>>
document.getElementById('dangerbtn').onclick = function () {
  document.getElementById('r').textContent = 'Sensitive action would have fired here.';
};
</script>
</body></html>
