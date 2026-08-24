<?php
require_once __DIR__ . '/../app/bootstrap.php';

$example = 'https://example.com/phishing-page';

render_header('Open redirect playground');
?>
<h1>Open redirect playground</h1>
<p class="lead">A "continue to X" style redirector, built two ways. Real-world attacks use this pattern to make a phishing link look like it starts on a trusted domain (<code>yoursite.com/go?url=evil.example</code>) before bouncing the victim off-site.</p>

<div class="two-col">
  <div class="card">
    <h2>Vulnerable</h2>
    <p class="lead"><code>header('Location: ' . $_GET['url'])</code> - no validation at all.</p>
    <p><a class="btn danger" href="<?php echo e(base_url('go-vulnerable')); ?>?url=<?php echo rawurlencode($example); ?>">Try it (redirects off-site for real)</a></p>
    <p><a class="btn secondary" href="<?php echo e(base_url('go-vulnerable')); ?>?url=/dashboard">Try a safe target instead</a></p>
  </div>
  <div class="card">
    <h2>Patched</h2>
    <p class="lead">Validates with <code>is_safe_relative_redirect()</code> - only a single-leading-slash, same-site path is allowed.</p>
    <p><a class="btn secondary" href="<?php echo e(base_url('go-patched')); ?>?url=<?php echo rawurlencode($example); ?>">Try it (blocked)</a></p>
    <p><a class="btn secondary" href="<?php echo e(base_url('go-patched')); ?>?url=/dashboard">Try a safe target</a></p>
  </div>
</div>

<?php render_footer(); ?>
