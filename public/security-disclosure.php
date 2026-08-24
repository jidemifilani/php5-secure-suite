<?php
require_once __DIR__ . '/../app/bootstrap.php';
render_header('Security disclosure');
?>
<h1>Vulnerability disclosure policy</h1>
<p class="lead">This is an educational project, not a production service - the vulnerable code paths in the playgrounds on this site (<a href="<?php echo e(base_url('index')); ?>">home page</a>) are intentional and documented, not real findings. This page exists to demonstrate the practice itself, alongside <a href="<?php echo e(base_url('.well-known/security.txt')); ?>">/.well-known/security.txt</a> (RFC 9116).</p>

<div class="card">
  <h2>Scope</h2>
  <p>In a real deployment of a site like this, in-scope would typically mean: the live application and its infrastructure, excluding the deliberately vulnerable demo modes of the playgrounds (those are the point).</p>
</div>

<div class="card">
  <h2>What this project actually does instead</h2>
  <ul>
    <li>Real security bugs found while building this were fixed immediately and are documented in <code>README.md</code> (e.g. the AES-256-GCM &rarr; CBC+HMAC change, once PHP 5.6's real <code>openssl_encrypt()</code> signature turned out not to support GCM tags).</li>
    <li>Every auth/admin/data-change event is recorded in the <a href="<?php echo e(base_url('admin/audit-log')); ?>">tamper-evident audit log</a> (item 13), if you have access to it.</li>
  </ul>
</div>

<?php render_footer(); ?>
