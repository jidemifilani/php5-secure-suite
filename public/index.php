<?php
require_once __DIR__ . '/../app/bootstrap.php';
render_header('Home');
?>
<h1>PHP5 Secure Suite</h1>
<p class="lead">Ten security modules, built and running on a real PHP 5.6.40 interpreter (the final PHP 5 release) with MySQL/MariaDB. Every module is live code, not a mockup.</p>

<div class="grid">
  <div class="card module-card">
    <h3>5. RBAC admin panel</h3>
    <p>Roles, permissions, session-scoped checks re-verified against the DB on every request.</p>
    <a href="<?php echo e(base_url('admin/index')); ?>">Open admin panel &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>6. Secure file upload</h3>
    <p>Extension whitelist + real MIME sniffing (fileinfo), storage outside the web root.</p>
    <a href="<?php echo e(base_url('upload')); ?>">Try upload &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>7. TOTP 2FA</h3>
    <p>Hand-rolled RFC 6238 add-on for the login flow, no external library.</p>
    <a href="<?php echo e(base_url('2fa-setup')); ?>">Enroll 2FA &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>8. Password reset</h3>
    <p>Time-limited, single-use, HMAC-signed reset tokens.</p>
    <a href="<?php echo e(base_url('forgot-password')); ?>">Try reset flow &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>9. Session hijacking demo + fix</h3>
    <p>Vulnerable vs. patched session handling, side by side, in an isolated sandbox session.</p>
    <a href="<?php echo e(base_url('session-hijack-demo')); ?>">Open demo &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>10. Rate limiter</h3>
    <p>Per-bucket brute-force protection on login and the API gateway, window math done in MySQL.</p>
    <a href="<?php echo e(base_url('login')); ?>">See it on login &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>11. Encrypted data-at-rest</h3>
    <p>AES-256-CBC + HMAC-SHA256 for sensitive profile fields (demo NIN/BVN), with one-click key rotation.</p>
    <a href="<?php echo e(base_url('profile')); ?>">Open profile &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>12. WAF lite</h3>
    <p>Regex signatures for SQLi/XSS/traversal/command-injection patterns, applied globally and testable live.</p>
    <a href="<?php echo e(base_url('waf-demo')); ?>">Try the filter &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>13. Tamper-evident audit log</h3>
    <p>Hash-chained log of auth/admin/data events; any edited row breaks every hash after it.</p>
    <a href="<?php echo e(base_url('admin/audit-log')); ?>">View audit log &rarr;</a>
  </div>
  <div class="card module-card">
    <h3>14. Secure API gateway</h3>
    <p>Raw-PHP JSON API requiring HMAC-SHA256 request signing plus timestamp/nonce replay protection.</p>
    <a href="<?php echo e(base_url('admin/api-keys')); ?>">Manage API keys &rarr;</a>
  </div>
</div>

<h2 style="margin-top:36px">20 more (auth hardening, playgrounds, defense infra, operability)</h2>
<div class="grid">
  <div class="card module-card"><h3>1. Account lockout</h3><p>Persistent per-account lock after repeated failures, separate from rate limiting.</p><a href="<?php echo e(base_url('login')); ?>">See it on login &rarr;</a></div>
  <div class="card module-card"><h3>2. Remember me</h3><p>Selector/validator cookie, rotates every use.</p><a href="<?php echo e(base_url('login')); ?>">See it on login &rarr;</a></div>
  <div class="card module-card"><h3>3. Password strength</h3><p>Live meter plus server-side common-password rejection.</p><a href="<?php echo e(base_url('register')); ?>">Try registering &rarr;</a></div>
  <div class="card module-card"><h3>4. 2FA backup codes</h3><p>One-time recovery codes generated at enrollment.</p><a href="<?php echo e(base_url('2fa-setup')); ?>">2FA setup &rarr;</a></div>
  <div class="card module-card"><h3>5. New-IP login notice</h3><p>Flags and audit-logs a first-seen IP for your account.</p><a href="<?php echo e(base_url('dashboard')); ?>">Dashboard &rarr;</a></div>
  <div class="card module-card"><h3>6. Math CAPTCHA</h3><p>Gates the login form after repeated failures.</p><a href="<?php echo e(base_url('login')); ?>">See it on login &rarr;</a></div>
  <div class="card module-card"><h3>7. XSS playground</h3><p>Stored XSS, rendered safely via sandboxed iframe.</p><a href="<?php echo e(base_url('xss-playground')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>8. CSRF playground</h3><p>Live forged-request button showing real-time rejection.</p><a href="<?php echo e(base_url('csrf-playground')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>9. SQL injection playground</h3><p>Raw concatenation vs. prepared statements.</p><a href="<?php echo e(base_url('sqli-playground')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>10. IDOR playground</h3><p>Unchecked vs. ownership-checked resource access.</p><a href="<?php echo e(base_url('idor-playground')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>11. Open redirect playground</h3><p>Unchecked vs. whitelist-validated redirect target.</p><a href="<?php echo e(base_url('redirect-playground')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>12. Command injection playground</h3><p>Contained/simulated vulnerable side, real validated ping when patched.</p><a href="<?php echo e(base_url('cmd-playground')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>13. Deserialization playground</h3><p>PHP object injection via unserialize() vs. json_decode().</p><a href="<?php echo e(base_url('deserialize-playground')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>14. Clickjacking demo</h3><p>Default framing headers vs. one page that opts out.</p><a href="<?php echo e(base_url('clickjacking-demo')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>15. Security headers</h3><p>CSP with per-request nonce, HSTS, X-Content-Type-Options, Referrer-Policy - sent globally.</p><a href="<?php echo e(base_url('security-checklist')); ?>">See live state &rarr;</a></div>
  <div class="card module-card"><h3>16. Session inspector</h3><p>Live view of this session's actual cookie/security flags.</p><a href="<?php echo e(base_url('session-inspector')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>17. Admin IP allowlist</h3><p>Optional network-layer gate on top of RBAC for /admin.</p><a href="<?php echo e(base_url('security-checklist')); ?>">See current state &rarr;</a></div>
  <div class="card module-card"><h3>18. Upload integrity</h3><p>SHA-256 at upload time, verified before every download.</p><a href="<?php echo e(base_url('upload')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>19. security.txt</h3><p>RFC 9116 disclosure file plus an in-app policy page.</p><a href="<?php echo e(base_url('security-disclosure')); ?>">Open &rarr;</a></div>
  <div class="card module-card"><h3>20. Security checklist</h3><p>Capstone page reading real live config/state, not prose claims.</p><a href="<?php echo e(base_url('security-checklist')); ?>">Open &rarr;</a></div>
</div>

<?php render_footer(); ?>
