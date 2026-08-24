<?php
require_once __DIR__ . '/../app/bootstrap.php';

render_header('Clickjacking demo');
?>
<h1>Clickjacking demo</h1>
<p class="lead">Every page on this site sends <code>X-Frame-Options: DENY</code> and <code>Content-Security-Policy: frame-ancestors 'none'</code> by default (item 15). <code>clickjacking-target.php?mode=vulnerable</code> is the one page that explicitly opts out of both, via <code>header_remove()</code> - the same pattern as this app's other opt-out cases. Your browser should refuse to render the first iframe below and load the second one fine.</p>

<div class="two-col">
  <div class="card">
    <h2>Protected (default headers)</h2>
    <iframe src="<?php echo e(base_url('clickjacking-target')); ?>?mode=protected" style="width:100%;height:140px;border:1px solid var(--border);border-radius:6px;background:#fff"></iframe>
    <p><small class="hint">Should be blank/blocked by your browser.</small></p>
  </div>
  <div class="card">
    <h2>Vulnerable (headers removed)</h2>
    <iframe src="<?php echo e(base_url('clickjacking-target')); ?>?mode=vulnerable" style="width:100%;height:140px;border:1px solid var(--border);border-radius:6px;background:#fff"></iframe>
    <p><small class="hint">Renders normally - in a real attack this would be made invisible and positioned over a decoy page.</small></p>
  </div>
</div>

<?php render_footer(); ?>
