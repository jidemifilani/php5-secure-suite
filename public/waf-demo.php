<?php
require_once __DIR__ . '/../app/bootstrap.php';

$result = null;
$payload = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $payload = isset($_POST['payload']) ? $_POST['payload'] : '';
    // Runs the exact same engine that already inspects every request's
    // URL/query string globally (see app/waf.php, called from
    // bootstrap.php) - here against arbitrary POST text, non-blocking,
    // so the result renders on this same page either way.
    $result = waf_check_value($payload, true);
}

render_header('WAF lite demo');
?>
<h1>WAF lite</h1>
<p class="lead">Regex signatures for common attack patterns (SQL injection, XSS, path traversal, command injection, null bytes). This exact engine already runs on every request's URL and query string globally - try adding <code>?x=&lt;script&gt;</code> to this page's URL and see it get blocked. Below, test arbitrary text against the same rules without needing a crafted URL.</p>

<div class="card" style="max-width:600px">
  <form method="post" action="<?php echo e(base_url('waf-demo')); ?>">
    <?php echo csrf_field(); ?>
    <label for="payload">Text to test</label>
    <textarea id="payload" name="payload" placeholder="e.g. ' OR 1=1 -- or &lt;script&gt;alert(1)&lt;/script&gt;"><?php echo e($payload); ?></textarea>
    <button type="submit">Run through WAF</button>
  </form>

  <?php if ($result !== null) : ?>
    <?php if ($result['matched']) : ?>
      <div class="flash flash-error" style="margin-top:16px">Blocked - matched rule: <code><?php echo e($result['rule']); ?></code></div>
    <?php else : ?>
      <div class="flash flash-success" style="margin-top:16px">Clean - no signature matched.</div>
    <?php endif; ?>
  <?php endif; ?>
</div>

<div class="card">
  <h2>Signatures</h2>
  <table>
    <tr><th>Rule</th><th>Catches</th></tr>
    <tr><td>sqli_union_select</td><td>UNION SELECT</td></tr>
    <tr><td>sqli_boolean</td><td>OR/AND 1=1 style tautologies</td></tr>
    <tr><td>sqli_comment</td><td>Trailing <code>--</code>/<code>#</code>/<code>/*</code> SQL comment</td></tr>
    <tr><td>sqli_stacked</td><td>Stacked queries: <code>; DROP/DELETE/UPDATE/INSERT</code></td></tr>
    <tr><td>xss_script_tag</td><td>&lt;script&gt;</td></tr>
    <tr><td>xss_event_handler</td><td>onerror=/onload=/onclick=/onmouseover=</td></tr>
    <tr><td>xss_js_uri</td><td>javascript: URIs</td></tr>
    <tr><td>path_traversal</td><td>../ or ..\</td></tr>
    <tr><td>cmd_injection</td><td>Shell metacharacters + common commands</td></tr>
    <tr><td>null_byte</td><td>%00</td></tr>
  </table>
  <?php if (current_user_id() && user_has_permission(current_user_id(), 'view_waf_log')) : ?>
    <p><small class="hint"><a href="<?php echo e(base_url('admin/waf-log')); ?>">View the full WAF block log &rarr;</a></small></p>
  <?php endif; ?>
</div>

<?php render_footer(); ?>
