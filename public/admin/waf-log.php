<?php
require_once __DIR__ . '/../../app/bootstrap.php';
require_permission('view_waf_log');
require_admin_ip_allowed();

$rows = db()->query('SELECT * FROM waf_log ORDER BY id DESC LIMIT 200')->fetchAll();

render_header('WAF log');
?>
<h1>WAF block log</h1>
<div class="card">
  <table>
    <tr><th>ID</th><th>IP</th><th>URI</th><th>Rule</th><th>Snippet</th><th>Action</th><th>When</th></tr>
    <?php foreach ($rows as $row) : ?>
      <tr>
        <td><?php echo (int) $row['id']; ?></td>
        <td><?php echo e($row['ip_address']); ?></td>
        <td style="max-width:220px;overflow-wrap:anywhere"><?php echo e($row['request_uri']); ?></td>
        <td><code><?php echo e($row['matched_rule']); ?></code></td>
        <td style="max-width:220px;overflow-wrap:anywhere"><?php echo e($row['payload_snippet']); ?></td>
        <td><span class="pill <?php echo $row['action'] === 'blocked' ? 'pill-err' : 'pill-warn'; ?>"><?php echo e($row['action']); ?></span></td>
        <td><?php echo e($row['created_at']); ?></td>
      </tr>
    <?php endforeach; ?>
    <?php if (!$rows) : ?><tr><td colspan="7">No blocked requests yet - try <a href="<?php echo e(base_url('waf-demo')); ?>">the WAF demo</a>.</td></tr><?php endif; ?>
  </table>
</div>
<?php render_footer(); ?>
