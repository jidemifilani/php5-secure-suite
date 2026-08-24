<?php
require_once __DIR__ . '/../app/bootstrap.php';

// Search is POST, not GET, on purpose: item 12's WAF globally inspects
// $_GET/the URL (documented scope in app/waf.php) precisely because
// query strings are the most common real-world attack vector - but
// that means a GET-based search here would have the WAF block this
// demo's own UNION payload before it ever reached the vulnerable
// query below. POST bodies are outside the WAF's global scan, so the
// two features coexist as designed instead of fighting each other.

$q = '';
$mode = 'patched';
$rows = array();
$sqlShown = '';
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $q = isset($_POST['q']) ? $_POST['q'] : '';
    $mode = (isset($_POST['mode']) && $_POST['mode'] === 'vulnerable') ? 'vulnerable' : 'patched';

    if ($q !== '') {
        if ($mode === 'vulnerable') {
            // VULNERABLE ON PURPOSE: raw string concatenation into the
            // query, executed with query() (no prepare/bind at all).
            $sql = "SELECT id, name, price FROM demo_products WHERE name LIKE '%$q%'";
            $sqlShown = $sql;
            try {
                $stmt = db()->query($sql);
                $rows = $stmt->fetchAll();
                audit_log_event('sqli_demo_query', current_user_id(), 'mode=vulnerable q=' . $q);
            } catch (PDOException $ex) {
                $error = $ex->getMessage();
            }
        } else {
            $sqlShown = "SELECT id, name, price FROM demo_products WHERE name LIKE ?";
            $stmt = db()->prepare($sqlShown);
            $stmt->execute(array('%' . $q . '%'));
            $rows = $stmt->fetchAll();
            audit_log_event('sqli_demo_query', current_user_id(), 'mode=patched q=' . $q);
        }
    }
}

render_header('SQL injection playground');
?>
<h1>SQL injection playground</h1>
<p class="lead">The same product search, built two ways. <strong>Vulnerable</strong>: raw string concatenation, executed with <code>query()</code> - no prepared statement at all. <strong>Patched</strong>: <code>PDO::prepare()</code> with a bound parameter. A seeded <code>demo_secret_notes</code> table exists solely so a UNION payload has something to leak.</p>

<div class="card">
  <form method="post" action="<?php echo e(base_url('sqli-playground')); ?>">
    <?php echo csrf_field(); ?>
    <label for="q">Search product name</label>
    <input type="text" id="q" name="q" value="<?php echo e($q); ?>" placeholder="try: ' UNION SELECT id, note, 0 FROM demo_secret_notes -- ">
    <label style="display:flex;align-items:center;gap:8px;margin-top:10px">
      <input type="radio" name="mode" value="patched" <?php echo $mode === 'patched' ? 'checked' : ''; ?> style="width:auto"> Patched (prepared statement)
    </label>
    <label style="display:flex;align-items:center;gap:8px">
      <input type="radio" name="mode" value="vulnerable" <?php echo $mode === 'vulnerable' ? 'checked' : ''; ?> style="width:auto"> Vulnerable (raw concatenation)
    </label>
    <button type="submit">Search</button>
  </form>
</div>

<?php if ($sqlShown) : ?>
<div class="card">
  <p><small class="hint">Query executed:</small></p>
  <code class="mono" style="display:block;white-space:pre-wrap"><?php echo e($sqlShown); ?></code>
  <?php if ($error) : ?>
    <div class="flash flash-error" style="margin-top:10px">SQL error: <?php echo e($error); ?></div>
  <?php endif; ?>
  <table style="margin-top:14px">
    <tr><th>id</th><th>name</th><th>price</th></tr>
    <?php foreach ($rows as $r) : ?>
      <tr><td><?php echo e($r['id']); ?></td><td><?php echo e($r['name']); ?></td><td><?php echo e($r['price']); ?></td></tr>
    <?php endforeach; ?>
    <?php if (!$rows && !$error) : ?><tr><td colspan="3">No matches.</td></tr><?php endif; ?>
  </table>
</div>
<?php endif; ?>

<div class="card">
  <form method="post" action="<?php echo e(base_url('sqli-reset')); ?>">
    <?php echo csrf_field(); ?>
    <button type="submit" class="secondary">Reset demo data to seeded state</button>
  </form>
</div>
<?php render_footer(); ?>
