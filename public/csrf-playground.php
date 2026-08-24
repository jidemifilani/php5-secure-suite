<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

$errors = array();
$userId = current_user_id();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require(); // the forged request below sends no csrf_token, so this is what rejects it
    $note = isset($_POST['note']) ? trim($_POST['note']) : '';
    if ($note === '' || strlen($note) > 255) {
        $errors[] = 'Note must be 1-255 characters.';
    } else {
        $stmt = db()->prepare('INSERT INTO csrf_notes (user_id, note) VALUES (?, ?)');
        $stmt->execute(array($userId, $note));
        audit_log_event('csrf_demo_note_added', $userId, '');
        redirect('csrf-playground');
    }
}

$notes = db()->prepare('SELECT * FROM csrf_notes WHERE user_id = ? ORDER BY id DESC LIMIT 10');
$notes->execute(array($userId));
$notes = $notes->fetchAll();

render_header('CSRF playground');
?>
<h1>CSRF playground</h1>
<p class="lead">This "add note" form is protected the normal way every form on this site is - a per-session token via <code>csrf_field()</code>/<code>csrf_require()</code> (<code>app/csrf.php</code>). The button below fires a live forged request using your real session cookie but no CSRF token - the same shape of request an attacker's page would send if you visited it while logged in here. Watch it get rejected in real time.</p>

<div class="two-col">
  <div class="card">
    <h2>Legitimate form (has a CSRF token)</h2>
    <?php foreach ($errors as $err) : ?><div class="flash flash-error"><?php echo e($err); ?></div><?php endforeach; ?>
    <form method="post" action="<?php echo e(base_url('csrf-playground')); ?>">
      <?php echo csrf_field(); ?>
      <label for="note">Note</label>
      <input type="text" id="note" name="note" maxlength="255" required>
      <button type="submit">Add note</button>
    </form>
  </div>

  <div class="card">
    <h2>Simulated forged request (no token)</h2>
    <p class="lead">Fires a real <code>fetch()</code> POST to this same endpoint, cookies included, no CSRF token.</p>
    <button type="button" class="danger" onclick="p5ssForge()">Simulate forged request</button>
    <pre id="forge-result" class="mono" style="white-space:pre-wrap;margin-top:10px"></pre>
  </div>
</div>

<div class="card">
  <h2>Your notes (only successfully added via the legitimate form survive)</h2>
  <table>
    <tr><th>Note</th><th>Added</th></tr>
    <?php foreach ($notes as $n) : ?>
      <tr><td><?php echo e($n['note']); ?></td><td><?php echo e($n['created_at']); ?></td></tr>
    <?php endforeach; ?>
    <?php if (!$notes) : ?><tr><td colspan="2">No notes yet.</td></tr><?php endif; ?>
  </table>
</div>

<script nonce="<?php echo e(csp_nonce()); ?>">
function p5ssForge() {
  var out = document.getElementById('forge-result');
  out.textContent = 'Sending forged POST (no csrf_token field)...';
  fetch('<?php echo e(base_url('csrf-playground')); ?>', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'note=' + encodeURIComponent('forged note (should never appear above)')
  }).then(function(r) {
    out.textContent = 'Response status: ' + r.status + ' ' + r.statusText + (r.status === 403 ? '\nBlocked by csrf_require() - exactly as intended.' : '\nUnexpected: this should have been blocked.');
  }).catch(function(e) {
    out.textContent = 'Request failed: ' + e;
  });
}
</script>

<?php render_footer(); ?>
