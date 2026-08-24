<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

$userId = current_user_id();
$stmt = db()->prepare('SELECT * FROM demo_idor_notes WHERE user_id = ?');
$stmt->execute(array($userId));
$myNote = $stmt->fetch();

$totalNotes = (int) db()->query('SELECT COUNT(*) FROM demo_idor_notes')->fetchColumn();

render_header('IDOR playground');
?>
<h1>IDOR playground</h1>
<p class="lead">Every account gets one private note automatically at registration (yours has id <strong><?php echo (int) $myNote['id']; ?></strong>). There are currently <strong><?php echo $totalNotes; ?></strong> notes in total across all accounts. Try viewing a different id in each mode below.</p>

<div class="card">
  <p><strong>Your note (id <?php echo (int) $myNote['id']; ?>):</strong> <?php echo e($myNote['title']); ?> - <?php echo e($myNote['body']); ?></p>
</div>

<div class="two-col">
  <div class="card">
    <h2>Vulnerable viewer</h2>
    <p class="lead">Fetches a note by id with no ownership check at all.</p>
    <form method="get" action="<?php echo e(base_url('idor-view')); ?>">
      <input type="hidden" name="mode" value="vulnerable">
      <label for="id_v">Note id</label>
      <input type="number" id="id_v" name="id" min="1" value="<?php echo (int) $myNote['id']; ?>" required>
      <button type="submit">View</button>
    </form>
  </div>
  <div class="card">
    <h2>Patched viewer</h2>
    <p class="lead">Fetches the note, then checks <code>note.user_id === current_user_id()</code>.</p>
    <form method="get" action="<?php echo e(base_url('idor-view')); ?>">
      <input type="hidden" name="mode" value="patched">
      <label for="id_p">Note id</label>
      <input type="number" id="id_p" name="id" min="1" value="<?php echo (int) $myNote['id']; ?>" required>
      <button type="submit">View</button>
    </form>
  </div>
</div>

<?php render_footer(); ?>
