<?php
require_once __DIR__ . '/../app/bootstrap.php';
require_login();

$mode = (isset($_GET['mode']) && $_GET['mode'] === 'vulnerable') ? 'vulnerable' : 'patched';
$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
$userId = current_user_id();

$stmt = db()->prepare('SELECT n.*, u.username FROM demo_idor_notes n JOIN users u ON u.id = n.user_id WHERE n.id = ?');
$stmt->execute(array($id));
$note = $stmt->fetch();

$denied = false;
if ($note && $mode === 'patched' && (int) $note['user_id'] !== $userId) {
    audit_log_event('idor_demo_blocked', $userId, 'attempted note_id=' . $id);
    $denied = true;
} elseif ($note && $mode === 'vulnerable' && (int) $note['user_id'] !== $userId) {
    audit_log_event('idor_demo_leaked', $userId, 'viewed note_id=' . $id . ' owned by user_id=' . $note['user_id']);
}

render_header('IDOR viewer (' . $mode . ')');
?>
<h1>IDOR viewer - <?php echo e($mode); ?> mode</h1>

<div class="card" style="max-width:480px">
  <?php if (!$note) : ?>
    <div class="flash flash-error">No note with id <?php echo (int) $id; ?>.</div>
  <?php elseif ($denied) : ?>
    <div class="flash flash-error">403: note <?php echo (int) $id; ?> belongs to another account. Ownership check blocked this.</div>
  <?php else : ?>
    <p><strong>Owner:</strong> <?php echo e($note['username']); ?> <?php echo ((int) $note['user_id'] === $userId) ? '<span class="pill pill-ok">you</span>' : '<span class="pill pill-err">not you</span>'; ?></p>
    <p><strong>Title:</strong> <?php echo e($note['title']); ?></p>
    <p><strong>Body:</strong> <?php echo e($note['body']); ?></p>
    <?php if ((int) $note['user_id'] !== $userId) : ?>
      <div class="flash flash-error">This is the IDOR: <?php echo e($mode); ?> mode let you read another account's private note just by changing the id in the URL.</div>
    <?php endif; ?>
  <?php endif; ?>
  <p><a href="<?php echo e(base_url('idor-playground')); ?>">&larr; back</a></p>
</div>
<?php render_footer(); ?>
