<?php
require_once __DIR__ . '/../app/bootstrap.php';

$errors = array();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $name = isset($_POST['author_name']) ? trim($_POST['author_name']) : '';
    $body = isset($_POST['body']) ? $_POST['body'] : '';

    if ($name === '' || strlen($name) > 60) { $errors[] = 'Name must be 1-60 characters.'; }
    if ($body === '' || strlen($body) > 2000) { $errors[] = 'Comment must be 1-2000 characters.'; }

    if (empty($errors)) {
        // Validated, but deliberately NOT sanitized/escaped at storage
        // time - that's the point of this playground. The safety net
        // is entirely in how each comment is rendered below.
        $stmt = db()->prepare('INSERT INTO demo_comments (author_name, body) VALUES (?, ?)');
        $stmt->execute(array($name, $body));
        audit_log_event('xss_demo_comment_posted', current_user_id(), 'name=' . $name);
        redirect('xss-playground');
    }
}

$comments = db()->query('SELECT * FROM demo_comments ORDER BY id DESC LIMIT 20')->fetchAll();

render_header('XSS playground');
?>
<h1>XSS playground</h1>
<p class="lead">A comment form that stores input unsanitized (only length-validated). Try posting <code>&lt;script&gt;document.title='pwned'&lt;/script&gt;</code> or <code>&lt;img src=x onerror=alert(1)&gt;</code>. Every comment renders twice below: safely (escaped) and in a way that actually executes what you submitted - fully contained in a sandboxed iframe with no <code>allow-same-origin</code>, so it has an opaque origin and cannot touch this page's cookies or DOM. This is the safe way to demonstrate real XSS execution without exposing anything.</p>

<div class="card" style="max-width:480px">
  <?php foreach ($errors as $err) : ?><div class="flash flash-error"><?php echo e($err); ?></div><?php endforeach; ?>
  <form method="post" action="<?php echo e(base_url('xss-playground')); ?>">
    <?php echo csrf_field(); ?>
    <label for="author_name">Name</label>
    <input type="text" id="author_name" name="author_name" maxlength="60" required>
    <label for="body">Comment</label>
    <textarea id="body" name="body" maxlength="2000" required></textarea>
    <button type="submit">Post comment</button>
  </form>
</div>

<?php foreach ($comments as $c) : ?>
  <div class="card">
    <p><strong><?php echo e($c['author_name']); ?></strong> <small class="hint"><?php echo e($c['created_at']); ?></small></p>
    <div class="two-col">
      <div>
        <small class="hint">Safe render (<code>htmlspecialchars</code>):</small>
        <div style="background:var(--panel-2);padding:10px;border-radius:6px;margin-top:4px"><?php echo e($c['body']); ?></div>
      </div>
      <div>
        <small class="hint">Unsafe render (sandboxed, contained):</small>
        <iframe sandbox="allow-scripts" style="width:100%;height:80px;border:1px solid var(--border);border-radius:6px;margin-top:4px;background:#fff"
          srcdoc="<?php echo e($c['body']); ?>"></iframe>
      </div>
    </div>
  </div>
<?php endforeach; ?>

<?php render_footer(); ?>
