<?php
require_once __DIR__ . '/../app/bootstrap.php';

$url = isset($_GET['url']) ? $_GET['url'] : '/dashboard';

if (!is_safe_relative_redirect($url)) {
    audit_log_event('redirect_demo_blocked', current_user_id(), 'url=' . $url);
    render_header('Redirect blocked');
    ?>
    <h1>Redirect blocked</h1>
    <div class="card" style="max-width:480px">
      <div class="flash flash-error">The target "<?php echo e($url); ?>" is not a same-site relative path - refusing to redirect.</div>
      <p><a href="<?php echo e(base_url('redirect-playground')); ?>">&larr; back</a></p>
    </div>
    <?php
    render_footer();
    exit;
}

audit_log_event('redirect_demo_patched', current_user_id(), 'url=' . $url);
header('Location: ' . $url);
exit;
