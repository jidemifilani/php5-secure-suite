<?php

function render_header($title) {
    $userId = current_user_id();
    $roles = $userId ? user_roles($userId) : array();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo e($title); ?> - <?php echo e(SITE_NAME); ?></title>
<link rel="stylesheet" href="<?php echo e(base_url('assets/css/style.css')); ?>">
</head>
<body>
<header class="site-header">
  <div class="wrap">
    <a class="brand" href="<?php echo e(base_url('index')); ?>"><?php echo e(SITE_NAME); ?></a>
    <nav>
      <?php if ($userId): ?>
        <a href="<?php echo e(base_url('dashboard')); ?>">Dashboard</a>
        <a href="<?php echo e(base_url('profile')); ?>">Profile</a>
        <a href="<?php echo e(base_url('upload')); ?>">Uploads</a>
        <?php if (in_array('admin', $roles, true) || in_array('moderator', $roles, true)): ?>
          <a href="<?php echo e(base_url('admin/index')); ?>">Admin</a>
        <?php endif; ?>
        <a href="<?php echo e(base_url('logout')); ?>">Log out</a>
      <?php else: ?>
        <a href="<?php echo e(base_url('login')); ?>">Log in</a>
        <a href="<?php echo e(base_url('register')); ?>">Register</a>
      <?php endif; ?>
    </nav>
  </div>
</header>
<main class="wrap">
<?php
    $error = flash_get('error');
    $success = flash_get('success');
    if ($error) { echo '<div class="flash flash-error">' . e($error) . '</div>'; }
    if ($success) { echo '<div class="flash flash-success">' . e($success) . '</div>'; }
}

function render_footer() {
?>
</main>
<footer class="site-footer wrap">
  <p><?php echo e(SITE_NAME); ?> &mdash; educational project, real PHP 5.6.40 runtime. Not for production use.</p>
</footer>
</body>
</html>
<?php
}
