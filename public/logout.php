<?php
require_once __DIR__ . '/../app/bootstrap.php';
clear_remember_cookie();
log_out_user();
flash_set('success', 'You have been logged out.');
redirect('login');
