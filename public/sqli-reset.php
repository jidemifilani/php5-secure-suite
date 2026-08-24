<?php
require_once __DIR__ . '/../app/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') { redirect('sqli-playground'); }
csrf_require();

$pdo = db();
$pdo->exec('DELETE FROM demo_products');
$pdo->exec('DELETE FROM demo_secret_notes');
$pdo->exec("INSERT INTO demo_products (name, price) VALUES
  ('Notebook', 4.50), ('USB Cable', 6.00), ('Wireless Mouse', 12.99),
  ('Mechanical Keyboard', 45.00), ('Monitor Stand', 22.50), ('Webcam', 33.00),
  ('Desk Lamp', 18.75), ('Laptop Sleeve', 15.20), ('Phone Charger', 9.99),
  ('Bluetooth Speaker', 27.40), ('Screen Cleaner Kit', 5.30)");
$pdo->exec("INSERT INTO demo_secret_notes (note) VALUES
  ('FLAG{sqli_playground_php5_demo_only}'),
  ('Internal note: this table only exists so a UNION payload has something to leak.')");

audit_log_event('sqli_demo_reset', current_user_id(), '');
flash_set('success', 'SQLi playground data reset to seeded state.');
redirect('sqli-playground');
