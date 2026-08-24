-- PHP5 Secure Suite - v2 additive migration (20-feature round, 2026-08-24).
-- Safe to re-run against the existing v1 install: mysql -u root php5_secure_suite < upgrade_v2.sql
-- Also folded into the master schema.sql for fresh installs.

USE php5_secure_suite;

-- 1. Account lockout (separate from the rate limiter: persistent per-account lock)
ALTER TABLE users
  ADD COLUMN failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN locked_until DATETIME NULL;

-- 2. Remember-me
CREATE TABLE IF NOT EXISTS remember_tokens (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  selector VARCHAR(24) NOT NULL UNIQUE,
  validator_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 4. TOTP backup/recovery codes
CREATE TABLE IF NOT EXISTS totp_backup_codes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. New-device/new-IP login notice
CREATE TABLE IF NOT EXISTS user_known_ips (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_ip (user_id, ip_address),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 7. XSS playground
CREATE TABLE IF NOT EXISTS demo_comments (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  author_name VARCHAR(60) NOT NULL,
  body TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 8. CSRF playground
CREATE TABLE IF NOT EXISTS csrf_notes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  note VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 9. SQL injection playground
CREATE TABLE IF NOT EXISTS demo_products (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  price DECIMAL(10,2) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS demo_secret_notes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  note VARCHAR(255) NOT NULL
) ENGINE=InnoDB;

INSERT INTO demo_products (name, price) VALUES
  ('Notebook', 4.50), ('USB Cable', 6.00), ('Wireless Mouse', 12.99),
  ('Mechanical Keyboard', 45.00), ('Monitor Stand', 22.50), ('Webcam', 33.00),
  ('Desk Lamp', 18.75), ('Laptop Sleeve', 15.20), ('Phone Charger', 9.99),
  ('Bluetooth Speaker', 27.40), ('Screen Cleaner Kit', 5.30);

INSERT INTO demo_secret_notes (note) VALUES
  ('FLAG{sqli_playground_php5_demo_only}'),
  ('Internal note: this table only exists so a UNION payload has something to leak.');

-- 10. IDOR playground
CREATE TABLE IF NOT EXISTS demo_idor_notes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  title VARCHAR(100) NOT NULL,
  body VARCHAR(255) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 18. Upload integrity verification
ALTER TABLE uploads ADD COLUMN sha256 CHAR(64) NULL;
