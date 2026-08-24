-- PHP5 Secure Suite - database schema
-- Target: MySQL/MariaDB, InnoDB, utf8mb4
-- Run once against a fresh database: mysql -u root php5_secure_suite < schema.sql

CREATE DATABASE IF NOT EXISTS php5_secure_suite CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE php5_secure_suite;

-- ---------------------------------------------------------------
-- Core auth (the "existing login system" every add-on hangs off)
-- ---------------------------------------------------------------
CREATE TABLE users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(190) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  totp_secret VARCHAR(64) NULL,
  totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,   -- item 1: account lockout (distinct from the rate limiter)
  locked_until DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 5. RBAC
-- ---------------------------------------------------------------
CREATE TABLE roles (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(50) NOT NULL UNIQUE,
  description VARCHAR(255) NULL
) ENGINE=InnoDB;

CREATE TABLE permissions (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(50) NOT NULL UNIQUE,
  description VARCHAR(255) NULL
) ENGINE=InnoDB;

CREATE TABLE role_permissions (
  role_id INT UNSIGNED NOT NULL,
  permission_id INT UNSIGNED NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE user_roles (
  user_id INT UNSIGNED NOT NULL,
  role_id INT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 6. Secure file upload
-- ---------------------------------------------------------------
CREATE TABLE uploads (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  original_name VARCHAR(255) NOT NULL,
  stored_name VARCHAR(120) NOT NULL,   -- random name on disk, storage/uploads/, outside web root
  mime_type VARCHAR(100) NOT NULL,
  size_bytes INT UNSIGNED NOT NULL,
  sha256 CHAR(64) NULL,                -- item 18: integrity hash computed at upload, checked at download
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 8. Password reset - time-limited, single-use, signed tokens
-- ---------------------------------------------------------------
CREATE TABLE password_resets (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  selector VARCHAR(24) NOT NULL UNIQUE,   -- looked up directly, not secret
  validator_hash VARCHAR(64) NOT NULL,    -- sha256 of the random validator; raw validator only ever in the emailed/shown link
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 10. Rate limiter / brute-force protection
-- window math done in MySQL (NOW() - INTERVAL), never in PHP,
-- to avoid PHP/MySQL clock-skew silently defeating the limiter
-- ---------------------------------------------------------------
CREATE TABLE rate_limit_hits (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  bucket_key VARCHAR(150) NOT NULL,   -- e.g. "login:ip:1.2.3.4", "api:key:abc123"
  hit_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_bucket_time (bucket_key, hit_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 11. Encrypted data-at-rest (AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC)
-- with key rotation. (Plan A was AES-256-GCM; PHP 5.6's openssl_encrypt()
-- has no $tag output param - that landed in PHP 7.1 - so this uses CBC
-- with an independent HMAC key instead. See app/crypto.php.)
-- ---------------------------------------------------------------
CREATE TABLE encryption_keys (
  key_version INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  is_active TINYINT(1) NOT NULL DEFAULT 1,   -- only the newest version is used to encrypt new data; old versions kept active-for-decrypt until rotated out
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  retired_at DATETIME NULL
  -- the raw key material itself is NOT stored here; it lives in
  -- storage/keys/key_<version>.bin (outside web root, outside the DB)
  -- so a DB dump alone can never decrypt anything.
) ENGINE=InnoDB;

CREATE TABLE secure_profile_data (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  field_name VARCHAR(30) NOT NULL,     -- e.g. "nin", "bvn"
  ciphertext MEDIUMBLOB NOT NULL,
  iv BINARY(16) NOT NULL,              -- AES-CBC IV
  auth_tag BINARY(32) NOT NULL,        -- HMAC-SHA256 over iv||ciphertext
  key_version INT UNSIGNED NOT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_field (user_id, field_name),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (key_version) REFERENCES encryption_keys(key_version)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 12. WAF lite - request filtering log
-- ---------------------------------------------------------------
CREATE TABLE waf_log (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL,
  request_uri VARCHAR(500) NOT NULL,
  matched_rule VARCHAR(100) NOT NULL,
  payload_snippet VARCHAR(255) NULL,
  action ENUM('blocked','logged') NOT NULL DEFAULT 'blocked',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 13. Tamper-evident audit log (hash chain, like a mini blockchain:
-- each row commits to the previous row's hash, so editing/deleting
-- a historical row breaks every hash after it)
-- ---------------------------------------------------------------
CREATE TABLE audit_log (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,
  user_id INT UNSIGNED NULL,
  ip_address VARCHAR(45) NULL,
  details TEXT NULL,
  prev_hash CHAR(64) NOT NULL,
  row_hash CHAR(64) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- 14. Secure API gateway - HMAC-signed requests, replay protection
-- ---------------------------------------------------------------
CREATE TABLE api_keys (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  label VARCHAR(100) NOT NULL,
  api_key VARCHAR(64) NOT NULL UNIQUE,     -- public identifier, sent as-is
  secret_ciphertext MEDIUMBLOB NOT NULL,   -- shared secret, encrypted at rest via the same module as #11 (AES-256-CBC + HMAC-SHA256)
  secret_iv BINARY(16) NOT NULL,
  secret_tag BINARY(32) NOT NULL,
  key_version INT UNSIGNED NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (key_version) REFERENCES encryption_keys(key_version)
) ENGINE=InnoDB;

CREATE TABLE api_nonces (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  api_key_id INT UNSIGNED NOT NULL,
  nonce VARCHAR(64) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_key_nonce (api_key_id, nonce),
  FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- Seed: roles, permissions, mapping
-- ---------------------------------------------------------------
INSERT INTO roles (name, description) VALUES
  ('admin', 'Full access: user/role management, audit log, encryption keys, API keys'),
  ('moderator', 'Can view uploads and audit log, cannot manage users/roles/keys'),
  ('user', 'Standard account: own uploads, own encrypted profile fields, API access');

INSERT INTO permissions (name, description) VALUES
  ('manage_users', 'Create/deactivate user accounts'),
  ('manage_roles', 'Assign roles to users'),
  ('view_admin_panel', 'Access the /admin section'),
  ('view_audit_log', 'Read the tamper-evident audit log'),
  ('view_waf_log', 'Read the WAF block log'),
  ('manage_uploads', 'View/delete any user''s uploads'),
  ('upload_files', 'Upload own files'),
  ('manage_encryption_keys', 'Rotate AES-256 data-at-rest keys'),
  ('view_encrypted_data', 'Decrypt and view own secure profile fields'),
  ('manage_api_keys', 'Create/revoke API gateway keys'),
  ('use_api', 'Call the HMAC-signed API gateway');

INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = 'admin';

INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id FROM roles r, permissions p
  WHERE r.name = 'moderator' AND p.name IN ('view_admin_panel','view_audit_log','view_waf_log','manage_uploads');

INSERT INTO role_permissions (role_id, permission_id)
  SELECT r.id, p.id FROM roles r, permissions p
  WHERE r.name = 'user' AND p.name IN ('upload_files','view_encrypted_data','use_api');

-- ---------------------------------------------------------------
-- v2 (20-feature round): auth hardening + new playgrounds
-- ---------------------------------------------------------------

-- 2. Remember-me
CREATE TABLE remember_tokens (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  selector VARCHAR(24) NOT NULL UNIQUE,
  validator_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 4. TOTP backup/recovery codes
CREATE TABLE totp_backup_codes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. New-device/new-IP login notice
CREATE TABLE user_known_ips (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_ip (user_id, ip_address),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 7. XSS playground
CREATE TABLE demo_comments (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  author_name VARCHAR(60) NOT NULL,
  body TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 8. CSRF playground
CREATE TABLE csrf_notes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  note VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 9. SQL injection playground
CREATE TABLE demo_products (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  price DECIMAL(10,2) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE demo_secret_notes (
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
CREATE TABLE demo_idor_notes (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  title VARCHAR(100) NOT NULL,
  body VARCHAR(255) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
