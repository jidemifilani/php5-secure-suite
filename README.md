# PHP5 Secure Suite

Thirty security modules (10 original + a 20-feature expansion round) built
and running on a **real PHP 5.6.40** interpreter (the final PHP 5 release,
EOL Jan 2019) with MySQL/MariaDB. No framework - plain PHP, PDO, prepared
statements throughout.

This is a separate, standalone project - not part of the [Iris Security
Lab](../security-labs) project, which runs on PHP 8.2.

Also on GitHub: **https://github.com/jidemifilani/php5-secure-suite**

## Modules

| # | Module | Where |
|---|---|---|
| Foundation | Register/login/logout, bcrypt password hashing | `app/auth.php`, `public/{register,login,logout}.php` |
| 5 | RBAC admin panel, session-based permissions | `app/rbac.php`, `public/admin/*` |
| 6 | Secure file upload | `app/upload.php`, `public/upload.php`, `public/download.php` |
| 7 | TOTP 2FA (hand-rolled RFC 6238) | `app/totp.php`, `public/2fa-setup.php`, `public/2fa-verify.php` |
| 8 | Password reset (signed, single-use, time-limited) | `app/password_reset.php`, `public/forgot-password.php`, `public/reset-password.php` |
| 9 | Session hijacking demo + fix | `app/session_security.php` (real fix, used everywhere), `public/session-hijack-demo.php` (isolated demo) |
| 10 | Rate limiter / brute-force protection | `app/rate_limit.php`, applied in `login.php`, `2fa-verify.php`, `forgot-password.php`, `public/api/*` |
| 11 | Encrypted data-at-rest + key rotation | `app/crypto.php`, `public/profile.php`, `public/admin/encryption.php` |
| 12 | WAF lite | `app/waf.php`, `public/waf-demo.php`, `public/admin/waf-log.php` |
| 13 | Tamper-evident audit log | `app/audit.php`, `public/admin/audit-log.php` |
| 14 | Secure API gateway (HMAC-signed) | `app/api_auth.php`, `public/api/{ping,echo}.php`, `public/admin/api-keys.php` |

### 20-feature expansion round

| # | Module | Where |
|---|---|---|
| 1 | Account lockout (persistent, distinct from rate limiting) | `account_lock_remaining_seconds()`/`register_failed_login()` in `app/auth.php`, used in `public/login.php` |
| 2 | Remember-me (selector/validator, rotates every use) | `app/remember.php` |
| 3 | Password strength meter + common-password rejection | `app/password_strength.php`, used in `public/register.php` and `public/reset-password.php` |
| 4 | 2FA backup/recovery codes | added to `app/totp.php`, generated/shown in `public/2fa-setup.php`, redeemed in `public/2fa-verify.php` |
| 5 | New-device/new-IP login notice | `check_and_record_known_ip()` in `app/auth.php`, banner in `public/dashboard.php` |
| 6 | Math CAPTCHA gate after repeated login failures | `public/login.php` (session-tracked, separate from the DB-backed lockout/rate-limit) |
| 7 | XSS playground | `public/xss-playground.php` |
| 8 | CSRF playground (live forged-request demo) | `public/csrf-playground.php` |
| 9 | SQL injection playground | `public/sqli-playground.php`, `public/sqli-reset.php` |
| 10 | IDOR playground | `public/idor-playground.php`, `public/idor-view.php` |
| 11 | Open redirect playground | `is_safe_relative_redirect()` in `app/functions.php`, `public/redirect-playground.php`, `public/go-{vulnerable,patched}.php` |
| 12 | OS command injection playground (contained) | `public/cmd-playground.php` |
| 13 | Insecure deserialization playground | `app/demo_gadget.php`, `public/deserialize-playground.php` |
| 14 | Clickjacking demo | `public/clickjacking-demo.php`, `public/clickjacking-target.php` |
| 15 | Site-wide security headers (CSP+nonce, HSTS, etc.) | `app/security_headers.php`, applied in `app/bootstrap.php` |
| 16 | Cookie/session security inspector | `public/session-inspector.php` |
| 17 | IP allowlist for `/admin` | `app/admin_guard.php`, called from every `public/admin/*.php` |
| 18 | Upload integrity verification (SHA-256) | added to `app/upload.php` (`upload_store()`) and `public/download.php` |
| 19 | `security.txt` + disclosure page | `public/.well-known/security.txt`, `public/security-disclosure.php` |
| 20 | Security checklist capstone | `public/security-checklist.php` |

## Architecture

```
php5-secure-suite/
  public/       <- web root (only this is ever served)
  app/          <- all PHP logic, outside the web root
  storage/      <- uploads/, keys/, logs/ - outside the web root
  database/     <- schema.sql
  router.php    <- clean-URL router for PHP's built-in server
  start-server.bat
```

`storage/` and `app/` are **physical siblings of `public/`, not
subdirectories of it** - the primary way this runs (PHP's own built-in
server, see below) can only ever serve files under `public/`, so uploaded
files and encryption keys are unreachable by any URL, not just blocked by
`.htaccess` rules.

## Why a whole separate PHP runtime

This machine's XAMPP install only had PHP 8.2. Since the requirement was
*real* PHP 5, not just PHP-5-style code running on a newer interpreter, a
genuine PHP 5.6.40 build was installed side by side:

- Runtime: `C:\xampp\php56\` (official Windows build from
  `windows.php.net/downloads/releases/archives/`)
- Required installing the **Visual C++ 2012 (VC11) redistributable**
  system-wide - this build needs it and this machine only had VC++ 2022.
  Reversible via Windows "Programs and Features" if ever needed.
- `php.ini` (copied from `php.ini-production`) has `mysqli`, `pdo_mysql`,
  `openssl`, `fileinfo`, `mbstring`, `curl` enabled.
- MySQL/MariaDB is the **existing** XAMPP MariaDB service (already running
  for the other projects on this machine) - a database server has no PHP
  version dependency, so it's shared. Database: `php5_secure_suite`.

## Running it

```
start-server.bat
```

This runs `C:\xampp\php56\php.exe -S 0.0.0.0:8050 -t public router.php`.
Open **http://localhost:8050/**. MariaDB must already be running (XAMPP
Control Panel, or it's likely already running for the other local sites).

The app owns its own port/origin - it is **not** served through XAMPP's
Apache (which is wired to PHP 8.2), so nothing here touches the other
XAMPP sites.

To make the first admin account: register normally through the site, then
grant the `admin` role directly once:

```sql
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r WHERE u.username='yourname' AND r.name='admin';
```

Roles/permissions are **session-based** (cached at login) - after running
that, use the "Refresh my permissions" button on the dashboard rather than
waiting for next login.

### Re-verifying after changes

```
php tests\smoke-test.php http://127.0.0.1:8050
```
(Uses the system PHP - any version works, it's just an HTTP client. Server
must already be running.) 20 checks covering both rounds. Creates and
cleans up its own throwaway test users; database is otherwise left exactly
as it found it. Note: `/register` and `/login` both redirect to
`/dashboard` if the script's session is already logged in - the script
logs out explicitly wherever a check needs a fresh anonymous session (a
real bug caught in this script itself the first time the v2 checks were
added, not an app bug).

`database/upgrade_v2.sql` is the additive migration for the 20-feature
round (safe to re-run); it's also folded into the master `schema.sql` for
fresh installs, same convention as `upgrade_v2.sql` on this machine's
other PHP project.

## Real PHP 5.6 gotchas hit while building this

- **`openssl_encrypt()` has no `$tag` parameter on PHP 5.6.** The plan was
  AES-256-GCM; the confirmed-live error was *"openssl_encrypt() expects at
  most 5 parameters, 6 given"*. That parameter (needed to retrieve a GCM/AEAD
  auth tag) was added in **PHP 7.1**, not 5.6 as commonly misremembered -
  `openssl_get_cipher_methods()` still *lists* `aes-256-gcm` on 5.6, which is
  what makes this trap easy to miss until it's actually exercised. Item 11
  uses **AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)** instead - a real,
  secure, PHP-5.6-native authenticated-encryption construction, with the
  encryption key and MAC key independently derived (via HMAC) from one
  stored master key per version. See `app/crypto.php`.
- **No `random_bytes()`/`random_int()`** (PHP 7.0+). Every CSPRNG use in
  this project goes through `openssl_random_pseudo_bytes()`
  (`app/functions.php:random_token_bytes()`).
- **No native cookie `SameSite` support** (added in PHP 7.3's options-array
  signature for `setcookie()`/`session_set_cookie_params()`). Worked around
  using the documented legacy trick of appending `; SameSite=Lax` onto the
  cookie `path` argument, which PHP <7.3 writes into the `Set-Cookie` header
  without validating - see `app/session_security.php`.
- **`define()` cannot hold an array** (array constants arrived in PHP 7.0).
  Config values that are lists (upload extension/MIME whitelists) are
  stored `serialize()`d into a string constant and `unserialize()`d where
  used - see `app/config.php` / `app/upload.php`.
- **`password_hash()`/`password_verify()`** (PHP 5.5+) and **`hash_equals()`**
  (added in exactly PHP 5.6.0) are both available and used throughout for
  timing-safe comparisons (CSRF tokens, reset-token validators, HMAC
  signatures) - these are not gaps, just worth noting as the reason this
  project doesn't need to hand-roll constant-time comparison itself.
- PHP 5.6's built-in dev server has no `.htaccess`/mod_rewrite - clean URLs
  (`/login` instead of `/login.php`) are handled by `router.php` instead;
  `public/.htaccess` exists only for the (secondary, unused-by-default)
  case of pointing real Apache at `public/` later.
- **No immediately-invoked function expressions.** `(function () { ... })();`
  - valid on PHP 7+ - is a hard parse error on this real 5.6.40 build
  (*"syntax error, unexpected '('"*), confirmed live while building the
  deserialization playground. Assign the closure to a variable first, or
  (as done here) just use a named function.

### A real interaction between two of these features

The WAF (item 12) globally inspects `$_GET`/the URL by design (see its own
scope note above) - which meant a GET-based search box for the SQLi
playground (item 9) would have the WAF block its own UNION-injection demo
payload before the vulnerable query ever ran. Fixed by making the SQLi
playground's search a POST form instead of GET, which is outside the WAF's
documented global-scan scope - the two features now coexist exactly as
each was already designed, no special-case exemption needed on either
side. If you add a new playground whose payloads look like other attack
signatures, prefer POST for the same reason.

## Known scope boundaries (by design, not oversight)

- No mail server is configured. The password-reset link is shown directly
  on the page after a request, labeled as a local-demo shortcut - a real
  deployment would only ever email it.
- `RATE_LIMIT_*`, `SESSION_IDLE_TIMEOUT`, `UPLOAD_MAX_BYTES`, etc. are in
  `app/config.php`.
- The WAF (item 12) inspects the URL/query string globally (near-zero false
  positive risk) and inspects arbitrary text on demand via `waf-demo.php`;
  it does **not** globally scan POST bodies, since real form fields on this
  site (passwords, free text) can legitimately contain characters that
  overlap with the attack signatures.
- API keys (item 14) are standalone machine credentials, not tied to a
  user account - `manage_api_keys` (an admin/RBAC permission) controls who
  can issue/revoke them, but the HMAC signature itself is what authenticates
  each API request, independent of any browser session.
