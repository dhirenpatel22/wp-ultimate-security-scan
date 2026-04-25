# WordPress Ultimate Security Scan

A deep, read-only security scanner for WordPress that audits **core, users, filesystem, plugins, themes, code patterns, HTTP headers, injection vulnerabilities, access control, SSRF, and the database** — and does it without hogging your server.

## Why another security plugin?

Most WP security plugins either:

- Run synchronously and freeze admin for a minute while they thrash your CPU, or
- Run as a background service that you can't pause, tune, or see progress on.

This one is built differently:

- **CPU-throttled.** Every unit of work is followed by a proportional sleep. At the default 20% limit, the scanner sleeps 4× longer than it works.
- **Chunked over AJAX.** Work is broken into tiny pieces the browser drives via AJAX. No request is ever long-running.
- **Resumable.** Scan state lives in `wp_options`. Reload the tab, come back tomorrow — it picks up where it left off.
- **Focus-aware.** If you switch tabs, the scan pauses. When you come back, it resumes. Your server never gets pounded in the background.
- **Read-only.** The scanner never writes to your files, users, or options (only to its own findings table).

## What it checks

| Area | What's inspected |
|---|---|
| **Core config** | WP version, hardening constants (`DISALLOW_FILE_EDIT`, `FORCE_SSL_ADMIN`, etc.), salts, `WP_DEBUG`, table prefix, HTTPS, XML-RPC, REST user enumeration |
| **Core integrity** | Every core file MD5-verified against `api.wordpress.org` checksums; flags modified files and unknown files inside `wp-admin` / `wp-includes` |
| **Users** | Default `admin` account, admin count, weak/legacy password hashes, empty passwords, display-name/login leak, recently-created admins |
| **Filesystem** | `wp-config.php` permissions, world-writable directories, `readme.html` exposure, PHP files in `uploads/`, backup artefacts (`.bak`, `.sql`), directory listing |
| **Plugins** | Pending updates, inactive plugins, missing PluginURI/UpdateURI, abandoned plugins |
| **Themes** | Pending updates, extra inactive themes, default-theme fallback |
| **Code patterns** | `eval(base64_decode(...))` backdoors, `shell_exec` / `passthru` / `proc_open` / `popen` / `system`, include/require on superglobals, missing `ABSPATH` guards, unprepared `$wpdb` queries, unescaped `echo` of superglobals, `file_put_contents()` on user input, long base64 payloads |
| **HTTP headers** | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Strict-Transport-Security`, WP generator meta leak, brute-force throttle plugin presence |
| **Database** | Open registration with `administrator` default role, `siteurl` vs `home` host mismatch, recently-created administrator accounts |
| **Injection** | PHP object injection (direct + multi-line taint tracking + co-occurrence heuristics), variable-variable injection, `extract()` on superglobals, `create_function()`, `preg_replace()` `/e` modifier, `call_user_func()` on user input, SQL injection via `sprintf`/`$wpdb`, XSS via `printf`/`echo`, LDAP injection, XXE, PHP `register_globals`/`allow_url_include` |
| **Access control** | Unauthenticated REST API write probe, Application Passwords on admin accounts, username exposure via `?author=` redirect, login page brute-force and 2FA plugin detection, AJAX handlers without nonce/capability checks, admin pages without `current_user_can()` |
| **Security misconfiguration** | PHP EOL version (7.x → Critical, 8.0 → High, 8.1 → Medium, 8.2 → Low), server/PHP version disclosure in response headers, publicly accessible `.env` / `.git/config` / `debug.log` / `phpinfo.php`, WP-Cron HTTP vs server cron, cookie security (`FORCE_SSL_ADMIN`, `COOKIE_DOMAIN`), PHP dangerous functions (`exec`, `shell_exec`, etc.) |
| **SSRF** | `wp_remote_*()` / `file_get_contents()` / `cURL` / `fsockopen()` called with user-controlled URLs, open redirects via `wp_redirect()` / `header(Location:)`, oEmbed REST proxy exposure, pingback, `allow_url_fopen` |
| **Vulnerable components** | MySQL/MariaDB EOL detection, WordPress version ranges with critical known CVEs, plugins with high historical CVE counts, HTTP-to-HTTPS redirect verification |
| **Vulnerability database** | WPScan API integration (optional key, 25 req/day, 24 h cache) for every installed plugin and theme; built-in curated CVE list for 18+ commonly-exploited plugins |

Findings are grouped by severity: **Critical / High / Medium / Low / Info**.

## Installation

### From a zip

1. Download `wp-ultimate-security-scan.zip`.
2. In WP admin, go to **Plugins → Add New → Upload Plugin**.
3. Choose the zip and click **Install Now**, then **Activate**.

### Manually via SFTP

1. Unzip the archive.
2. Upload the `wp-ultimate-security-scan/` folder to `wp-content/plugins/`.
3. Activate from the **Plugins** screen.

## Usage

1. Open **Security Scan** in the admin sidebar.
2. Optionally visit **Security Scan → Settings** and adjust:
   - **Max CPU usage** (default 20%)
   - **Chunk time budget** (default 2 s per AJAX chunk)
   - **Skip files larger than N MB** (default 2 MB)
   - **Pause when tab is hidden** (default on)
   - **WPScan API Key** (optional — enables live CVE lookups for every installed plugin and theme)
3. Click **Start Scan**.
4. When complete, visit **Security Scan → Last Report** for findings grouped by severity.

## How the throttle works

After every unit of work the scanner computes:

```
sleep_seconds = work_seconds × (100 − cpu_limit) / cpu_limit   (capped at 2s)
```

So at `cpu_limit = 20`, it sleeps `work_seconds × 4`. Combined with AJAX chunking, the scan stays well under ~20% of one CPU core.

## How focus-lock works

The admin JS listens for `window.blur`, `window.focus`, and `visibilitychange`. When the scan tab is no longer the active tab:

1. JS calls `wpuss_pause` — the server stops doing work.
2. A friendly banner appears on the page. The document title changes to `⏸ Scan paused — come back!` so you see it in the tab bar.
3. On focus return, JS calls `wpuss_resume` and the scan continues from where it stopped.

You can disable this in **Settings → Pause when tab is hidden** if you prefer the scan to continue in the background.

## Security posture of the plugin itself

- `ABSPATH` guard on every PHP file.
- Every AJAX handler and admin page: `current_user_can('manage_options')` + nonce verification.
- All input passed through `wp_unslash()` + appropriate sanitize function.
- All queries use `$wpdb->prepare()`; schema built via `dbDelta()`.
- All output escaped (`esc_html`, `esc_attr`, `esc_url`, `wp_kses_post`).
- Singleton with `__clone` / `__wakeup` guards.
- Autoloader scoped to the `WPUSS_` prefix.
- `X-WPUSS-Scan` header on self-probes so the scanner can't loop on its own HTTP check.
- `uninstall.php` removes the findings table, options, transients, and cron events cleanly.

## File layout

```
wp-ultimate-security-scan/
├── wp-ultimate-security-scan.php          # bootstrap, constants, autoloader
├── uninstall.php                          # clean DB on plugin delete
├── readme.txt                             # WP.org-style readme
├── README.md                              # this file
├── includes/
│   ├── class-wpuss-core.php               # singleton controller, activation hooks
│   ├── class-wpuss-scanner.php            # chunked scan engine + resumable state
│   ├── class-wpuss-throttle.php           # CPU sleep logic
│   ├── class-wpuss-logger.php             # findings persistence
│   ├── class-wpuss-ajax.php               # AJAX endpoints
│   ├── class-wpuss-admin.php              # menus, enqueue, settings save
│   └── checks/                            # one file per check module
│       ├── class-wpuss-check-base.php
│       ├── class-wpuss-check-core.php
│       ├── class-wpuss-check-core-integrity.php
│       ├── class-wpuss-check-users.php
│       ├── class-wpuss-check-database.php
│       ├── class-wpuss-check-filesystem.php
│       ├── class-wpuss-check-plugins.php
│       ├── class-wpuss-check-themes.php
│       ├── class-wpuss-check-config.php
│       ├── class-wpuss-check-code-patterns.php
│       ├── class-wpuss-check-injection.php
│       ├── class-wpuss-check-access-control.php
│       ├── class-wpuss-check-security-config.php
│       ├── class-wpuss-check-ssrf.php
│       ├── class-wpuss-check-components.php
│       └── class-wpuss-check-vuln-db.php
├── admin/
│   ├── views/                             # scan.php, report.php, settings.php
│   ├── js/admin.js
│   └── css/admin.css
└── languages/
    └── wp-ultimate-security-scan.pot
```

## Requirements

- WordPress 5.8+
- PHP 7.4+
- The core integrity and access-control checks call external URLs (`api.wordpress.org`, your own site); outbound HTTPS is required for those checks.
- The WPScan API key feature requires outbound HTTPS to `wpscan.com` (optional).

## License

GPL-2.0-or-later. See `readme.txt` for the full license notice.
