=== WordPress Ultimate Security Scan ===
Contributors: dhirenpatel
Tags: security, scanner, malware, hardening, audit
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

CPU-throttled WordPress security scanner: audits core integrity, users, plugins, themes, code patterns, filesystem, database and headers.

== Description ==

**WordPress Ultimate Security Scan** performs a deep, read-only audit of your entire WordPress site and produces a prioritised report of security issues grouped by severity (Critical / High / Medium / Low / Info).

Unlike scanners that lock up your server, this plugin is designed to be a polite neighbour:

* Scans run in small AJAX chunks with an adjustable CPU throttle (default: 20%).
* The scanner sleeps proportionally between units of work so other requests on your site stay responsive.
* Focus-lock: if the user navigates away from the scan tab, the scan automatically pauses and resumes when they return.
* State is persisted in `wp_options`, so the scan survives a page reload without losing progress.

**What it checks**

* **Core** — WP version freshness, hardening constants (`DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`, `FORCE_SSL_ADMIN`, `AUTOMATIC_UPDATER_DISABLED`), auth salts, `WP_DEBUG`/`WP_DEBUG_DISPLAY`, table prefix, HTTPS, XML-RPC, REST user enumeration.
* **Core integrity** — MD5-verifies every shipped WordPress file against the official `api.wordpress.org` checksums for your exact version & locale, and flags any unknown `.php` files sitting inside `wp-admin/` or `wp-includes/`.
* **Users** — default `admin` account, admin count, insecure password hashes, empty passwords, display-name/login leak, recently-created admins.
* **Filesystem** — `wp-config.php` permissions, world-writable directories, exposed `readme.html`, PHP files in `uploads/`, backup files (`.bak`, `.sql`), directory listing.
* **Plugins** — pending updates, inactive plugins, missing PluginURI/UpdateURI, abandoned plugins.
* **Themes** — pending updates, extra inactive themes, default-theme fallback.
* **Code patterns** — `eval` + `base64_decode`/`gzinflate` backdoors, dangerous exec calls (`shell_exec`, `passthru`, etc.), include/require on superglobals, missing `ABSPATH` guards, unprepared `$wpdb` queries, unescaped echo of superglobals, `file_put_contents` on user input, long base64 payloads.
* **HTTP config** — security headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS), WP generator meta leak, presence of a login brute-force throttle plugin.
* **Database** — open registration with administrator default role, `siteurl` vs `home` host mismatch, recently-created administrator accounts.
* **Injection vulnerabilities** — PHP object injection (direct + multi-line taint tracking), variable-variable injection, `extract()` on superglobals, `create_function()`, `preg_replace()` `/e` modifier, `call_user_func()` on user input, SQL injection via `sprintf`/`$wpdb`, XSS via `printf`/`echo`, LDAP injection, XXE, co-occurrence heuristics (unauthenticated AJAX + deserialization), PHP `register_globals`/`allow_url_include`.
* **Access control** — unauthenticated REST API write test, Application Passwords on admin accounts, username exposure via author archive, login page brute-force protection, two-factor authentication plugin, AJAX handlers without nonce or capability checks, admin pages without `current_user_can()`.
* **Security misconfiguration** — PHP EOL version check, server/PHP version disclosure in response headers, publicly-accessible sensitive files (`.env`, `.git/config`, `debug.log`, `phpinfo.php`), WP-Cron HTTP vs server cron, cookie security (`FORCE_SSL_ADMIN`, `COOKIE_DOMAIN`), PHP dangerous functions (`exec`, `shell_exec`, etc.).
* **SSRF** — `wp_remote_*()` / `file_get_contents()` / `cURL` / `fsockopen()` called with user-controlled URL, open redirects (`wp_redirect()`, `header(Location:)`), oEmbed REST proxy exposure, pingbacks, `allow_url_fopen`.
* **Vulnerable & outdated components** — MySQL/MariaDB EOL version, WordPress version ranges with critical known CVEs, plugins with a high historical CVE count, HTTP-to-HTTPS redirect check.
* **Vulnerability database** — queries the WPScan API (optional API key) for up-to-date CVE data on every installed plugin and theme; falls back to a built-in curated list covering 18+ commonly-exploited plugins.

== Third-Party Services ==

This plugin communicates with the following external services **only while a scan is actively running**. No data is sent on regular page loads.

= WordPress.org Core Checksums API =

During the Core Integrity check the plugin fetches the official MD5 checksums for your exact WordPress version and locale from `api.wordpress.org`. The only data sent is your WordPress version number and site locale (e.g. `en_US`). No personal data, usernames, or site URLs are transmitted.

* Service: https://api.wordpress.org/core/checksums/1.0/
* Privacy policy: https://automattic.com/privacy/

= WPScan Vulnerability Database (optional) =

If you enter a WPScan API key in Settings, the Vulnerability Database check sends the slug and version number of each installed plugin and theme to `wpscan.com` to retrieve known CVE data. This feature is **disabled by default** and requires you to explicitly provide an API key. Free tier: 25 requests/day; results are cached for 24 hours.

* Service: https://wpscan.com/api/v3/
* Privacy policy: https://wpscan.com/privacy
* Terms of service: https://wpscan.com/terms-and-conditions

== Installation ==

1. Upload the `wp-ultimate-security-scan` folder to `/wp-content/plugins/`, or install the zip via **Plugins → Add New → Upload Plugin**.
2. Activate the plugin.
3. Navigate to **Security Scan** in the admin menu.
4. Review settings (CPU limit, chunk size, max file size, focus-lock, optional WPScan API key) and click **Start Scan**.

== Frequently Asked Questions ==

= Will this slow down my site? =
The scanner is CPU-throttled. At the default 20% setting it sleeps four times longer than it works after each unit. You can lower this further from the Settings tab.

= Why does the scan pause when I switch tabs? =
Because the scan runs via AJAX driven by the browser, leaving the tab without focus-lock would either stall the scan or let it run unthrottled. Focus-lock keeps the user informed and server load predictable. You can disable it in Settings.

= Does it modify my site? =
No. The scanner is strictly read-only. It never writes to your files, modifies options, or changes user accounts. The only data it writes is its own findings table and scan state.

= Where is the report? =
Under **Security Scan → Last Report**. Findings are grouped by severity.

= What is the WPScan API key for? =
When you enter a WPScan API key in Settings, the Vulnerability Database check queries wpscan.com for up-to-date CVE data on every installed plugin and theme. The free tier allows 25 requests/day; results are cached for 24 hours to stay well within the limit. Without a key, only the built-in curated CVE list is used.

== Changelog ==

= 1.2.0 =
* New: Injection vulnerability scanner — PHP object injection (direct + multi-line taint tracking + co-occurrence heuristics), variable-variable injection, `extract()` on superglobals, SQL/XSS/LDAP/XXE patterns, `create_function()`, `preg_replace()` `/e` modifier, PHP `register_globals`/`allow_url_include` checks.
* New: Access control scanner — unauthenticated REST API write probe, Application Passwords audit, author enumeration, login page brute-force and 2FA detection, AJAX handler nonce/capability analysis.
* New: Security misconfiguration scanner — PHP EOL version check (7.x → Critical, 8.0 → High, 8.1 → Medium, 8.2 → Low), server/PHP version disclosure, sensitive file exposure (`.env`, `.git/config`, `debug.log`, `phpinfo.php`), WP-Cron configuration, cookie security, PHP dangerous function availability.
* New: SSRF scanner — `wp_remote_*()` / `file_get_contents()` / `cURL` / `fsockopen()` with user-controlled URLs, open redirects, oEmbed REST proxy, pingback, `allow_url_fopen`.
* New: Vulnerable & outdated components — MySQL/MariaDB EOL detection, WordPress CVE version ranges, high-risk plugin flag list, HTTP-to-HTTPS redirect verification.
* New: Vulnerability database — WPScan API integration (optional) + built-in curated CVE list covering 18+ commonly-exploited plugins with critical CVE history.
* Fixed: MariaDB EOL detection now correctly flags versions 10.7–10.10 (all EOL 2023) and 11.x below 11.4 LTS (EOL 2024–2025).
* Fixed: PHP 8.2 now flagged as EOL (Low severity; went EOL December 2025).

= 1.1.0 =
* New: WordPress core integrity check — MD5-verifies every shipped core file against `api.wordpress.org` checksums and flags modified files and unknown `.php` files inside `wp-admin/` and `wp-includes/`.
* Improved: "Skip files larger than" setting now accepts a value in **MB** (1–20) instead of raw bytes.
* Improved: Friendly, more noticeable popup/banner explains that leaving the tab will pause the scan — plus the browser tab title updates to `⏸ Scan paused — come back!` so you can see it from other tabs.
* Added: GitHub-style `README.md` with a full architecture overview.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.2.0 =
Adds six major new check modules: injection vulnerabilities, access control, security misconfiguration, SSRF, vulnerable components, and a vulnerability database with WPScan API integration.

= 1.1.0 =
Adds WordPress core file integrity verification and friendlier focus-lock messaging.

= 1.0.0 =
Initial release.
