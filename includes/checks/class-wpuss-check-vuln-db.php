<?php
/**
 * Vulnerability database check.
 *
 * Compares installed plugin and theme versions against:
 *  1. WPScan API (https://wpscan.com) — when an API key is configured in
 *     Settings, provides up-to-date CVE data for every installed plugin/theme.
 *  2. Built-in curated list — covers the most commonly-exploited plugins with
 *     known critical CVEs. Used as a fallback when no API key is set, and as
 *     an instant check even before the API responds.
 *
 * WPScan free tier: 25 requests/day. Results are cached in transients (24h)
 * to stay well within the limit.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Vuln_DB
 */
class WPUSS_Check_Vuln_DB extends WPUSS_Check_Base {

	/**
	 * WPScan API base URL.
	 */
	const WPSCAN_API = 'https://wpscan.com/api/v3/';

	/**
	 * Transient TTL for WPScan responses (seconds).
	 */
	const CACHE_TTL = DAY_IN_SECONDS;

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Scan ID.
	 * @param WPUSS_Logger $logger  Logger.
	 */
	public function __construct( $scan_id, WPUSS_Logger $logger ) {
		parent::__construct( $scan_id, $logger );
		$this->settings = (array) get_option( 'wpuss_settings', array() );
	}

	/** @return string */
	public function get_id() {
		return 'vuln_db';
	}

	/** @return string */
	public function get_label() {
		return __( 'Vulnerability Database', 'wp-ultimate-security-scan' );
	}

	/** @return array */
	public function get_steps() {
		return array( 'check_plugins', 'check_themes' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( 'check_plugins' === $step ) {
			$this->check_plugins();
		} elseif ( 'check_themes' === $step ) {
			$this->check_themes();
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	// -----------------------------------------------------------------------
	// Plugin checks
	// -----------------------------------------------------------------------

	/**
	 * Check all installed plugins against known CVE data.
	 *
	 * @return void
	 */
	private function check_plugins() {
		$installed = get_plugins();
		if ( empty( $installed ) ) {
			return;
		}

		$api_key = $this->get_api_key();

		foreach ( $installed as $plugin_file => $plugin_data ) {
			$slug    = $this->plugin_slug( $plugin_file );
			$version = $plugin_data['Version'];
			$name    = $plugin_data['Name'];

			if ( ! $slug || ! $version ) {
				continue;
			}

			// Try WPScan API first (when key available).
			if ( $api_key ) {
				$this->check_via_wpscan_api( 'plugins', $slug, $version, $name, $plugin_file );
			}

			// Always run the built-in list — it catches issues instantly.
			$this->check_built_in_list( $slug, $version, $name, $plugin_file );
		}
	}

	/**
	 * Check active themes against known CVE data.
	 *
	 * @return void
	 */
	private function check_themes() {
		$themes = array();

		$active = wp_get_theme();
		if ( $active && $active->exists() ) {
			$themes[ $active->get_stylesheet() ] = $active;
		}
		$parent = $active ? $active->parent() : null;
		if ( $parent && $parent->exists() ) {
			$themes[ $parent->get_stylesheet() ] = $parent;
		}

		if ( empty( $themes ) ) {
			return;
		}

		$api_key = $this->get_api_key();

		foreach ( $themes as $slug => $theme ) {
			$version = $theme->get( 'Version' );
			$name    = $theme->get( 'Name' );

			if ( ! $version ) {
				continue;
			}

			if ( $api_key ) {
				$this->check_via_wpscan_api( 'themes', $slug, $version, $name, $slug );
			}
		}
	}

	// -----------------------------------------------------------------------
	// WPScan API
	// -----------------------------------------------------------------------

	/**
	 * Query WPScan API and flag any unresolved CVEs for the installed version.
	 *
	 * @param string $type        'plugins' or 'themes'.
	 * @param string $slug        Plugin/theme slug.
	 * @param string $version     Installed version.
	 * @param string $name        Display name.
	 * @param string $target      Finding target (plugin file path or slug).
	 * @return void
	 */
	private function check_via_wpscan_api( $type, $slug, $version, $name, $target ) {
		$api_key = $this->get_api_key();
		if ( ! $api_key ) {
			return;
		}

		$cache_key = 'wpuss_wpscan_' . md5( $type . $slug );
		$data      = get_transient( $cache_key );

		if ( false === $data ) {
			$url      = self::WPSCAN_API . $type . '/' . rawurlencode( $slug );
			$response = wp_remote_get(
				$url,
				array(
					'timeout' => 8,
					'headers' => array(
						'Authorization' => 'Token token=' . $api_key,
						'User-Agent'    => 'wp-ultimate-security-scan/' . WPUSS_VERSION,
					),
				)
			);

			if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
				// Cache negative result briefly to avoid hammering on transient failure.
				set_transient( $cache_key, array(), 600 );
				return;
			}

			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			$data = is_array( $body ) ? $body : array();
			set_transient( $cache_key, $data, self::CACHE_TTL );
		}

		if ( empty( $data ) ) {
			return;
		}

		// WPScan response structure: { slug: { vulnerabilities: [...] } }.
		$slug_data = isset( $data[ $slug ] ) ? $data[ $slug ] : array();
		$vulns     = isset( $slug_data['vulnerabilities'] ) ? (array) $slug_data['vulnerabilities'] : array();

		foreach ( $vulns as $vuln ) {
			$fixed_in = isset( $vuln['fixed_in'] ) ? $vuln['fixed_in'] : null;

			// If fixed_in is set and installed version >= fixed_in, the vulnerability is patched.
			if ( $fixed_in && version_compare( $version, $fixed_in, '>=' ) ) {
				continue;
			}

			$vuln_title = isset( $vuln['title'] ) ? $vuln['title'] : __( 'Unknown vulnerability', 'wp-ultimate-security-scan' );
			$cve_ids    = array();
			if ( ! empty( $vuln['references']['cve'] ) ) {
				foreach ( (array) $vuln['references']['cve'] as $cve ) {
					$cve_ids[] = 'CVE-' . $cve;
				}
			}

			$severity = $this->wpscan_cvss_to_severity(
				isset( $vuln['cvss']['score'] ) ? (float) $vuln['cvss']['score'] : 0.0
			);

			$desc = sprintf(
				/* translators: 1: plugin name, 2: installed version, 3: fix version or 'unknown' */
				__( '%1$s version %2$s is affected. %3$s', 'wp-ultimate-security-scan' ),
				$name,
				$version,
				$fixed_in
					? sprintf( __( 'Fixed in version %s.', 'wp-ultimate-security-scan' ), $fixed_in )
					: __( 'No fix version known — check the plugin/theme page for updates.', 'wp-ultimate-security-scan' )
			);

			$rec = $fixed_in
				? sprintf(
					/* translators: %s: fix version */
					__( 'Update to version %s or later immediately.', 'wp-ultimate-security-scan' ),
					$fixed_in
				)
				: __( 'Deactivate and remove this plugin/theme until a fix is available.', 'wp-ultimate-security-scan' );

			$this->finding(
				$severity,
				sprintf(
					/* translators: 1: plugin name, 2: CVE ID(s) or vulnerability title */
					__( '[WPScan] %1$s — %2$s', 'wp-ultimate-security-scan' ),
					$name,
					! empty( $cve_ids ) ? implode( ', ', $cve_ids ) : $vuln_title
				),
				$desc,
				$rec,
				$target,
				array(
					'vuln_title'  => $vuln_title,
					'fixed_in'    => $fixed_in,
					'cves'        => $cve_ids,
					'installed'   => $version,
					'source'      => 'wpscan',
				)
			);
		}
	}

	/**
	 * Map a CVSS score to a WPUSS severity level.
	 *
	 * @param float $score CVSS score (0-10).
	 * @return string
	 */
	private function wpscan_cvss_to_severity( $score ) {
		if ( $score >= 9.0 ) {
			return WPUSS_Logger::SEVERITY_CRITICAL;
		}
		if ( $score >= 7.0 ) {
			return WPUSS_Logger::SEVERITY_HIGH;
		}
		if ( $score >= 4.0 ) {
			return WPUSS_Logger::SEVERITY_MEDIUM;
		}
		if ( $score > 0.0 ) {
			return WPUSS_Logger::SEVERITY_LOW;
		}
		return WPUSS_Logger::SEVERITY_HIGH; // Unknown score — default to HIGH.
	}

	// -----------------------------------------------------------------------
	// Built-in CVE list
	// -----------------------------------------------------------------------

	/**
	 * Check a plugin against the built-in curated vulnerability list.
	 *
	 * The list covers plugins with critical CVE history. Each entry specifies
	 * the minimum safe version (fixed_in). If the installed version is below
	 * that, we flag it.
	 *
	 * This list is intentionally conservative: only critical/high CVEs where
	 * a widely-deployed, non-patched version is a realistic risk.
	 *
	 * @param string $slug    Plugin slug (directory name).
	 * @param string $version Installed version string.
	 * @param string $name    Plugin display name.
	 * @param string $target  Plugin file path for the finding target.
	 * @return void
	 */
	private function check_built_in_list( $slug, $version, $name, $target ) {
		$db = $this->get_built_in_vuln_db();

		if ( ! isset( $db[ $slug ] ) ) {
			return;
		}

		foreach ( $db[ $slug ] as $vuln ) {
			// Skip if installed version >= fixed version.
			if ( version_compare( $version, $vuln['fixed_in'], '>=' ) ) {
				continue;
			}

			$cve_str = ! empty( $vuln['cve'] ) ? ' (' . $vuln['cve'] . ')' : '';

			$this->finding(
				$vuln['severity'],
				sprintf(
					/* translators: 1: plugin name, 2: vulnerability type */
					__( '%1$s — %2$s (installed version is vulnerable)', 'wp-ultimate-security-scan' ),
					$name,
					$vuln['type'] . $cve_str
				),
				sprintf(
					/* translators: 1: plugin name, 2: installed version, 3: fixed version */
					__( '%1$s version %2$s is affected by a known security vulnerability. The fix was released in version %3$s.', 'wp-ultimate-security-scan' ),
					$name,
					$version,
					$vuln['fixed_in']
				),
				sprintf(
					/* translators: %s: fixed version */
					__( 'Update %s immediately via Dashboard → Plugins → Updates.', 'wp-ultimate-security-scan' ),
					$name
				),
				$target,
				array(
					'vuln_type'  => $vuln['type'],
					'cve'        => $vuln['cve'] ?? '',
					'installed'  => $version,
					'fixed_in'   => $vuln['fixed_in'],
					'source'     => 'built-in',
				)
			);
		}
	}

	/**
	 * Curated list of high-impact plugin CVEs.
	 *
	 * Format: slug => [ [ type, cve, fixed_in, severity ], ... ]
	 *
	 * @return array
	 */
	private function get_built_in_vuln_db() {
		return array(

			// Formidable Forms — PHP Object Injection (unauthenticated)
			'formidable' => array(
				array(
					'type'     => __( 'Unauthenticated PHP Object Injection', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-3681',
					'fixed_in' => '6.3',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
				array(
					'type'     => __( 'SQL Injection (subscriber+)', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-2087',
					'fixed_in' => '6.2',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// Elementor — Authenticated RCE / Stored XSS
			'elementor'  => array(
				array(
					'type'     => __( 'Authenticated Remote Code Execution', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2022-29455',
					'fixed_in' => '3.6.3',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// WooCommerce — SQL Injection / unauthenticated arbitrary options
			'woocommerce' => array(
				array(
					'type'     => __( 'SQL Injection (unauthenticated)', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-28121',
					'fixed_in' => '7.8.2',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
				array(
					'type'     => __( 'Arbitrary File Deletion (subscriber+)', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2021-32789',
					'fixed_in' => '5.5.1',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// Contact Form 7 — Unrestricted File Upload
			'contact-form-7' => array(
				array(
					'type'     => __( 'Unrestricted File Upload leading to RCE', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2020-35489',
					'fixed_in' => '5.3.2',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// Duplicator — Unauthenticated Arbitrary File Read
			'duplicator' => array(
				array(
					'type'     => __( 'Unauthenticated Arbitrary File Read', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2020-11738',
					'fixed_in' => '1.3.28',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// File Manager (wp-file-manager) — Unauthenticated RCE
			'wp-file-manager' => array(
				array(
					'type'     => __( 'Unauthenticated Remote Code Execution', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2020-25213',
					'fixed_in' => '6.9',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// WP GDPR Compliance — Privilege Escalation (unauthenticated)
			'wp-gdpr-compliance' => array(
				array(
					'type'     => __( 'Unauthenticated Privilege Escalation', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2018-19207',
					'fixed_in' => '1.4.3',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// ThemeGrill Demo Importer — Unauthenticated DB Wipe
			'themegrill-demo-importer' => array(
				array(
					'type'     => __( 'Unauthenticated Database Reset / Admin Takeover', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2020-8772',
					'fixed_in' => '1.6.3',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// Ninja Forms — Unauthenticated Code Injection
			'ninja-forms' => array(
				array(
					'type'     => __( 'Unauthenticated Code Injection', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2022-34867',
					'fixed_in' => '3.6.11',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// WPForms — Insecure Direct Object Reference (subscriber+)
			'wpforms-lite' => array(
				array(
					'type'     => __( 'Insecure Direct Object Reference', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-2732',
					'fixed_in' => '1.8.2.2',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// All-in-One WP Migration — Unauthenticated Sensitive Data Exposure
			'all-in-one-wp-migration' => array(
				array(
					'type'     => __( 'Unauthenticated Sensitive Data Exposure', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-40004',
					'fixed_in' => '7.80',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// Yoast SEO — Stored XSS (contributor+)
			'wordpress-seo' => array(
				array(
					'type'     => __( 'Stored Cross-Site Scripting (contributor+)', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-1999',
					'fixed_in' => '20.2.1',
					'severity' => WPUSS_Logger::SEVERITY_MEDIUM,
				),
			),

			// WP Fastest Cache — Unauthenticated SQL Injection
			'wp-fastest-cache' => array(
				array(
					'type'     => __( 'Unauthenticated SQL Injection', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-6063',
					'fixed_in' => '1.2.2',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// Essential Addons for Elementor — Unauthenticated Privilege Escalation
			'essential-addons-for-elementor-lite' => array(
				array(
					'type'     => __( 'Unauthenticated Privilege Escalation', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-32243',
					'fixed_in' => '5.7.2',
					'severity' => WPUSS_Logger::SEVERITY_CRITICAL,
				),
			),

			// Advanced Custom Fields — Reflected XSS (subscriber+)
			'advanced-custom-fields' => array(
				array(
					'type'     => __( 'Reflected Cross-Site Scripting (subscriber+)', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-30777',
					'fixed_in' => '6.1.6',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),
			'advanced-custom-fields-pro' => array(
				array(
					'type'     => __( 'Reflected Cross-Site Scripting (subscriber+)', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-30777',
					'fixed_in' => '6.1.6',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// Jetpack — Multiple vulnerabilities (various versions)
			'jetpack' => array(
				array(
					'type'     => __( 'Stored XSS / Content Injection', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2023-2996',
					'fixed_in' => '12.1.1',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// Download Manager — Unauthenticated Sensitive Data Exposure
			'download-manager' => array(
				array(
					'type'     => __( 'Unauthenticated Sensitive Data Exposure', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2021-3553',
					'fixed_in' => '3.1.25',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// WP Statistics — SQL Injection (subscriber+)
			'wp-statistics' => array(
				array(
					'type'     => __( 'SQL Injection (subscriber+)', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2022-25148',
					'fixed_in' => '13.1.6',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),

			// BackWPup — Unauthenticated SSRF / Data Disclosure
			'backwpup' => array(
				array(
					'type'     => __( 'Unauthenticated Directory Traversal', 'wp-ultimate-security-scan' ),
					'cve'      => 'CVE-2022-0432',
					'fixed_in' => '3.8.8',
					'severity' => WPUSS_Logger::SEVERITY_HIGH,
				),
			),
		);
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/**
	 * Extract the plugin slug (directory name) from a plugin file path.
	 *
	 * @param string $plugin_file e.g. 'formidable/formidable.php'.
	 * @return string Slug (directory part only), or '' for single-file plugins.
	 */
	private function plugin_slug( $plugin_file ) {
		$parts = explode( '/', $plugin_file );
		return count( $parts ) > 1 ? $parts[0] : '';
	}

	/**
	 * Retrieve the configured WPScan API key.
	 *
	 * @return string Empty string if not configured.
	 */
	private function get_api_key() {
		return isset( $this->settings['wpscan_api_key'] )
			? (string) $this->settings['wpscan_api_key']
			: '';
	}
}
