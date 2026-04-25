<?php
/**
 * Vulnerable and Outdated Components checks.
 *
 * Assesses the patch level of core infrastructure components: database server
 * version (MySQL/MariaDB EOL), WordPress known-CVE version windows, HSTS
 * enforcement, and plugins with a high historical CVE count.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Components
 */
class WPUSS_Check_Components extends WPUSS_Check_Base {

	/** @return string */
	public function get_id() {
		return 'components';
	}

	/** @return string */
	public function get_label() {
		return __( 'Vulnerable & Outdated Components', 'wp-ultimate-security-scan' );
	}

	/** @return array */
	public function get_steps() {
		return array(
			'database_version',
			'wp_vuln_ranges',
			'high_risk_plugins',
			'http_redirect',
		);
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'database_version':
				$this->check_database_version();
				break;
			case 'wp_vuln_ranges':
				$this->check_wp_vuln_ranges();
				break;
			case 'high_risk_plugins':
				$this->check_high_risk_plugins();
				break;
			case 'http_redirect':
				$this->check_http_to_https_redirect();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Check MySQL / MariaDB version against EOL dates.
	 *
	 * @return void
	 */
	private function check_database_version() {
		global $wpdb;

		$full_version = $wpdb->get_var( 'SELECT VERSION()' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( ! $full_version ) {
			return;
		}

		$is_mariadb = ( false !== stripos( $full_version, 'mariadb' ) );

		if ( $is_mariadb ) {
			// Extract numeric version from e.g. "10.11.5-MariaDB".
			preg_match( '/(\d+)\.(\d+)\.(\d+)/i', $full_version, $m );
			$major = isset( $m[1] ) ? (int) $m[1] : 0;
			$minor = isset( $m[2] ) ? (int) $m[2] : 0;
			$ver   = isset( $m[0] ) ? $m[0] : $full_version;

			// MariaDB supported: 10.6 LTS (Jul 2026), 10.11 LTS (Feb 2028), 11.4 LTS (May 2029).
			// 10.7-10.10 went EOL May-Nov 2023; 11.0-11.3 went EOL Jun 2024-Mar 2025.
			if ( $major < 10 ) {
				$is_eol = true;
			} elseif ( 10 === $major ) {
				$is_eol = ! in_array( $minor, array( 6, 11 ), true );
			} elseif ( 11 === $major ) {
				$is_eol = ( $minor < 4 );
			} else {
				$is_eol = false; // 12.x and later — assume supported.
			}

			if ( $is_eol ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					__( 'MariaDB version is end-of-life', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: MariaDB version */
						__( 'MariaDB %s no longer receives security patches. Known CVEs will remain permanently unpatched.', 'wp-ultimate-security-scan' ),
						$ver
					),
					__( 'Upgrade to MariaDB 10.11 LTS or 11.x. Contact your hosting provider or upgrade via your database control panel.', 'wp-ultimate-security-scan' ),
					'database',
					array( 'version' => $ver, 'engine' => 'MariaDB' )
				);
			} else {
				$this->finding(
					WPUSS_Logger::SEVERITY_INFO,
					sprintf(
						/* translators: %s: MariaDB version */
						__( 'MariaDB %s is a supported version', 'wp-ultimate-security-scan' ),
						$ver
					),
					'',
					'',
					'database',
					array( 'version' => $ver, 'engine' => 'MariaDB' )
				);
			}
		} else {
			// MySQL EOL: 5.5 Dec 2018, 5.6 Feb 2021, 5.7 Oct 2023, 8.0 active, 8.4 LTS active.
			preg_match( '/(\d+)\.(\d+)\.(\d+)/i', $full_version, $m );
			$major = isset( $m[1] ) ? (int) $m[1] : 0;
			$ver   = isset( $m[0] ) ? $m[0] : $wpdb->db_version();

			if ( $major < 8 ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					__( 'MySQL version is end-of-life', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: MySQL version */
						__( 'MySQL %s no longer receives security patches. Known CVEs will remain permanently unpatched.', 'wp-ultimate-security-scan' ),
						$ver
					),
					__( 'Upgrade to MySQL 8.0 or 8.4 LTS. Contact your hosting provider.', 'wp-ultimate-security-scan' ),
					'database',
					array( 'version' => $ver, 'engine' => 'MySQL' )
				);
			} else {
				$this->finding(
					WPUSS_Logger::SEVERITY_INFO,
					sprintf(
						/* translators: %s: MySQL version */
						__( 'MySQL %s is a supported version', 'wp-ultimate-security-scan' ),
						$ver
					),
					'',
					'',
					'database',
					array( 'version' => $ver, 'engine' => 'MySQL' )
				);
			}
		}
	}

	/**
	 * Flag WordPress version ranges with critical known CVEs.
	 *
	 * This supplements the core check that flags available updates — it
	 * specifically calls out versions with publicly-documented RCE/auth-bypass CVEs.
	 *
	 * @return void
	 */
	private function check_wp_vuln_ranges() {
		global $wp_version;

		$version_float = (float) $wp_version;

		if ( $version_float < 4.7 ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'WordPress version contains critical publicly-known CVEs', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: WordPress version */
					__( 'WordPress %s is within a version range that includes unauthenticated remote code execution CVEs (e.g. CVE-2017-1000600). These are actively exploited in the wild.', 'wp-ultimate-security-scan' ),
					$wp_version
				),
				__( 'Update WordPress immediately via Dashboard → Updates. Back up your database and files first.', 'wp-ultimate-security-scan' ),
				'wordpress-core',
				array( 'version' => $wp_version )
			);
			return;
		}

		if ( $version_float < 5.0 ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'WordPress version is significantly out of date with known high-severity CVEs', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: WordPress version */
					__( 'WordPress %s is well below the current major version and within a range with multiple documented high-severity vulnerabilities.', 'wp-ultimate-security-scan' ),
					$wp_version
				),
				__( 'Update WordPress via Dashboard → Updates.', 'wp-ultimate-security-scan' ),
				'wordpress-core',
				array( 'version' => $wp_version )
			);
		}
		// Current update availability is already reported by WPUSS_Check_Core.
	}

	/**
	 * Flag installed plugins that historically have high CVE counts.
	 *
	 * This is not about whether they are currently vulnerable — it is a
	 * signal to watch these plugins extra-carefully and keep them updated.
	 *
	 * @return void
	 */
	private function check_high_risk_plugins() {
		$high_cve_history = array(
			'contact-form-7/wp-contact-form-7.php'                            => 'Contact Form 7',
			'woocommerce/woocommerce.php'                                      => 'WooCommerce',
			'wp-fastest-cache/wpFastestCache.php'                             => 'WP Fastest Cache',
			'duplicator/duplicator.php'                                        => 'Duplicator',
			'all-in-one-wp-migration/all-in-one-wp-migration.php'             => 'All-in-One WP Migration',
			'wp-file-manager/file_folder_manager.php'                         => 'File Manager',
			'essential-addons-for-elementor-lite/essential_adons_elementor.php' => 'Essential Addons for Elementor',
			'download-manager/download-manager.php'                           => 'WP Download Manager',
			'newsletter/plugin.php'                                            => 'Newsletter',
			'ninja-forms/ninja-forms.php'                                     => 'Ninja Forms',
		);

		$installed = get_plugins();
		$flagged   = array();

		foreach ( $high_cve_history as $slug => $name ) {
			if ( isset( $installed[ $slug ] ) ) {
				$flagged[] = sprintf( '%s v%s', $name, $installed[ $slug ]['Version'] );
			}
		}

		if ( ! empty( $flagged ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Plugins with high historical CVE count detected', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: comma-separated list of plugin names and versions */
					__( 'The following installed plugins have historically had critical security vulnerabilities and are common attack targets: %s. Keeping them updated and monitoring security advisories is essential.', 'wp-ultimate-security-scan' ),
					implode( ', ', $flagged )
				),
				__( 'Ensure these plugins are fully updated. Subscribe to WPScan (wpscan.com) or Patchstack advisories to receive early notification of new CVEs.', 'wp-ultimate-security-scan' ),
				'',
				array( 'plugins' => $flagged )
			);
		}
	}

	/**
	 * Verify that HTTP requests are redirected to HTTPS.
	 *
	 * @return void
	 */
	private function check_http_to_https_redirect() {
		$site_url = get_site_url();
		if ( 0 !== stripos( $site_url, 'https://' ) ) {
			return; // Site not on HTTPS — WPUSS_Check_Core already flags this.
		}

		$http_url = 'http://' . preg_replace( '/^https:\/\//i', '', $site_url ) . '/';

		$response = wp_remote_head(
			$http_url,
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'sslverify'   => false,
				'headers'     => array( 'X-WPUSS-Scan' => '1' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code     = wp_remote_retrieve_response_code( $response );
		$location = wp_remote_retrieve_header( $response, 'location' );

		$redirects_to_https = (
			in_array( $code, array( 301, 302, 307, 308 ), true ) &&
			0 === stripos( (string) $location, 'https://' )
		);

		if ( ! $redirects_to_https ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'HTTP requests are not redirected to HTTPS', 'wp-ultimate-security-scan' ),
				__( 'The site uses HTTPS but plain HTTP requests are not automatically redirected. Visitors who type the address without "https://" will have an unencrypted connection.', 'wp-ultimate-security-scan' ),
				__( 'Add a permanent HTTP-to-HTTPS redirect in your webserver config (.htaccess RewriteRule for Apache, return 301 for Nginx). This is separate from FORCE_SSL_ADMIN.', 'wp-ultimate-security-scan' ),
				$http_url
			);
		} elseif ( 301 !== $code ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_LOW,
				__( 'HTTP-to-HTTPS redirect uses a non-permanent status code', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'The HTTP-to-HTTPS redirect uses a %d (temporary) status code instead of 301. Browsers will not cache it and search engines will not pass full link equity.', 'wp-ultimate-security-scan' ),
					$code
				),
				__( 'Change the redirect to a 301 Permanent in your webserver configuration.', 'wp-ultimate-security-scan' ),
				$http_url
			);
		}
	}
}
