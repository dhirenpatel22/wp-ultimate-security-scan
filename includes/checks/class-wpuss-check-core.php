<?php
/**
 * WordPress core configuration checks.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Core
 */
class WPUSS_Check_Core extends WPUSS_Check_Base {

	/**
	 * Check ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'core';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'WordPress Core', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array(
			'version',
			'constants',
			'salts',
			'debug',
			'prefix',
			'ssl',
			'xmlrpc',
			'rest_enum',
		);
	}

	/**
	 * Run a step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'version':
				$this->check_version();
				break;
			case 'constants':
				$this->check_constants();
				break;
			case 'salts':
				$this->check_salts();
				break;
			case 'debug':
				$this->check_debug();
				break;
			case 'prefix':
				$this->check_table_prefix();
				break;
			case 'ssl':
				$this->check_ssl();
				break;
			case 'xmlrpc':
				$this->check_xmlrpc();
				break;
			case 'rest_enum':
				$this->check_rest_user_enum();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * WordPress version freshness.
	 *
	 * @return void
	 */
	private function check_version() {
		global $wp_version;

		$update = get_site_transient( 'update_core' );
		if ( $update && isset( $update->updates ) && is_array( $update->updates ) ) {
			foreach ( $update->updates as $u ) {
				if ( isset( $u->response ) && 'upgrade' === $u->response ) {
					$this->finding(
						WPUSS_Logger::SEVERITY_HIGH,
						__( 'WordPress core is out of date', 'wp-ultimate-security-scan' ),
						sprintf(
							/* translators: 1: current version, 2: new version */
							__( 'You are running WordPress %1$s; version %2$s is available.', 'wp-ultimate-security-scan' ),
							$wp_version,
							isset( $u->current ) ? $u->current : 'latest'
						),
						__( 'Back up your site and update WordPress core from Dashboard → Updates.', 'wp-ultimate-security-scan' ),
						'wordpress-core'
					);
					return;
				}
			}
		}

		$this->finding(
			WPUSS_Logger::SEVERITY_INFO,
			__( 'WordPress core is up to date', 'wp-ultimate-security-scan' ),
			sprintf(
				/* translators: %s: version string */
				__( 'Running WordPress %s.', 'wp-ultimate-security-scan' ),
				$wp_version
			)
		);
	}

	/**
	 * Hardening constants.
	 *
	 * @return void
	 */
	private function check_constants() {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Theme/plugin file editor is enabled', 'wp-ultimate-security-scan' ),
				__( 'The built-in editor lets administrators run arbitrary PHP from the dashboard. If an admin account is compromised, the entire site can be backdoored.', 'wp-ultimate-security-scan' ),
				__( "Add to wp-config.php: define('DISALLOW_FILE_EDIT', true);", 'wp-ultimate-security-scan' ),
				'wp-config.php'
			);
		}

		if ( ! defined( 'DISALLOW_FILE_MODS' ) || ! DISALLOW_FILE_MODS ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_LOW,
				__( 'File modifications from the dashboard are allowed', 'wp-ultimate-security-scan' ),
				__( 'DISALLOW_FILE_MODS is not set. Consider disabling plugin/theme installation and updates via the dashboard in strict environments.', 'wp-ultimate-security-scan' ),
				__( "Add to wp-config.php: define('DISALLOW_FILE_MODS', true); — note this also blocks automatic updates.", 'wp-ultimate-security-scan' ),
				'wp-config.php'
			);
		}

		if ( ! defined( 'FORCE_SSL_ADMIN' ) || ! FORCE_SSL_ADMIN ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'FORCE_SSL_ADMIN is not enabled', 'wp-ultimate-security-scan' ),
				__( 'Admin logins and cookies can be sent over HTTP without this constant.', 'wp-ultimate-security-scan' ),
				__( "Add to wp-config.php: define('FORCE_SSL_ADMIN', true);", 'wp-ultimate-security-scan' ),
				'wp-config.php'
			);
		}

		if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Automatic updates are fully disabled', 'wp-ultimate-security-scan' ),
				__( 'Automatic minor/security updates are disabled. Unpatched vulnerabilities will stay unpatched.', 'wp-ultimate-security-scan' ),
				__( 'Remove or set AUTOMATIC_UPDATER_DISABLED to false, or ensure a reliable manual update process.', 'wp-ultimate-security-scan' )
			);
		}
	}

	/**
	 * Auth salts sanity check.
	 *
	 * @return void
	 */
	private function check_salts() {
		$keys = array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);

		$bad = array();
		foreach ( $keys as $k ) {
			if ( ! defined( $k ) ) {
				$bad[] = $k . ' (missing)';
				continue;
			}
			$v = constant( $k );
			if ( ! is_string( $v ) || strlen( $v ) < 40 || false !== stripos( $v, 'put your unique phrase here' ) ) {
				$bad[] = $k . ' (weak/placeholder)';
			}
		}

		if ( $bad ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'Weak or missing authentication salts', 'wp-ultimate-security-scan' ),
				__( 'One or more AUTH/NONCE keys in wp-config.php are missing, short, or still set to their placeholder value. An attacker who learns a weak salt may forge cookies.', 'wp-ultimate-security-scan' ),
				__( 'Replace with fresh values from https://api.wordpress.org/secret-key/1.1/salt/ . Existing users will have to log in again.', 'wp-ultimate-security-scan' ),
				'wp-config.php',
				array( 'failed_keys' => $bad )
			);
		}
	}

	/**
	 * Debug mode checks.
	 *
	 * @return void
	 */
	private function check_debug() {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$display = defined( 'WP_DEBUG_DISPLAY' ) ? WP_DEBUG_DISPLAY : true;
			if ( $display ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					__( 'WP_DEBUG is enabled and errors are displayed', 'wp-ultimate-security-scan' ),
					__( 'Error messages leak path and software version information to visitors and attackers.', 'wp-ultimate-security-scan' ),
					__( 'In production, set WP_DEBUG to false, or at minimum set WP_DEBUG_DISPLAY to false and log to a file with WP_DEBUG_LOG.', 'wp-ultimate-security-scan' ),
					'wp-config.php'
				);
			} else {
				$this->finding(
					WPUSS_Logger::SEVERITY_LOW,
					__( 'WP_DEBUG is enabled (errors hidden)', 'wp-ultimate-security-scan' ),
					__( 'Debug logging is on. If debug.log is inside wp-content and not blocked by the webserver, it may be publicly readable.', 'wp-ultimate-security-scan' ),
					__( 'Disable WP_DEBUG in production and make sure debug.log is not accessible via HTTP.', 'wp-ultimate-security-scan' )
				);
			}
		}
	}

	/**
	 * Default table prefix detection.
	 *
	 * @return void
	 */
	private function check_table_prefix() {
		global $wpdb;
		if ( 'wp_' === $wpdb->prefix ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_LOW,
				__( "Default database prefix 'wp_' in use", 'wp-ultimate-security-scan' ),
				__( 'Using the default prefix is not itself a vulnerability, but can make blind SQL injection exploitation marginally easier.', 'wp-ultimate-security-scan' ),
				__( 'This change requires renaming tables and updating wp-config.php — only undertake it with a tested migration plan.', 'wp-ultimate-security-scan' )
			);
		}
	}

	/**
	 * SSL configuration.
	 *
	 * @return void
	 */
	private function check_ssl() {
		$home    = get_home_url();
		$siteurl = get_site_url();
		if ( 0 !== stripos( $home, 'https://' ) || 0 !== stripos( $siteurl, 'https://' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Site URL is not HTTPS', 'wp-ultimate-security-scan' ),
				__( 'The home or site URL is configured over HTTP. Traffic, including login credentials, can be intercepted.', 'wp-ultimate-security-scan' ),
				__( 'Install a TLS certificate and update Settings → General to use https:// for both URLs.', 'wp-ultimate-security-scan' )
			);
		}
	}

	/**
	 * XML-RPC exposure.
	 *
	 * @return void
	 */
	private function check_xmlrpc() {
		if ( apply_filters( 'xmlrpc_enabled', true ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'XML-RPC is enabled', 'wp-ultimate-security-scan' ),
				__( 'XML-RPC is commonly abused for password brute-force (system.multicall) and pingback-based DDoS. If you do not use Jetpack, the mobile app, or XML-RPC-based clients, disable it.', 'wp-ultimate-security-scan' ),
				__( "Add to functions.php or a mu-plugin: add_filter('xmlrpc_enabled', '__return_false'); or block /xmlrpc.php at the webserver.", 'wp-ultimate-security-scan' ),
				'/xmlrpc.php'
			);
		}
	}

	/**
	 * REST API user enumeration.
	 *
	 * @return void
	 */
	private function check_rest_user_enum() {
		// Unauthenticated request to /wp/v2/users — does it return usernames?
		$url      = rest_url( 'wp/v2/users' );
		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		if ( 200 === $code && $body ) {
			$decoded = json_decode( $body, true );
			if ( is_array( $decoded ) && ! empty( $decoded ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_MEDIUM,
					__( 'REST API exposes user list to unauthenticated requests', 'wp-ultimate-security-scan' ),
					__( 'GET /wp/v2/users returns usernames without authentication, aiding targeted brute-force attempts.', 'wp-ultimate-security-scan' ),
					__( "Restrict the endpoint with a rest_authentication_errors filter, or require authentication via the rest_user_query filter.", 'wp-ultimate-security-scan' ),
					'/wp-json/wp/v2/users'
				);
			}
		}
	}
}
