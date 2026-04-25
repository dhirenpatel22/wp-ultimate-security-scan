<?php
/**
 * Access control vulnerability checks.
 *
 * Detects missing or inadequate restrictions on authenticated actions:
 * unauthenticated REST API writes, application passwords, author enumeration,
 * unprotected login page, and AJAX handlers lacking nonce or capability checks.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Access_Control
 */
class WPUSS_Check_Access_Control extends WPUSS_Check_Base {

	/**
	 * Max file size to scan.
	 *
	 * @var int
	 */
	private $max_file_size;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Scan ID.
	 * @param WPUSS_Logger $logger  Logger.
	 */
	public function __construct( $scan_id, WPUSS_Logger $logger ) {
		parent::__construct( $scan_id, $logger );
		$settings            = (array) get_option( 'wpuss_settings', array() );
		$this->max_file_size = isset( $settings['max_scan_file_size'] )
			? (int) $settings['max_scan_file_size']
			: 2 * MB_IN_BYTES;
	}

	/** @return string */
	public function get_id() {
		return 'access_control';
	}

	/** @return string */
	public function get_label() {
		return __( 'Access Control', 'wp-ultimate-security-scan' );
	}

	/** @return array */
	public function get_steps() {
		return array(
			'rest_write',
			'app_passwords',
			'author_enum',
			'login_page',
			'scan_plugins',
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
			case 'rest_write':
				$this->check_rest_write();
				break;
			case 'app_passwords':
				$this->check_application_passwords();
				break;
			case 'author_enum':
				$this->check_author_enumeration();
				break;
			case 'login_page':
				$this->check_login_page();
				break;
			case 'scan_plugins':
				return $this->scan_plugins_for_auth( $cursor );
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Test whether the REST API rejects unauthenticated write requests.
	 *
	 * @return void
	 */
	private function check_rest_write() {
		$url      = rest_url( 'wp/v2/posts' );
		$response = wp_remote_post(
			$url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				'headers'   => array(
					'Content-Type' => 'application/json',
					'X-WPUSS-Scan' => '1',
				),
				'body'      => wp_json_encode(
					array(
						'title'   => 'WPUSS-scan-probe',
						'content' => '',
						'status'  => 'draft',
					)
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( in_array( $code, array( 200, 201 ), true ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'REST API allows unauthenticated content creation', 'wp-ultimate-security-scan' ),
				__( 'A POST to /wp-json/wp/v2/posts with no credentials returned 200/201. Attackers can create, edit, or delete content without a valid account.', 'wp-ultimate-security-scan' ),
				__( 'Audit plugins that modify REST API authentication. Ensure no code removes the authentication callbacks from REST endpoints.', 'wp-ultimate-security-scan' ),
				'/wp-json/wp/v2/posts'
			);

			// Attempt to clean up the accidental draft, best-effort.
			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( isset( $body['id'] ) ) {
				wp_delete_post( (int) $body['id'], true );
			}
		}
	}

	/**
	 * Audit Application Passwords usage.
	 *
	 * @return void
	 */
	private function check_application_passwords() {
		if ( ! function_exists( 'wp_is_application_passwords_available' ) ) {
			return;
		}
		if ( ! wp_is_application_passwords_available() ) {
			return;
		}

		$users_with_app_pw = get_users(
			array(
				'meta_key'     => '_application_passwords',
				'meta_compare' => 'EXISTS',
				'number'       => 20,
				'fields'       => array( 'ID', 'user_login', 'roles' ),
			)
		);

		if ( empty( $users_with_app_pw ) ) {
			return;
		}

		$admin_logins = array();
		foreach ( $users_with_app_pw as $u ) {
			if ( user_can( $u->ID, 'manage_options' ) ) {
				$admin_logins[] = $u->user_login;
			}
		}

		if ( ! empty( $admin_logins ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Administrator accounts have Application Passwords configured', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: comma-separated list of usernames */
					__( 'The following administrator accounts have application passwords: %s. Each app password is an independent credential — if leaked it grants full API access with no 2FA challenge.', 'wp-ultimate-security-scan' ),
					implode( ', ', $admin_logins )
				),
				__( 'Review and revoke unused application passwords via Users → Profile. Apply the principle of least privilege — avoid granting admin-level app passwords.', 'wp-ultimate-security-scan' ),
				'',
				array( 'admin_users' => $admin_logins )
			);
		} else {
			$logins = wp_list_pluck( $users_with_app_pw, 'user_login' );
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Application Passwords are active on user accounts', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: comma-separated list of usernames */
					__( 'Users with application passwords configured: %s. Review and revoke any that are unused or unrecognised.', 'wp-ultimate-security-scan' ),
					implode( ', ', $logins )
				),
				__( 'Audit application passwords in Users → Profile and remove any that are no longer needed.', 'wp-ultimate-security-scan' ),
				'',
				array( 'users' => $logins )
			);
		}
	}

	/**
	 * Check if the ?author=N redirect leaks usernames.
	 *
	 * @return void
	 */
	private function check_author_enumeration() {
		$url      = home_url( '/?author=1' );
		$response = wp_remote_head(
			$url,
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
				'headers'     => array( 'X-WPUSS-Scan' => '1' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code     = wp_remote_retrieve_response_code( $response );
		$location = wp_remote_retrieve_header( $response, 'location' );

		if ( in_array( $code, array( 301, 302 ), true ) && false !== strpos( (string) $location, '/author/' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Username exposed via author archive redirect', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: redirect URL */
					__( '/?author=1 redirects to %s, leaking a username to unauthenticated visitors and aiding brute-force targeting.', 'wp-ultimate-security-scan' ),
					$location
				),
				__( 'Redirect numeric author URLs to the homepage using a rewrite rule, or replace user display names with aliases distinct from login names.', 'wp-ultimate-security-scan' ),
				'/?author=1',
				array( 'redirect' => $location )
			);
		}
	}

	/**
	 * Check login page exposure and brute-force protection.
	 *
	 * @return void
	 */
	private function check_login_page() {
		$login_url = wp_login_url();
		$response  = wp_remote_get(
			$login_url,
			array(
				'timeout'     => 5,
				'redirection' => 3,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
				'headers'     => array( 'X-WPUSS-Scan' => '1' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return;
		}

		// Login page is accessible — check for recognised brute-force protection.
		$bf_plugins = array(
			'wordfence/wordfence.php',
			'better-wp-security/better-wp-security.php',
			'ithemes-security/ithemes-security.php',
			'loginizer/loginizer.php',
			'wp-cerber/wp-cerber.php',
			'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php',
			'wps-hide-login/wps-hide-login.php',
			'rename-wp-login/rename-wp-login.php',
			'solid-security-basic/solid-security-basic.php',
			'all-in-one-wp-security-and-firewall/wp-security.php',
		);

		$active_bf = false;
		foreach ( $bf_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$active_bf = true;
				break;
			}
		}

		if ( ! $active_bf ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Login page is publicly accessible without brute-force protection', 'wp-ultimate-security-scan' ),
				__( 'wp-login.php is reachable and no recognised login-protection plugin is active. Bots continuously run credential-stuffing attacks against WordPress login pages.', 'wp-ultimate-security-scan' ),
				__( 'Install a login-protection plugin (Limit Login Attempts Reloaded, Wordfence, etc.), add HTTP Basic Auth in front of wp-login.php, or move the login URL.', 'wp-ultimate-security-scan' ),
				$login_url
			);
		}

		// Check for 2FA plugin.
		$twofa_plugins = array(
			'two-factor/two-factor.php',
			'google-authenticator/google-authenticator.php',
			'wp-2fa/wp-2fa.php',
			'miniOrange-2-factor-authentication/miniorange_2_factor_authentication.php',
			'wordfence/wordfence.php',
		);

		$has_2fa = false;
		foreach ( $twofa_plugins as $plugin ) {
			if ( is_plugin_active( $plugin ) ) {
				$has_2fa = true;
				break;
			}
		}

		if ( ! $has_2fa ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_LOW,
				__( 'No two-factor authentication plugin detected', 'wp-ultimate-security-scan' ),
				__( 'No recognised 2FA plugin is active. Without a second factor, a stolen password is sufficient to compromise any account.', 'wp-ultimate-security-scan' ),
				__( 'Install a 2FA plugin (Two Factor, WP 2FA, Wordfence) and enforce it for all administrator accounts.', 'wp-ultimate-security-scan' )
			);
		}
	}

	/**
	 * Scan plugin PHP files for AJAX handlers without proper authorisation.
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function scan_plugins_for_auth( array $cursor ) {
		$root = WP_PLUGIN_DIR;
		if ( ! is_dir( $root ) ) {
			return array( 'continue' => false, 'cursor' => array() );
		}
		if ( empty( $cursor ) ) {
			$cursor = array( 'queue' => array( $root ), 'checked' => 0 );
		}

		$files_per_call = 25;
		$processed      = 0;

		while ( ! empty( $cursor['queue'] ) && $processed < $files_per_call ) {
			$current = array_shift( $cursor['queue'] );
			$handle  = @opendir( $current ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $handle ) {
				continue;
			}
			while ( false !== ( $entry = readdir( $handle ) ) && $processed < $files_per_call ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$full = $current . DIRECTORY_SEPARATOR . $entry;
				if ( false !== strpos( $full, 'wp-ultimate-security-scan' ) ) {
					continue;
				}
				if ( is_dir( $full ) ) {
					if ( in_array( $entry, array( 'node_modules', 'vendor', '.git' ), true ) ) {
						continue;
					}
					$cursor['queue'][] = $full;
				} elseif ( preg_match( '/\.php$/i', $entry ) ) {
					$this->scan_file_for_auth( $full );
					$processed++;
					$cursor['checked']++;
				}
			}
			closedir( $handle );
		}

		return array(
			'continue' => ! empty( $cursor['queue'] ),
			'cursor'   => $cursor,
		);
	}

	/**
	 * Check one file for AJAX / admin-page handlers lacking auth.
	 *
	 * @param string $path File path.
	 * @return void
	 */
	private function scan_file_for_auth( $path ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $this->max_file_size || 0 === $size ) {
			return;
		}
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents || '' === $contents ) {
			return;
		}

		// wp_ajax_nopriv_ hooks without any nonce verification in the same file.
		$nopriv_count = preg_match_all(
			"/add_action\s*\(\s*['\"]wp_ajax_nopriv_/i",
			$contents
		);
		if ( $nopriv_count > 0 ) {
			$has_nonce = (bool) preg_match( '/check_ajax_referer|wp_verify_nonce|check_admin_referer/i', $contents );
			if ( ! $has_nonce ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					__( 'Unauthenticated AJAX handler without nonce verification', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %d: number of hooks found */
						_n(
							'Found %d wp_ajax_nopriv_ hook in a file with no nonce checks. Unauthenticated AJAX handlers without CSRF protection can be exploited by any visitor.',
							'Found %d wp_ajax_nopriv_ hooks in a file with no nonce checks. Unauthenticated AJAX handlers without CSRF protection can be exploited by any visitor.',
							$nopriv_count,
							'wp-ultimate-security-scan'
						),
						$nopriv_count
					),
					__( 'Add check_ajax_referer() or wp_verify_nonce() to all AJAX handlers, including public ones, to prevent cross-site request forgery.', 'wp-ultimate-security-scan' ),
					$path
				);
			}
		}

		// wp_ajax_ (logged-in) hooks without capability or nonce check.
		$priv_count = preg_match_all(
			"/add_action\s*\(\s*['\"]wp_ajax_(?!nopriv_)/i",
			$contents
		);
		if ( $priv_count > 0 ) {
			$has_auth = (bool) preg_match( '/current_user_can|check_ajax_referer|wp_verify_nonce|check_admin_referer/i', $contents );
			if ( ! $has_auth ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_MEDIUM,
					__( 'Admin AJAX handler may lack capability or nonce check', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %d: number of hooks found */
						_n(
							'Found %d wp_ajax_ hook in a file with no current_user_can() or nonce check. Any logged-in user could trigger privileged actions.',
							'Found %d wp_ajax_ hooks in a file with no current_user_can() or nonce check. Any logged-in user could trigger privileged actions.',
							$priv_count,
							'wp-ultimate-security-scan'
						),
						$priv_count
					),
					__( 'Call current_user_can() with the required capability and use check_ajax_referer() or wp_verify_nonce() to prevent CSRF.', 'wp-ultimate-security-scan' ),
					$path
				);
			}
		}

		// Admin menu registration without a visible capability check in the callback.
		if ( preg_match( "/add_(?:menu|submenu)_page\s*\(/i", $contents ) ) {
			if ( ! preg_match( '/current_user_can\s*\(/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_MEDIUM,
					__( 'Admin page registered without a visible current_user_can() check', 'wp-ultimate-security-scan' ),
					__( 'add_menu_page() or add_submenu_page() found without current_user_can() in the page callback. The capability parameter in add_menu_page() only hides the menu item — it does not block direct URL access to the callback.', 'wp-ultimate-security-scan' ),
					__( 'Add current_user_can( \'manage_options\' ) (or the required capability) at the top of every admin page callback and call wp_die() if it returns false.', 'wp-ultimate-security-scan' ),
					$path
				);
			}
		}
	}
}
