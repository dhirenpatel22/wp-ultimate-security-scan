<?php
/**
 * HTTP configuration & security header checks.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Config
 */
class WPUSS_Check_Config extends WPUSS_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'config';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'HTTP Configuration', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'headers', 'version_disclosure', 'login_throttle' );
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
			case 'headers':
				$this->check_headers();
				break;
			case 'version_disclosure':
				$this->check_version_disclosure();
				break;
			case 'login_throttle':
				$this->check_login_throttle();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * HTTP response headers.
	 *
	 * @return void
	 */
	private function check_headers() {
		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				'headers'   => array( 'X-WPUSS-Scan' => '1' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return;
		}

		$headers_object = wp_remote_retrieve_headers( $response );
		$headers        = array();
		if ( is_object( $headers_object ) && method_exists( $headers_object, 'getAll' ) ) {
			$headers = $headers_object->getAll();
		} elseif ( is_array( $headers_object ) ) {
			$headers = $headers_object;
		}
		// Normalize keys to lowercase.
		$lower = array();
		foreach ( $headers as $k => $v ) {
			$lower[ strtolower( $k ) ] = $v;
		}

		$checks = array(
			'x-frame-options'         => array(
				'severity' => WPUSS_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'X-Frame-Options header not set', 'wp-ultimate-security-scan' ),
				'desc'     => __( 'Without this header the site can be iframed by third parties — clickjacking risk.', 'wp-ultimate-security-scan' ),
				'rec'      => __( "Send 'X-Frame-Options: SAMEORIGIN' or set a Content-Security-Policy frame-ancestors directive.", 'wp-ultimate-security-scan' ),
			),
			'x-content-type-options'  => array(
				'severity' => WPUSS_Logger::SEVERITY_LOW,
				'title'    => __( 'X-Content-Type-Options header not set', 'wp-ultimate-security-scan' ),
				'desc'     => __( 'Browsers may MIME-sniff responses, which enables certain XSS vectors.', 'wp-ultimate-security-scan' ),
				'rec'      => __( "Send 'X-Content-Type-Options: nosniff'.", 'wp-ultimate-security-scan' ),
			),
			'referrer-policy'         => array(
				'severity' => WPUSS_Logger::SEVERITY_LOW,
				'title'    => __( 'Referrer-Policy header not set', 'wp-ultimate-security-scan' ),
				'desc'     => __( 'Full URLs may leak in the Referer header to third-party sites.', 'wp-ultimate-security-scan' ),
				'rec'      => __( "Send 'Referrer-Policy: strict-origin-when-cross-origin'.", 'wp-ultimate-security-scan' ),
			),
			'strict-transport-security' => array(
				'severity' => WPUSS_Logger::SEVERITY_MEDIUM,
				'title'    => __( 'HSTS (Strict-Transport-Security) not set', 'wp-ultimate-security-scan' ),
				'desc'     => __( 'Without HSTS, first-visit downgrade attacks are possible even when HTTPS is deployed.', 'wp-ultimate-security-scan' ),
				'rec'      => __( "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (after confirming full HTTPS).", 'wp-ultimate-security-scan' ),
			),
		);

		foreach ( $checks as $header_name => $info ) {
			if ( ! isset( $lower[ $header_name ] ) ) {
				$this->finding( $info['severity'], $info['title'], $info['desc'], $info['rec'], $header_name );
			}
		}
	}

	/**
	 * WordPress version leaked in HTML (generator meta).
	 *
	 * @return void
	 */
	private function check_version_disclosure() {
		$response = wp_remote_get(
			home_url( '/' ),
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return;
		}
		$body = wp_remote_retrieve_body( $response );
		if ( $body && preg_match( '/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+[\d.]+/i', $body ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_LOW,
				__( 'WordPress version disclosed in HTML meta', 'wp-ultimate-security-scan' ),
				__( 'The generator meta tag reveals the exact WP version to visitors and automated vulnerability scanners.', 'wp-ultimate-security-scan' ),
				__( "Add to functions.php or an mu-plugin: remove_action('wp_head', 'wp_generator');", 'wp-ultimate-security-scan' )
			);
		}
	}

	/**
	 * Login throttle presence (heuristic — is there a plugin or known constant?).
	 *
	 * @return void
	 */
	private function check_login_throttle() {
		$known_throttlers = array(
			'wordfence/wordfence.php',
			'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php',
			'all-in-one-wp-security-and-firewall/wp-security.php',
			'wps-limit-login/wps-limit-login.php',
			'ithemes-security-pro/ithemes-security-pro.php',
			'better-wp-security/better-wp-security.php',
		);
		$active = (array) get_option( 'active_plugins', array() );
		foreach ( $known_throttlers as $p ) {
			if ( in_array( $p, $active, true ) ) {
				return;
			}
		}
		$this->finding(
			WPUSS_Logger::SEVERITY_MEDIUM,
			__( 'No login brute-force throttling plugin detected', 'wp-ultimate-security-scan' ),
			__( 'WordPress by default accepts unlimited login attempts. Automated credential-stuffing attacks are ubiquitous.', 'wp-ultimate-security-scan' ),
			__( 'Install a login-limiting plugin or enforce throttling at the webserver / WAF.', 'wp-ultimate-security-scan' )
		);
	}
}
