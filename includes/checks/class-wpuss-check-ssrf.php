<?php
/**
 * Server-Side Request Forgery (SSRF) checks.
 *
 * Scans plugin and theme PHP files for HTTP request patterns where
 * user-controlled data can influence the target URL (wp_remote_*, cURL,
 * file_get_contents, fsockopen), and checks WordPress features that expose
 * SSRF-prone functionality (oEmbed proxy, pingbacks, open redirects).
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_SSRF
 */
class WPUSS_Check_SSRF extends WPUSS_Check_Base {

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
		return 'ssrf';
	}

	/** @return string */
	public function get_label() {
		return __( 'Server-Side Request Forgery (SSRF)', 'wp-ultimate-security-scan' );
	}

	/** @return array */
	public function get_steps() {
		return array( 'scan_plugins', 'scan_themes', 'wp_features' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( 'scan_plugins' === $step ) {
			return $this->scan_tree( WP_PLUGIN_DIR, $cursor );
		}
		if ( 'scan_themes' === $step ) {
			return $this->scan_tree( get_theme_root(), $cursor );
		}
		if ( 'wp_features' === $step ) {
			$this->check_wp_ssrf_features();
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Walk a directory tree resumably, 25 files per call.
	 *
	 * @param string $root   Root directory.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	private function scan_tree( $root, array $cursor ) {
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
					$this->scan_file( $full );
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
	 * Inspect one file for SSRF code patterns.
	 *
	 * @param string $path File path.
	 * @return void
	 */
	private function scan_file( $path ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $this->max_file_size || 0 === $size ) {
			return;
		}
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents || '' === $contents ) {
			return;
		}

		// WordPress HTTP API with user-controlled URL.
		if ( preg_match( '/\bwp_remote_(?:get|post|request|head)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'SSRF: wp_remote_*() called with user-controlled URL', 'wp-ultimate-security-scan' ),
				__( 'The WordPress HTTP API is invoked with a URL derived from user input. An attacker can redirect the server to probe internal services such as cloud metadata endpoints (169.254.169.254), localhost, or other internal hosts.', 'wp-ultimate-security-scan' ),
				__( 'Validate URLs with wp_http_validate_url(). Use an explicit allowlist of permitted hosts. Block private/loopback IP ranges via a pre_http_request hook or use wp_safe_remote_get().', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// wp_safe_remote_*() with user input — partial mitigation but still exploitable.
		if ( preg_match( '/\bwp_safe_remote_(?:get|post|request)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'SSRF (partial mitigation): wp_safe_remote_*() called with user URL', 'wp-ultimate-security-scan' ),
				__( 'wp_safe_remote_get/post blocks requests to private IPs but is still vulnerable to DNS rebinding and redirect chains that resolve to internal addresses.', 'wp-ultimate-security-scan' ),
				__( 'Apply an explicit allowlist of permitted domains in addition to wp_safe_remote_get(). Validate URLs with wp_http_validate_url() and verify the resolved IP before making the request.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// file_get_contents with user-controlled path/URL.
		if ( preg_match( '/\bfile_get_contents\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'SSRF / LFI: file_get_contents() called with user-controlled path or URL', 'wp-ultimate-security-scan' ),
				__( 'file_get_contents() with user input can read arbitrary local files (LFI) or make outbound HTTP requests (SSRF) if allow_url_fopen is enabled.', 'wp-ultimate-security-scan' ),
				__( 'Never pass user input directly to file_get_contents(). Validate paths against an allowlist; use wp_remote_get() with URL validation for HTTP requests.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// cURL CURLOPT_URL set from user input.
		if ( preg_match( '/curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,[^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'SSRF: cURL CURLOPT_URL set from user-controlled input', 'wp-ultimate-security-scan' ),
				__( 'Setting CURLOPT_URL from user data enables full SSRF. Attackers can target cloud metadata services, localhost services, or internal network hosts.', 'wp-ultimate-security-scan' ),
				__( 'Validate the URL before passing to cURL. Enforce a host allowlist and block private/loopback IP ranges. Prefer wp_remote_get() with proper validation.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// fsockopen / stream_socket_client with user-controlled host.
		if ( preg_match( '/\b(?:fsockopen|stream_socket_client)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'SSRF: socket connection target derived from user input', 'wp-ultimate-security-scan' ),
				__( 'fsockopen() or stream_socket_client() with user-supplied data allows attackers to open TCP connections to arbitrary hosts from the server.', 'wp-ultimate-security-scan' ),
				__( 'Validate and whitelist the hostname before opening a socket. Block loopback (127.x), link-local (169.254.x), and private IP ranges (10.x, 172.16-31.x, 192.168.x).', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Open redirect via wp_redirect() with user-controlled URL.
		if ( preg_match( '/\bwp_redirect\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Open redirect: wp_redirect() called with user-controlled URL', 'wp-ultimate-security-scan' ),
				__( 'Redirecting to a user-supplied URL enables open redirect attacks (phishing, OAuth token theft) and can be chained into SSRF via redirect following.', 'wp-ultimate-security-scan' ),
				__( 'Validate redirect destinations against an allowlist. Use wp_safe_redirect() instead of wp_redirect() and always supply a fallback URL.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// header('Location:') with user input — raw PHP redirect.
		if ( preg_match( '/\bheader\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$_(?:GET|POST|REQUEST)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Open redirect: header(Location:) set from user input', 'wp-ultimate-security-scan' ),
				__( 'Concatenating user input into a Location redirect header enables open redirect and can be chained to SSRF.', 'wp-ultimate-security-scan' ),
				__( 'Use wp_safe_redirect() with an explicit fallback URL. Validate the destination against a trusted-domain allowlist.', 'wp-ultimate-security-scan' ),
				$path
			);
		}
	}

	/**
	 * Check WordPress features that enable server-side request functionality.
	 *
	 * @return void
	 */
	private function check_wp_ssrf_features() {
		// oEmbed proxy endpoint — unauthenticated server-side HTTP fetcher.
		$proxy_url = add_query_arg(
			array(
				'url'    => 'https://example.com/',
				'format' => 'json',
			),
			rest_url( 'oembed/1.0/proxy' )
		);

		$response = wp_remote_get(
			$proxy_url,
			array(
				'timeout'   => 5,
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				'headers'   => array( 'X-WPUSS-Scan' => '1' ),
			)
		);

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'oEmbed REST proxy is publicly accessible — SSRF vector', 'wp-ultimate-security-scan' ),
				__( 'The /wp-json/oembed/1.0/proxy endpoint allows unauthenticated users to make the server fetch arbitrary public URLs and receive the response. This can probe internal hosts via DNS rebinding or redirect chains.', 'wp-ultimate-security-scan' ),
				__( "Restrict the oEmbed proxy to authenticated requests or disable it: remove_action( 'rest_api_init', 'wp_oembed_register_routes' );", 'wp-ultimate-security-scan' ),
				'/wp-json/oembed/1.0/proxy'
			);
		}

		// Pingback — classic SSRF / DDoS reflection vector.
		if ( apply_filters( 'xmlrpc_enabled', true ) && get_option( 'default_pingback_flag' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Pingback functionality is enabled', 'wp-ultimate-security-scan' ),
				__( 'WordPress pingbacks make the server issue outbound HTTP requests to any URL supplied in a pingback call. This is a documented SSRF and DDoS amplification vector.', 'wp-ultimate-security-scan' ),
				__( "Disable pingbacks: Settings → Discussion → uncheck 'Allow link notifications from other blogs'. Disabling XML-RPC fully prevents pingback abuse.", 'wp-ultimate-security-scan' ),
				'xmlrpc.php'
			);
		}

		// allow_url_fopen enabled — increases SSRF risk from file_get_contents.
		if ( ini_get( 'allow_url_fopen' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_LOW,
				__( 'PHP allow_url_fopen is enabled', 'wp-ultimate-security-scan' ),
				__( 'allow_url_fopen lets file_get_contents() and similar functions fetch remote URLs. Combined with any path-traversal or injection bug that passes a URL to file_get_contents(), this becomes an SSRF vector.', 'wp-ultimate-security-scan' ),
				__( 'Set allow_url_fopen = Off in php.ini if your code does not intentionally use file_get_contents() for HTTP requests (use wp_remote_get() instead).', 'wp-ultimate-security-scan' ),
				'php.ini'
			);
		}

		// WooCommerce webhooks — if active, flag for review.
		if ( class_exists( 'WooCommerce' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_INFO,
				__( 'WooCommerce webhooks may be configured — review webhook URLs', 'wp-ultimate-security-scan' ),
				__( 'WooCommerce supports webhooks that cause the server to make outbound HTTP requests. A compromised admin account could add a webhook pointing at an internal service, enabling SSRF.', 'wp-ultimate-security-scan' ),
				__( 'Review active webhooks in WooCommerce → Settings → Advanced → Webhooks. Ensure only trusted external URLs are configured.', 'wp-ultimate-security-scan' ),
				'woocommerce'
			);
		}
	}
}
