<?php
/**
 * Source code pattern analysis.
 *
 * Walks plugin and theme PHP files looking for:
 *  - Malware / backdoor signatures (eval + base64_decode, shell_exec, …)
 *  - Direct file access without ABSPATH guard
 *  - Dangerous dynamic code execution
 *  - Missing output escaping / prepared SQL (heuristic)
 *
 * This is static lint-style analysis; false positives are possible. Every
 * finding is low confidence by design — the scanner's job is to point a
 * human at suspicious spots, not to judge them.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Code_Patterns
 */
class WPUSS_Check_Code_Patterns extends WPUSS_Check_Base {

	/**
	 * Maximum file size to inspect (bytes).
	 *
	 * @var int
	 */
	private $max_file_size;

	/**
	 * Constructor — reads max file size from settings.
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

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'code_patterns';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Code Pattern Analysis', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'scan_plugins', 'scan_themes' );
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
			return $this->scan_tree( WP_PLUGIN_DIR, 'plugin', $cursor );
		}
		if ( 'scan_themes' === $step ) {
			return $this->scan_tree( get_theme_root(), 'theme', $cursor );
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Scan a tree resumably.
	 *
	 * @param string $root   Root directory.
	 * @param string $type   'plugin' or 'theme'.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	private function scan_tree( $root, $type, array $cursor ) {
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
				// Skip our own plugin to avoid false-positive recursion on our regex strings.
				if ( false !== strpos( $full, 'wp-ultimate-security-scan' ) ) {
					continue;
				}
				if ( is_dir( $full ) ) {
					// Skip common dependency folders.
					if ( in_array( $entry, array( 'node_modules', 'vendor', '.git' ), true ) ) {
						continue;
					}
					$cursor['queue'][] = $full;
				} elseif ( preg_match( '/\.php$/i', $entry ) ) {
					$this->scan_file( $full, $type );
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
	 * Inspect a single file.
	 *
	 * @param string $path File path.
	 * @param string $type 'plugin' or 'theme'.
	 * @return void
	 */
	private function scan_file( $path, $type ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $this->max_file_size || 0 === $size ) {
			return;
		}

		// Read via WP filesystem API would add overhead; direct read is fine here.
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents || '' === $contents ) {
			return;
		}

		// --- Malware / backdoor signatures --- .
		// eval() on a base64 or gzinflate payload is very rarely benign.
		if ( preg_match( '/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'Possible obfuscated backdoor', 'wp-ultimate-security-scan' ),
				__( 'Found eval() wrapping a decode/decompress function. This is a standard shape for PHP backdoors.', 'wp-ultimate-security-scan' ),
				__( 'Compare against the original plugin/theme source. If not legitimate, remove the file and investigate for further compromise.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Direct exec calls are rarely legitimate in plugin/theme code.
		if ( preg_match( '/\b(?:shell_exec|passthru|proc_open|popen|system)\s*\(/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Use of shell execution function', 'wp-ultimate-security-scan' ),
				__( 'The file calls shell_exec / passthru / proc_open / popen / system. WordPress plugins and themes should never need to run shell commands.', 'wp-ultimate-security-scan' ),
				__( 'Verify the call. If dynamic user input reaches it, this is a command-injection bug.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Dangerous file inclusion on user input.
		if ( preg_match( '/\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'File inclusion from user input', 'wp-ultimate-security-scan' ),
				__( 'include/require with a superglobal — classic local/remote file inclusion vulnerability.', 'wp-ultimate-security-scan' ),
				__( 'Rewrite to whitelist allowed paths. Never pass user input directly into include/require.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Missing ABSPATH guard on files that look like top-level plugin includes.
		// Heuristic: PHP file not in wp-admin/wp-includes, doesn't check ABSPATH.
		if (
			false !== strpos( $type, 'plugin' ) &&
			false === stripos( $contents, 'ABSPATH' ) &&
			false === stripos( $contents, 'WPINC' ) &&
			preg_match( '/<\?php/', $contents )
		) {
			// Only flag files that declare functions/classes (library-ish files).
			if ( preg_match( '/\b(?:function|class)\s+\w/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_LOW,
					__( 'PHP file without direct-access guard', 'wp-ultimate-security-scan' ),
					__( "This file does not check for ABSPATH. If the webserver serves .php files directly from wp-content, partial execution can leak errors or allow unintended calls.", 'wp-ultimate-security-scan' ),
					__( "Add at the top: if ( ! defined( 'ABSPATH' ) ) { exit; }", 'wp-ultimate-security-scan' ),
					$path
				);
			}
		}

		// Heuristic: raw $wpdb->query with string concatenation of superglobals.
		if ( preg_match( '/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\(\s*["\'][^"\']*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Likely unprepared SQL with user input', 'wp-ultimate-security-scan' ),
				__( 'A $wpdb query string appears to concatenate superglobal data directly. This is very likely SQL injection.', 'wp-ultimate-security-scan' ),
				__( 'Use $wpdb->prepare() with placeholders (%s, %d, %f). Never concatenate user input into SQL.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Unescaped echo of superglobals (reflected XSS heuristic).
		if ( preg_match( '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\b/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Unescaped output of user input', 'wp-ultimate-security-scan' ),
				__( 'Directly echoing $_GET / $_POST without escaping is a reflected XSS bug.', 'wp-ultimate-security-scan' ),
				__( 'Wrap the value in esc_html(), esc_attr() or wp_kses() depending on the context.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// File writes from user input (upload / arbitrary file write).
		if ( preg_match( '/\bfile_put_contents\s*\([^)]*\$_(?:GET|POST|REQUEST|FILES)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'File write from user input', 'wp-ultimate-security-scan' ),
				__( 'file_put_contents receiving user-controlled data is a classic arbitrary-file-write / RCE vector.', 'wp-ultimate-security-scan' ),
				__( 'Use wp_handle_upload() and validate destination paths with realpath against an allowed base.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Check for long base64 strings (possible payload).
		if ( preg_match( '/[A-Za-z0-9+\/=]{400,}/', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Long opaque string — possible embedded payload', 'wp-ultimate-security-scan' ),
				__( 'The file contains a base64-shaped string 400+ characters long. This is sometimes legitimate (SVG, fonts), sometimes a hidden payload.', 'wp-ultimate-security-scan' ),
				__( 'Open the file and inspect the string context.', 'wp-ultimate-security-scan' ),
				$path
			);
		}
	}
}
