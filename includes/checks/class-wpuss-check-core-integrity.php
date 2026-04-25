<?php
/**
 * Core integrity check.
 *
 * Verifies that every shipped WordPress core file matches the official
 * checksums published at api.wordpress.org. Also flags any unknown .php
 * files sitting inside wp-admin/ or wp-includes/ — a classic post-exploit
 * persistence pattern.
 *
 * The WordPress.org checksums API returns a map of
 * { path-relative-to-ABSPATH => md5 }.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Core_Integrity
 */
class WPUSS_Check_Core_Integrity extends WPUSS_Check_Base {

	/**
	 * Transient name where the fetched checksums are cached for the duration
	 * of the scan (and a bit beyond, so repeat scans don't hammer the API).
	 */
	const CHECKSUMS_TRANSIENT = 'wpuss_core_checksums';

	/**
	 * Cache TTL — 12 hours. Core version rarely changes within that window.
	 */
	const CHECKSUMS_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * Batch size for file verification per invocation.
	 *
	 * Kept conservative — each file is a disk read + md5_file.
	 */
	const VERIFY_BATCH = 80;

	/**
	 * Batch size for the unknown-files walker.
	 */
	const EXTRAS_BATCH = 200;

	/**
	 * ID used in findings.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'core_integrity';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'WordPress Core Integrity', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * fetch   — pull the checksums JSON from api.wordpress.org
	 * verify  — walk checksums, verify each file's md5 (resumable, batched)
	 * extras  — walk wp-admin / wp-includes for files NOT in checksums
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'fetch', 'verify', 'extras' );
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
			case 'fetch':
				$this->step_fetch();
				return array( 'continue' => false, 'cursor' => array() );

			case 'verify':
				return $this->step_verify( $cursor );

			case 'extras':
				return $this->step_extras( $cursor );
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Fetch checksums from api.wordpress.org and cache them.
	 *
	 * @return void
	 */
	private function step_fetch() {
		global $wp_version, $wp_local_package;

		$version = isset( $wp_version ) ? $wp_version : '';
		if ( '' === $version ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_INFO,
				__( 'Core version not detected', 'wp-ultimate-security-scan' ),
				__( 'Could not read $wp_version — skipping core integrity verification.', 'wp-ultimate-security-scan' ),
				'',
				ABSPATH
			);
			return;
		}

		// Stale cache from a previous major-version? Bust it.
		$cached = get_transient( self::CHECKSUMS_TRANSIENT );
		if ( is_array( $cached ) && isset( $cached['version'] ) && $cached['version'] === $version ) {
			return; // Already have the right ones cached.
		}

		$locale = is_string( $wp_local_package ) && '' !== $wp_local_package ? $wp_local_package : 'en_US';
		$url    = add_query_arg(
			array(
				'version' => rawurlencode( $version ),
				'locale'  => rawurlencode( $locale ),
			),
			'https://api.wordpress.org/core/checksums/1.0/'
		);

		$response = wp_remote_get(
			$url,
			array(
				'timeout' => 15,
				'headers' => array( 'X-WPUSS-Scan' => '1' ),
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_INFO,
				__( 'Core integrity check skipped', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: error message */
					__( 'Could not reach the WordPress.org checksums API: %s', 'wp-ultimate-security-scan' ),
					$response->get_error_message()
				),
				__( 'Ensure outbound HTTPS to api.wordpress.org is allowed, then re-run the scan.', 'wp-ultimate-security-scan' ),
				$url
			);
			return;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		if ( 200 !== $code || '' === $body ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_INFO,
				__( 'Core integrity check skipped', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %d: HTTP status */
					__( 'WordPress.org returned HTTP %d with no usable checksum data. This usually means the exact WP version / locale combination is not indexed (e.g. nightly builds).', 'wp-ultimate-security-scan' ),
					$code
				),
				'',
				$url
			);
			return;
		}

		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) || empty( $decoded['checksums'] ) || ! is_array( $decoded['checksums'] ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_INFO,
				__( 'Core integrity check skipped', 'wp-ultimate-security-scan' ),
				__( 'The WordPress.org checksums response was malformed or empty.', 'wp-ultimate-security-scan' ),
				'',
				$url
			);
			return;
		}

		set_transient(
			self::CHECKSUMS_TRANSIENT,
			array(
				'version'   => $version,
				'locale'    => $locale,
				'checksums' => $decoded['checksums'],
			),
			self::CHECKSUMS_TTL
		);
	}

	/**
	 * Walk the checksums list and MD5-verify each file.
	 *
	 * Cursor:
	 *   keys    — remaining relative paths to verify (array shifted from)
	 *   total   — total count (for info only)
	 *   bad     — running count of mismatches (for a summary finding)
	 *   missing — running count of missing-from-disk files
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function step_verify( array $cursor ) {
		$cached = get_transient( self::CHECKSUMS_TRANSIENT );
		if ( ! is_array( $cached ) || empty( $cached['checksums'] ) ) {
			// No checksums available (fetch step failed). Nothing to verify.
			return array( 'continue' => false, 'cursor' => array() );
		}
		$checksums = $cached['checksums'];

		if ( ! isset( $cursor['keys'] ) ) {
			// Filter out entries we deliberately don't want to police.
			$skip_prefixes = array(
				'wp-content/', // User content — owned by the user, not core.
			);
			$skip_paths = array(
				'wp-config-sample.php',
				'readme.html',
				'license.txt',
			);

			$keys = array();
			foreach ( $checksums as $path => $hash ) {
				if ( ! is_string( $path ) || ! is_string( $hash ) ) {
					continue;
				}
				$skip = false;
				foreach ( $skip_prefixes as $p ) {
					if ( 0 === strpos( $path, $p ) ) {
						$skip = true;
						break;
					}
				}
				if ( $skip || in_array( $path, $skip_paths, true ) ) {
					continue;
				}
				$keys[] = $path;
			}

			$cursor = array(
				'keys'    => $keys,
				'total'   => count( $keys ),
				'bad'     => 0,
				'missing' => 0,
			);
		}

		$seen = 0;
		while ( ! empty( $cursor['keys'] ) && $seen < self::VERIFY_BATCH ) {
			$path     = array_shift( $cursor['keys'] );
			$expected = isset( $checksums[ $path ] ) ? $checksums[ $path ] : '';
			$full     = ABSPATH . $path;

			if ( ! file_exists( $full ) ) {
				// Core file is missing — unusual; worth noting.
				$cursor['missing']++;
				$this->finding(
					WPUSS_Logger::SEVERITY_MEDIUM,
					__( 'Missing WordPress core file', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: relative path */
						__( 'The core file %s is listed in the WordPress.org checksums but is not present on disk. It may have been deleted or the installation is incomplete.', 'wp-ultimate-security-scan' ),
						$path
					),
					__( 'Reinstall WordPress from Dashboard → Updates → Re-install, or upload a fresh copy of the missing file.', 'wp-ultimate-security-scan' ),
					$path
				);
				$seen++;
				continue;
			}

			if ( ! is_readable( $full ) ) {
				$seen++;
				continue;
			}

			$actual = md5_file( $full );
			if ( false !== $actual && $actual !== $expected ) {
				$cursor['bad']++;
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					__( 'Modified WordPress core file', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: 1: path, 2: expected hash, 3: actual hash */
						__( 'The core file %1$s does not match the hash published on WordPress.org. Expected %2$s, got %3$s. This is almost always a sign of either a manual edit (don\'t do that) or a compromise.', 'wp-ultimate-security-scan' ),
						$path,
						$expected,
						$actual
					),
					__( 'Compare the file against a clean copy of the same WordPress version. If you did not modify it intentionally, reinstall WordPress from Dashboard → Updates → Re-install.', 'wp-ultimate-security-scan' ),
					$path,
					array(
						'expected' => $expected,
						'actual'   => $actual,
					)
				);
			}
			$seen++;
		}

		// More files left? Ask the scanner to call us again with the cursor.
		if ( ! empty( $cursor['keys'] ) ) {
			return array( 'continue' => true, 'cursor' => $cursor );
		}

		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Walk wp-admin / wp-includes looking for suspicious extra files
	 * (files NOT present in the WordPress.org checksums list).
	 *
	 * Cursor:
	 *   queue     — directories still to walk
	 *   known     — associative array of known core paths (from checksums)
	 *   seen      — files examined so far
	 *
	 * @param array $cursor Cursor.
	 * @return array
	 */
	private function step_extras( array $cursor ) {
		$cached = get_transient( self::CHECKSUMS_TRANSIENT );
		if ( ! is_array( $cached ) || empty( $cached['checksums'] ) ) {
			return array( 'continue' => false, 'cursor' => array() );
		}

		if ( ! isset( $cursor['queue'] ) ) {
			$cursor = array(
				'queue' => array(
					ABSPATH . 'wp-admin',
					ABSPATH . 'wp-includes',
				),
				'known' => $cached['checksums'], // path => md5 map.
				'seen'  => 0,
			);
			// Ensure directories actually exist before queueing.
			$cursor['queue'] = array_values( array_filter( $cursor['queue'], 'is_dir' ) );
		}

		$abs_path = wp_normalize_path( ABSPATH );
		$seen     = 0;

		while ( ! empty( $cursor['queue'] ) && $seen < self::EXTRAS_BATCH ) {
			$current = array_shift( $cursor['queue'] );
			$handle  = @opendir( $current ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $handle ) {
				continue;
			}

			while ( false !== ( $entry = readdir( $handle ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}

				$full = $current . DIRECTORY_SEPARATOR . $entry;

				if ( is_dir( $full ) ) {
					$cursor['queue'][] = $full;
					continue;
				}

				// Build the same relative path format that the checksums API uses.
				$rel = ltrim( str_replace( $abs_path, '', wp_normalize_path( $full ) ), '/' );

				if ( isset( $cursor['known'][ $rel ] ) ) {
					$seen++;
					continue;
				}

				// Only care about code-executing files — images, translations, etc.
				// get dropped into core dirs by plugins occasionally and aren't scary.
				if ( preg_match( '/\.(php|phtml|php5|php7|phar|inc)$/i', $entry ) ) {
					$this->finding(
						WPUSS_Logger::SEVERITY_HIGH,
						__( 'Unknown file inside WordPress core directory', 'wp-ultimate-security-scan' ),
						sprintf(
							/* translators: %s: relative path */
							__( 'The file %s is inside a core WordPress directory but is not part of the official WordPress.org checksums for this version. This is frequently how backdoors hide.', 'wp-ultimate-security-scan' ),
							$rel
						),
						__( 'Inspect the file. If it wasn\'t installed by you deliberately, quarantine it and reinstall WordPress core from Dashboard → Updates → Re-install.', 'wp-ultimate-security-scan' ),
						$rel
					);
				}
				$seen++;
				if ( $seen >= self::EXTRAS_BATCH ) {
					break;
				}
			}
			closedir( $handle );
		}

		$cursor['seen'] = (int) $cursor['seen'] + $seen;

		if ( ! empty( $cursor['queue'] ) ) {
			return array( 'continue' => true, 'cursor' => $cursor );
		}

		return array( 'continue' => false, 'cursor' => array() );
	}
}
