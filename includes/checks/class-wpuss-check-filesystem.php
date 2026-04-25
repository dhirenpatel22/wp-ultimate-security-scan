<?php
/**
 * Filesystem & permission checks.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Filesystem
 */
class WPUSS_Check_Filesystem extends WPUSS_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'filesystem';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Filesystem & Permissions', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'wp_config_perms', 'key_perms', 'readme', 'uploads_php', 'backup_files', 'directory_listing' );
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
			case 'wp_config_perms':
				$this->check_wp_config_perms();
				break;
			case 'key_perms':
				$this->check_key_perms();
				break;
			case 'readme':
				$this->check_readme();
				break;
			case 'uploads_php':
				return $this->check_uploads_php( $cursor );
			case 'backup_files':
				$this->check_exposed_backups();
				break;
			case 'directory_listing':
				$this->check_directory_listing();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * wp-config.php file permission check.
	 *
	 * @return void
	 */
	private function check_wp_config_perms() {
		$path = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $path ) ) {
			$path = dirname( ABSPATH ) . '/wp-config.php';
			if ( ! file_exists( $path ) ) {
				return;
			}
		}

		$perms = fileperms( $path ) & 0777;
		if ( $perms & 0044 ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'wp-config.php is world-readable', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: octal permissions */
					__( 'Permissions on wp-config.php are %s. Other users on the server could read the database credentials.', 'wp-ultimate-security-scan' ),
					'0' . decoct( $perms )
				),
				__( 'Change permissions to 0640 or 0600 (chmod 600 wp-config.php).', 'wp-ultimate-security-scan' ),
				$path
			);
		}
	}

	/**
	 * Permissions on other key files/directories.
	 *
	 * @return void
	 */
	private function check_key_perms() {
		$targets = array(
			ABSPATH                => array( 'max' => 0755, 'label' => 'WordPress root' ),
			ABSPATH . 'wp-admin'   => array( 'max' => 0755, 'label' => 'wp-admin' ),
			WP_CONTENT_DIR         => array( 'max' => 0755, 'label' => 'wp-content' ),
			WP_CONTENT_DIR . '/uploads' => array( 'max' => 0755, 'label' => 'uploads' ),
		);
		if ( defined( 'WP_PLUGIN_DIR' ) ) {
			$targets[ WP_PLUGIN_DIR ] = array( 'max' => 0755, 'label' => 'plugins' );
		}

		foreach ( $targets as $path => $info ) {
			if ( ! is_dir( $path ) ) {
				continue;
			}
			$perms = fileperms( $path ) & 0777;
			// World-writable is always bad.
			if ( $perms & 0002 ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					/* translators: %s: label */
					sprintf( __( '%s directory is world-writable', 'wp-ultimate-security-scan' ), $info['label'] ),
					sprintf(
						/* translators: 1: path, 2: octal */
						__( 'Directory %1$s has permissions %2$s. Any user on the server can write to it.', 'wp-ultimate-security-scan' ),
						$path,
						'0' . decoct( $perms )
					),
					__( 'Change permissions to 0755 (directories) / 0644 (files) or stricter, owned by the web user.', 'wp-ultimate-security-scan' ),
					$path
				);
			}
		}
	}

	/**
	 * readme.html exposed.
	 *
	 * @return void
	 */
	private function check_readme() {
		$readme = ABSPATH . 'readme.html';
		if ( file_exists( $readme ) ) {
			$url      = home_url( '/readme.html' );
			$response = wp_remote_get(
				$url,
				array(
					'timeout'   => 5,
					'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				)
			);
			if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_LOW,
					__( 'readme.html is publicly accessible', 'wp-ultimate-security-scan' ),
					__( 'The file discloses the WordPress version, helping attackers match known CVEs.', 'wp-ultimate-security-scan' ),
					__( 'Delete readme.html or block it at the webserver.', 'wp-ultimate-security-scan' ),
					$readme
				);
			}
		}
	}

	/**
	 * PHP files in uploads — walks the directory tree resumably.
	 *
	 * @param array $cursor Cursor — holds 'queue' of directories left.
	 * @return array
	 */
	private function check_uploads_php( array $cursor ) {
		$upload_dir = wp_get_upload_dir();
		$root       = isset( $upload_dir['basedir'] ) ? $upload_dir['basedir'] : '';
		if ( ! $root || ! is_dir( $root ) ) {
			return array( 'continue' => false, 'cursor' => array() );
		}

		if ( ! isset( $cursor['queue'] ) ) {
			$cursor = array( 'queue' => array( $root ), 'checked' => 0 );
		}

		$budget = 200; // files per invocation.
		$seen   = 0;

		while ( ! empty( $cursor['queue'] ) && $seen < $budget ) {
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
				} elseif ( preg_match( '/\.(php|phtml|php5|php7|phar)$/i', $entry ) ) {
					$this->finding(
						WPUSS_Logger::SEVERITY_CRITICAL,
						__( 'Executable PHP file inside uploads', 'wp-ultimate-security-scan' ),
						__( 'PHP files inside wp-content/uploads are a classic backdoor indicator. Uploads must never execute server-side code.', 'wp-ultimate-security-scan' ),
						__( 'Inspect the file immediately. Remove if unexpected, and block PHP execution in uploads via .htaccess or webserver rules.', 'wp-ultimate-security-scan' ),
						$full
					);
				}
				$seen++;
				if ( $seen >= $budget ) {
					break;
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
	 * Exposed backup / source files.
	 *
	 * @return void
	 */
	private function check_exposed_backups() {
		$patterns = array(
			'wp-config.php.bak',
			'wp-config.php.save',
			'wp-config.php.old',
			'wp-config.php~',
			'wp-config.bak',
			'.wp-config.php.swp',
			'backup.zip',
			'site.zip',
			'database.sql',
			'backup.sql',
			'dump.sql',
		);

		foreach ( $patterns as $file ) {
			$path = ABSPATH . $file;
			if ( file_exists( $path ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_CRITICAL,
					__( 'Sensitive backup file present in webroot', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: filename */
						__( 'Found %s in the site root. Files like these frequently leak database credentials or full site data.', 'wp-ultimate-security-scan' ),
						$file
					),
					__( 'Delete the file or move it outside the webroot immediately.', 'wp-ultimate-security-scan' ),
					$path
				);
			}
		}
	}

	/**
	 * Directory listing on uploads.
	 *
	 * @return void
	 */
	private function check_directory_listing() {
		$upload_dir = wp_get_upload_dir();
		$url        = isset( $upload_dir['baseurl'] ) ? trailingslashit( $upload_dir['baseurl'] ) : '';
		if ( ! $url ) {
			return;
		}

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
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return;
		}
		$body = wp_remote_retrieve_body( $response );
		if ( false !== stripos( $body, 'Index of /' ) || false !== stripos( $body, '<title>Index of' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Directory listing enabled on uploads', 'wp-ultimate-security-scan' ),
				__( 'Visitors can enumerate every file under wp-content/uploads.', 'wp-ultimate-security-scan' ),
				__( "Add 'Options -Indexes' to .htaccess (Apache) or 'autoindex off;' (nginx), or place an empty index.php in the directory.", 'wp-ultimate-security-scan' ),
				$url
			);
		}
	}
}
