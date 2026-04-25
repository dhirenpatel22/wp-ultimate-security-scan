<?php
/**
 * Plugin-level security checks.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Plugins
 */
class WPUSS_Check_Plugins extends WPUSS_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'plugins';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Plugins', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'updates', 'inactive', 'unknown_source', 'abandoned' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		switch ( $step ) {
			case 'updates':
				$this->check_updates();
				break;
			case 'inactive':
				$this->check_inactive();
				break;
			case 'unknown_source':
				$this->check_unknown_source();
				break;
			case 'abandoned':
				$this->check_abandoned();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Pending plugin updates.
	 *
	 * @return void
	 */
	private function check_updates() {
		$updates = get_site_transient( 'update_plugins' );
		if ( ! $updates || empty( $updates->response ) ) {
			return;
		}
		foreach ( $updates->response as $plugin_file => $info ) {
			$data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_file, false, false );
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Plugin update available', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: 1: name, 2: current, 3: new */
					__( 'Plugin "%1$s" is at version %2$s; %3$s is available. Outdated plugins are the single most common WordPress compromise vector.', 'wp-ultimate-security-scan' ),
					$data['Name'],
					$data['Version'],
					isset( $info->new_version ) ? $info->new_version : 'latest'
				),
				__( 'Review the changelog and apply the update.', 'wp-ultimate-security-scan' ),
				'plugin:' . $plugin_file
			);
		}
	}

	/**
	 * Inactive plugins still present.
	 *
	 * @return void
	 */
	private function check_inactive() {
		$all    = get_plugins();
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		foreach ( $all as $file => $data ) {
			if ( ! in_array( $file, $active, true ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_LOW,
					__( 'Inactive plugin present on disk', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: name */
						__( 'Plugin "%s" is installed but not active. Its code is still on disk and could be exploited if it has a vulnerability.', 'wp-ultimate-security-scan' ),
						$data['Name']
					),
					__( 'Delete plugins you do not intend to use.', 'wp-ultimate-security-scan' ),
					'plugin:' . $file
				);
			}
		}
	}

	/**
	 * Plugins without a WordPress.org URI (heuristic: possibly nulled/unknown).
	 *
	 * @return void
	 */
	private function check_unknown_source() {
		$plugins = get_plugins();
		foreach ( $plugins as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug || '' === $slug ) {
				continue; // Single-file plugins.
			}
			if ( empty( $data['PluginURI'] ) && empty( $data['UpdateURI'] ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_LOW,
					__( 'Plugin has no update source declared', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: name */
						__( 'Plugin "%s" declares neither a PluginURI nor an UpdateURI. If this is not a custom plugin, verify it came from a trusted source.', 'wp-ultimate-security-scan' ),
						$data['Name']
					),
					__( 'Confirm the plugin origin. Remove if unknown or nulled.', 'wp-ultimate-security-scan' ),
					'plugin:' . $file
				);
			}
		}
	}

	/**
	 * Plugins that have not been updated in a long time (abandoned heuristic).
	 *
	 * @return void
	 */
	private function check_abandoned() {
		$plugins = get_plugins();
		foreach ( $plugins as $file => $data ) {
			$full_path = WP_PLUGIN_DIR . '/' . $file;
			if ( ! file_exists( $full_path ) ) {
				continue;
			}
			$mtime = filemtime( $full_path );
			if ( $mtime && ( time() - $mtime ) > ( 2 * YEAR_IN_SECONDS ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_MEDIUM,
					__( 'Plugin appears abandoned', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: 1: name, 2: date */
						__( 'Plugin "%1$s" has not been updated on disk since %2$s. Unmaintained plugins accumulate unfixed vulnerabilities.', 'wp-ultimate-security-scan' ),
						$data['Name'],
						gmdate( 'Y-m-d', $mtime )
					),
					__( 'Check the plugin directory page. If unmaintained, find a replacement.', 'wp-ultimate-security-scan' ),
					'plugin:' . $file
				);
			}
		}
	}
}
