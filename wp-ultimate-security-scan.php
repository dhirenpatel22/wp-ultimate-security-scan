<?php
/**
 * Plugin Name:       WordPress Ultimate Security Scan
 * Plugin URI:        https://github.com/dhirenpatel22/wp-ultimate-security-scan
 * Description:       Comprehensive background security scanner for WordPress core, themes, plugins, filesystem, database, users and code patterns. CPU-throttled and non-blocking.
 * Version:           1.2.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Dhiren Patel
 * Author URI:        https://www.dhirenpatel.me/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-ultimate-security-scan
 * Domain Path:       /languages
 *
 * @package WP_Ultimate_Security_Scan
 */

// Abort if accessed directly — standard WPCS direct-access guard.
defined( 'ABSPATH' ) || exit;

// Bail silently if a second copy of this plugin is loaded (e.g. wp-ultimate-security-scan-main).
// Checking WPUSS_VERSION is sufficient because it is the first thing we define below.
if ( defined( 'WPUSS_VERSION' ) ) {
	return;
}

// Plugin constants.
define( 'WPUSS_VERSION', '1.2.0' );
define( 'WPUSS_PLUGIN_FILE', __FILE__ );
define( 'WPUSS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPUSS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WPUSS_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'WPUSS_MIN_CAP', 'manage_options' );
define( 'WPUSS_SLUG', 'wp-ultimate-security-scan' );

/**
 * PSR-4-style lightweight autoloader for WPUSS_* classes.
 *
 * Maps class names like WPUSS_Check_Core to includes/checks/class-wpuss-check-core.php
 * or WPUSS_Scanner to includes/class-wpuss-scanner.php.
 *
 * @param string $class_name Fully-qualified class name.
 * @return void
 */
if ( ! function_exists( 'wpuss_autoload' ) ) {
	function wpuss_autoload( $class_name ) {
		if ( strpos( $class_name, 'WPUSS_' ) !== 0 ) {
			return;
		}

		$file_name = 'class-' . strtolower( str_replace( '_', '-', $class_name ) ) . '.php';

		$candidates = array(
			WPUSS_PLUGIN_DIR . 'includes/checks/' . $file_name,
			WPUSS_PLUGIN_DIR . 'includes/' . $file_name,
		);

		foreach ( $candidates as $candidate ) {
			if ( file_exists( $candidate ) ) {
				require_once $candidate;
				return;
			}
		}
	}
	spl_autoload_register( 'wpuss_autoload' );
}

// Activation, deactivation, uninstall hooks.
register_activation_hook( __FILE__, array( 'WPUSS_Core', 'on_activate' ) );
register_deactivation_hook( __FILE__, array( 'WPUSS_Core', 'on_deactivate' ) );

/**
 * Boot the plugin once WordPress is ready.
 *
 * @return void
 */
function wpuss_bootstrap() {
	load_plugin_textdomain(
		'wp-ultimate-security-scan',
		false,
		dirname( WPUSS_PLUGIN_BASENAME ) . '/languages'
	);

	WPUSS_Core::instance()->init();
}
add_action( 'plugins_loaded', 'wpuss_bootstrap' );
