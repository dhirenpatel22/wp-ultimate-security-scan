<?php
/**
 * Core plugin class — singleton controller.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Core
 */
final class WPUSS_Core {

	/**
	 * Singleton instance.
	 *
	 * @var WPUSS_Core|null
	 */
	private static $instance = null;

	/**
	 * Admin handler.
	 *
	 * @var WPUSS_Admin|null
	 */
	public $admin = null;

	/**
	 * AJAX handler.
	 *
	 * @var WPUSS_Ajax|null
	 */
	public $ajax = null;

	/**
	 * Get singleton.
	 *
	 * @return WPUSS_Core
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — singleton pattern.
	 */
	private function __construct() {}

	/**
	 * Prevent cloning.
	 *
	 * @return void
	 */
	private function __clone() {}

	/**
	 * Prevent unserialization.
	 *
	 * @return void
	 */
	public function __wakeup() {
		throw new \Exception( 'Cannot unserialize singleton' );
	}

	/**
	 * Wire up hooks.
	 *
	 * @return void
	 */
	public function init() {
		// Admin surfaces only load for users who can manage options.
		if ( is_admin() ) {
			$this->admin = new WPUSS_Admin();
			$this->admin->register();

			$this->ajax = new WPUSS_Ajax();
			$this->ajax->register();
		}

		// Cron handler — runs regardless of admin context.
		add_action( 'wpuss_run_scan_chunk', array( $this, 'run_scheduled_chunk' ) );
		add_action( 'wpuss_daily_maintenance', array( $this, 'run_daily_maintenance' ) );
	}

	/**
	 * Handle a scheduled scan chunk (used as a cron fallback when AJAX pauses).
	 *
	 * @return void
	 */
	public function run_scheduled_chunk() {
		$scanner = new WPUSS_Scanner();
		$scanner->run_chunk( true );
	}

	/**
	 * Daily maintenance — prune old findings and transients.
	 *
	 * @return void
	 */
	public function run_daily_maintenance() {
		$logger = new WPUSS_Logger();
		$logger->prune_old( 30 * DAY_IN_SECONDS );
	}

	/**
	 * Activation hook — schedule events, create table, seed settings.
	 *
	 * @return void
	 */
	public static function on_activate() {
		// Require capability even on activation, belt-and-braces.
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		if ( ! wp_next_scheduled( 'wpuss_daily_maintenance' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'wpuss_daily_maintenance' );
		}

		// Create findings table.
		WPUSS_Logger::create_table();

		// Seed defaults.
		if ( false === get_option( 'wpuss_settings' ) ) {
			add_option(
				'wpuss_settings',
				array(
					'cpu_limit'          => 20, // percent.
					'chunk_time_limit'   => 2,  // seconds per chunk.
					'max_scan_file_size' => 2 * MB_IN_BYTES,
					'pause_on_blur'      => 1,
				)
			);
		}

		update_option( 'wpuss_version', WPUSS_VERSION );
	}

	/**
	 * Deactivation hook — unschedule cron.
	 *
	 * @return void
	 */
	public static function on_deactivate() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		$crons = array( 'wpuss_run_scan_chunk', 'wpuss_daily_maintenance' );
		foreach ( $crons as $cron ) {
			$timestamp = wp_next_scheduled( $cron );
			while ( false !== $timestamp ) {
				wp_unschedule_event( $timestamp, $cron );
				$timestamp = wp_next_scheduled( $cron );
			}
		}
	}
}
