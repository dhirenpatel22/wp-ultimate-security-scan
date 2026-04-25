<?php
/**
 * Admin UI registration.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Admin
 */
class WPUSS_Admin {

	/**
	 * Hook suffix for our top-level page.
	 *
	 * @var string
	 */
	private $hook_suffix = '';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_filter( 'plugin_action_links_' . WPUSS_PLUGIN_BASENAME, array( $this, 'action_links' ) );
	}

	/**
	 * Add the menu page.
	 *
	 * @return void
	 */
	public function register_menu() {
		$this->hook_suffix = add_menu_page(
			__( 'Security Scan', 'wp-ultimate-security-scan' ),
			__( 'Security Scan', 'wp-ultimate-security-scan' ),
			WPUSS_MIN_CAP,
			WPUSS_SLUG,
			array( $this, 'render_scan_page' ),
			'dashicons-shield-alt',
			80
		);

		add_submenu_page(
			WPUSS_SLUG,
			__( 'Scan', 'wp-ultimate-security-scan' ),
			__( 'Scan', 'wp-ultimate-security-scan' ),
			WPUSS_MIN_CAP,
			WPUSS_SLUG,
			array( $this, 'render_scan_page' )
		);

		add_submenu_page(
			WPUSS_SLUG,
			__( 'Last Report', 'wp-ultimate-security-scan' ),
			__( 'Last Report', 'wp-ultimate-security-scan' ),
			WPUSS_MIN_CAP,
			WPUSS_SLUG . '-report',
			array( $this, 'render_report_page' )
		);

		add_submenu_page(
			WPUSS_SLUG,
			__( 'Settings', 'wp-ultimate-security-scan' ),
			__( 'Settings', 'wp-ultimate-security-scan' ),
			WPUSS_MIN_CAP,
			WPUSS_SLUG . '-settings',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Enqueue admin JS/CSS only on our pages.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( false === strpos( $hook, WPUSS_SLUG ) ) {
			return;
		}

		wp_enqueue_style(
			'wpuss-admin',
			WPUSS_PLUGIN_URL . 'admin/css/admin.css',
			array(),
			WPUSS_VERSION
		);

		wp_enqueue_script(
			'wpuss-admin',
			WPUSS_PLUGIN_URL . 'admin/js/admin.js',
			array( 'jquery' ),
			WPUSS_VERSION,
			true
		);

		$settings = (array) get_option( 'wpuss_settings', array() );

		wp_localize_script(
			'wpuss-admin',
			'WPUSS',
			array(
				'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'wpuss_scan' ),
				'pauseOnBlur'   => ! empty( $settings['pause_on_blur'] ),
				'tickInterval'  => 1500, // ms between chunk requests when running.
				'pollInterval'  => 5000, // ms while paused.
				'i18n'          => array(
					'starting'     => __( 'Starting scan…', 'wp-ultimate-security-scan' ),
					'paused'       => __( 'Paused (tab not focused). Return to this tab to resume.', 'wp-ultimate-security-scan' ),
					'resumed'      => __( 'Resumed. Scanning again.', 'wp-ultimate-security-scan' ),
					'finished'     => __( 'Scan complete.', 'wp-ultimate-security-scan' ),
					'aborted'      => __( 'Scan aborted.', 'wp-ultimate-security-scan' ),
					'leaveWarn'    => __( "Hey, the scan is still running! If you close this tab it'll pause — but don't worry, it'll pick up right where it left off when you come back.", 'wp-ultimate-security-scan' ),
					'error'        => __( 'Network error. Retrying…', 'wp-ultimate-security-scan' ),
					// Funny / friendly banner copy for tab blur.
					'blurTitle'    => __( '👋 Pssst — scan paused!', 'wp-ultimate-security-scan' ),
					'blurBody'     => __( "We noticed you wandered off to another tab, so we politely paused the scan. Your server says thank you. Come back whenever — we'll pick up right where we left off.", 'wp-ultimate-security-scan' ),
					'titleActive'  => __( '🛡️ Scanning… — Security Scan', 'wp-ultimate-security-scan' ),
					'titlePaused'  => __( '⏸ Scan paused — come back!', 'wp-ultimate-security-scan' ),
					'titleDone'    => __( '✅ Scan complete — Security Scan', 'wp-ultimate-security-scan' ),
				),
			)
		);
	}

	/**
	 * Plugin action links (Settings on plugins screen).
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public function action_links( $links ) {
		$url   = admin_url( 'admin.php?page=' . WPUSS_SLUG );
		$links = array_merge(
			array( '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Scan', 'wp-ultimate-security-scan' ) . '</a>' ),
			(array) $links
		);
		return $links;
	}

	/**
	 * Render scan page.
	 *
	 * @return void
	 */
	public function render_scan_page() {
		if ( ! current_user_can( WPUSS_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-ultimate-security-scan' ) );
		}
		$scanner = new WPUSS_Scanner();
		$state   = $scanner->get_state();
		include WPUSS_PLUGIN_DIR . 'admin/views/scan.php';
	}

	/**
	 * Render report page.
	 *
	 * @return void
	 */
	public function render_report_page() {
		if ( ! current_user_can( WPUSS_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-ultimate-security-scan' ) );
		}
		$logger      = new WPUSS_Logger();
		$last_scan   = get_option( 'wpuss_last_scan', '' );
		$findings    = $last_scan ? $logger->get_findings( $last_scan ) : array();
		$summary     = $last_scan ? $logger->get_summary( $last_scan ) : array();
		include WPUSS_PLUGIN_DIR . 'admin/views/report.php';
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings_page() {
		if ( ! current_user_can( WPUSS_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-ultimate-security-scan' ) );
		}
		$this->maybe_save_settings();

		$settings = wp_parse_args(
			(array) get_option( 'wpuss_settings', array() ),
			array(
				'cpu_limit'          => 20,
				'chunk_time_limit'   => 2,
				'max_scan_file_size' => 2 * MB_IN_BYTES,
				'pause_on_blur'      => 1,
			)
		);
		include WPUSS_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * Handle settings form POST.
	 *
	 * @return void
	 */
	private function maybe_save_settings() {
		if ( empty( $_POST['wpuss_settings_submit'] ) ) {
			return;
		}
		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'wpuss_save_settings' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'wp-ultimate-security-scan' ) );
		}
		if ( ! current_user_can( WPUSS_MIN_CAP ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-ultimate-security-scan' ) );
		}

		$raw = isset( $_POST['wpuss_settings'] ) && is_array( $_POST['wpuss_settings'] )
			? wp_unslash( $_POST['wpuss_settings'] )
			: array();

		// Max file size: the form submits MB (1-20); we store bytes internally so every
		// consumer can continue to reason in bytes without change.
		$mb = 2;
		if ( isset( $raw['max_scan_file_size_mb'] ) ) {
			$mb = max( 1, min( 20, (int) $raw['max_scan_file_size_mb'] ) );
		} elseif ( isset( $raw['max_scan_file_size'] ) ) {
			// Backwards compat with old byte-based submissions.
			$mb = max( 1, min( 20, (int) round( (int) $raw['max_scan_file_size'] / MB_IN_BYTES ) ) );
		}

		// WPScan API key — preserve existing value if the field was submitted blank
		// (browser password fields submit empty when not changed by user).
		$existing     = (array) get_option( 'wpuss_settings', array() );
		$wpscan_key   = isset( $raw['wpscan_api_key'] ) ? sanitize_text_field( $raw['wpscan_api_key'] ) : '';
		if ( '' === $wpscan_key && ! empty( $existing['wpscan_api_key'] ) ) {
			$wpscan_key = $existing['wpscan_api_key'];
		}

		$clean = array(
			'cpu_limit'          => isset( $raw['cpu_limit'] ) ? max( 5, min( 80, (int) $raw['cpu_limit'] ) ) : 20,
			'chunk_time_limit'   => isset( $raw['chunk_time_limit'] ) ? max( 1, min( 10, (int) $raw['chunk_time_limit'] ) ) : 2,
			'max_scan_file_size' => $mb * MB_IN_BYTES,
			'pause_on_blur'      => ! empty( $raw['pause_on_blur'] ) ? 1 : 0,
			'wpscan_api_key'     => $wpscan_key,
		);
		update_option( 'wpuss_settings', $clean );

		add_settings_error(
			'wpuss_settings',
			'saved',
			__( 'Settings saved.', 'wp-ultimate-security-scan' ),
			'updated'
		);
	}
}
