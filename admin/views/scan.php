<?php
/**
 * Scan control view.
 *
 * @package WP_Ultimate_Security_Scan
 *
 * @var array $state Passed in from render_scan_page().
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap wpuss-wrap">
	<h1><?php esc_html_e( 'WordPress Ultimate Security Scan', 'wp-ultimate-security-scan' ); ?></h1>

	<p class="description">
		<?php esc_html_e( 'Run a comprehensive background scan of your WordPress installation, themes, plugins, users and filesystem. The scan is CPU-throttled and will automatically pause if you leave this tab.', 'wp-ultimate-security-scan' ); ?>
	</p>

	<div id="wpuss-scan-panel"
		 data-status="<?php echo esc_attr( $state['status'] ); ?>"
		 data-progress="<?php echo esc_attr( (int) ( ! empty( $state['total_steps'] ) ? floor( ( $state['done_steps'] * 100 ) / $state['total_steps'] ) : 0 ) ); ?>"
		 data-scan-id="<?php echo esc_attr( $state['scan_id'] ); ?>">

		<div id="wpuss-blur-banner" class="wpuss-blur-banner" role="status" aria-live="polite" hidden>
			<span class="wpuss-blur-icon" aria-hidden="true">👋</span>
			<div class="wpuss-blur-text">
				<strong id="wpuss-blur-title"></strong>
				<span id="wpuss-blur-body"></span>
			</div>
		</div>

		<div class="wpuss-card">
			<div class="wpuss-status-row">
				<span class="wpuss-status-label"><?php esc_html_e( 'Status', 'wp-ultimate-security-scan' ); ?>:</span>
				<span class="wpuss-status-value" id="wpuss-status-text"><?php echo esc_html( ucfirst( $state['status'] ) ); ?></span>
			</div>

			<div class="wpuss-progress-wrap">
				<div class="wpuss-progress-bar">
					<div class="wpuss-progress-fill" id="wpuss-progress-fill" style="width:0%"></div>
				</div>
				<div class="wpuss-progress-meta">
					<span id="wpuss-progress-pct">0%</span>
					<span id="wpuss-progress-steps">
						<?php
						printf(
							/* translators: 1: done, 2: total */
							esc_html__( '%1$d of %2$d checks', 'wp-ultimate-security-scan' ),
							(int) $state['done_steps'],
							(int) $state['total_steps']
						);
						?>
					</span>
				</div>
			</div>

			<p id="wpuss-message" class="wpuss-message">
				<?php echo esc_html( $state['last_message'] ); ?>
			</p>

			<div class="wpuss-controls">
				<button type="button" class="button button-primary" id="wpuss-btn-start">
					<?php esc_html_e( 'Start Scan', 'wp-ultimate-security-scan' ); ?>
				</button>
				<button type="button" class="button" id="wpuss-btn-pause" disabled>
					<?php esc_html_e( 'Pause', 'wp-ultimate-security-scan' ); ?>
				</button>
				<button type="button" class="button" id="wpuss-btn-resume" disabled>
					<?php esc_html_e( 'Resume', 'wp-ultimate-security-scan' ); ?>
				</button>
				<button type="button" class="button button-link-delete" id="wpuss-btn-abort" disabled>
					<?php esc_html_e( 'Abort', 'wp-ultimate-security-scan' ); ?>
				</button>
			</div>
		</div>

		<div class="wpuss-card wpuss-summary" id="wpuss-summary" style="display:none">
			<h2><?php esc_html_e( 'Live findings', 'wp-ultimate-security-scan' ); ?></h2>
			<ul class="wpuss-summary-grid">
				<li class="sev-critical"><span class="count" data-sev="critical">0</span><span class="label"><?php esc_html_e( 'Critical', 'wp-ultimate-security-scan' ); ?></span></li>
				<li class="sev-high"><span class="count" data-sev="high">0</span><span class="label"><?php esc_html_e( 'High', 'wp-ultimate-security-scan' ); ?></span></li>
				<li class="sev-medium"><span class="count" data-sev="medium">0</span><span class="label"><?php esc_html_e( 'Medium', 'wp-ultimate-security-scan' ); ?></span></li>
				<li class="sev-low"><span class="count" data-sev="low">0</span><span class="label"><?php esc_html_e( 'Low', 'wp-ultimate-security-scan' ); ?></span></li>
				<li class="sev-info"><span class="count" data-sev="info">0</span><span class="label"><?php esc_html_e( 'Info', 'wp-ultimate-security-scan' ); ?></span></li>
			</ul>
			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . WPUSS_SLUG . '-report' ) ); ?>" class="button">
					<?php esc_html_e( 'View full report', 'wp-ultimate-security-scan' ); ?>
				</a>
			</p>
		</div>

		<div class="wpuss-card wpuss-notice-card">
			<p>
				<strong><?php esc_html_e( 'About the focus-lock:', 'wp-ultimate-security-scan' ); ?></strong>
				<?php esc_html_e( 'To avoid stealing CPU from the rest of your site, the scanner only runs chunks of work while this browser tab is focused. If you switch tabs, minimize the window, or navigate away, the scan pauses automatically and resumes when you return.', 'wp-ultimate-security-scan' ); ?>
			</p>
		</div>
	</div>
</div>
