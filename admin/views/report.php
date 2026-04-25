<?php
/**
 * Report view.
 *
 * @package WP_Ultimate_Security_Scan
 *
 * @var array  $findings  Passed from render_report_page().
 * @var array  $summary   Passed from render_report_page().
 * @var string $last_scan Passed from render_report_page().
 */

defined( 'ABSPATH' ) || exit;

$severity_order = array( 'critical', 'high', 'medium', 'low', 'info' );
$severity_label = array(
	'critical' => __( 'Critical', 'wp-ultimate-security-scan' ),
	'high'     => __( 'High', 'wp-ultimate-security-scan' ),
	'medium'   => __( 'Medium', 'wp-ultimate-security-scan' ),
	'low'      => __( 'Low', 'wp-ultimate-security-scan' ),
	'info'     => __( 'Informational', 'wp-ultimate-security-scan' ),
);

$grouped = array_fill_keys( $severity_order, array() );
foreach ( (array) $findings as $f ) {
	$sev = isset( $f['severity'] ) ? $f['severity'] : 'info';
	if ( ! isset( $grouped[ $sev ] ) ) {
		$grouped[ $sev ] = array();
	}
	$grouped[ $sev ][] = $f;
}
?>
<div class="wrap wpuss-wrap">
	<h1><?php esc_html_e( 'Security Scan Report', 'wp-ultimate-security-scan' ); ?></h1>

	<?php if ( empty( $last_scan ) ) : ?>
		<div class="notice notice-info">
			<p><?php esc_html_e( 'No completed scan yet. Run a scan first.', 'wp-ultimate-security-scan' ); ?></p>
		</div>
	<?php else : ?>
		<p class="description">
			<?php
			printf(
				/* translators: %s: scan id */
				esc_html__( 'Scan ID: %s', 'wp-ultimate-security-scan' ),
				'<code>' . esc_html( $last_scan ) . '</code>'
			);
			?>
		</p>

		<div class="wpuss-card">
			<ul class="wpuss-summary-grid">
				<?php foreach ( $severity_order as $sev ) : ?>
					<li class="sev-<?php echo esc_attr( $sev ); ?>">
						<span class="count"><?php echo (int) ( isset( $summary[ $sev ] ) ? $summary[ $sev ] : 0 ); ?></span>
						<span class="label"><?php echo esc_html( $severity_label[ $sev ] ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
		</div>

		<?php foreach ( $severity_order as $sev ) : ?>
			<?php if ( empty( $grouped[ $sev ] ) ) : continue; endif; ?>
			<div class="wpuss-card wpuss-group sev-<?php echo esc_attr( $sev ); ?>">
				<h2><?php echo esc_html( $severity_label[ $sev ] ); ?> <span class="wpuss-count">(<?php echo count( $grouped[ $sev ] ); ?>)</span></h2>
				<div class="wpuss-findings">
					<?php foreach ( $grouped[ $sev ] as $f ) : ?>
						<details class="wpuss-finding sev-<?php echo esc_attr( $f['severity'] ); ?>">
							<summary>
								<span class="wpuss-finding-title"><?php echo esc_html( $f['title'] ); ?></span>
								<span class="wpuss-finding-check"><?php echo esc_html( $f['check_id'] ); ?></span>
							</summary>
							<div class="wpuss-finding-body">
								<?php if ( ! empty( $f['description'] ) ) : ?>
									<p><?php echo wp_kses_post( $f['description'] ); ?></p>
								<?php endif; ?>
								<?php if ( ! empty( $f['recommendation'] ) ) : ?>
									<p><strong><?php esc_html_e( 'Recommendation:', 'wp-ultimate-security-scan' ); ?></strong> <?php echo wp_kses_post( $f['recommendation'] ); ?></p>
								<?php endif; ?>
								<?php if ( ! empty( $f['target'] ) ) : ?>
									<p><strong><?php esc_html_e( 'Target:', 'wp-ultimate-security-scan' ); ?></strong> <code><?php echo esc_html( $f['target'] ); ?></code></p>
								<?php endif; ?>
							</div>
						</details>
					<?php endforeach; ?>
				</div>
			</div>
		<?php endforeach; ?>
	<?php endif; ?>
</div>
