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

// Build tabs: severity → { count, groups: issue-title → [findings] }
// Findings with identical titles are the same issue type and are merged so
// the user sees one collapsible row per type, with all affected targets listed
// inside rather than one row per individual finding.
$tabs = array();
foreach ( $severity_order as $sev ) {
	$tabs[ $sev ] = array(
		'count'  => 0,
		'groups' => array(),
	);
}

foreach ( (array) $findings as $f ) {
	$sev   = ( isset( $f['severity'] ) && isset( $tabs[ $f['severity'] ] ) )
	         ? $f['severity'] : 'info';
	$title = ( isset( $f['title'] ) && '' !== trim( (string) $f['title'] ) )
	         ? trim( (string) $f['title'] )
	         : __( 'Unknown issue', 'wp-ultimate-security-scan' );
	$tabs[ $sev ]['count']++;
	$tabs[ $sev ]['groups'][ $title ][] = $f;
}

// Default active tab: first severity that has findings.
$active_tab = 'info';
foreach ( $severity_order as $sev ) {
	if ( $tabs[ $sev ]['count'] > 0 ) {
		$active_tab = $sev;
		break;
	}
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

		<!-- Summary counts — tiles with findings are clickable to jump to that tab -->
		<div class="wpuss-card">
			<ul class="wpuss-summary-grid">
				<?php foreach ( $severity_order as $sev ) : ?>
					<li
						class="sev-<?php echo esc_attr( $sev ); ?><?php echo esc_attr( $tabs[ $sev ]['count'] > 0 ? ' is-clickable' : '' ); ?>"
						<?php if ( $tabs[ $sev ]['count'] > 0 ) : ?>
							data-tab="<?php echo esc_attr( $sev ); ?>"
							role="button"
							tabindex="0"
						<?php endif; ?>
					>
						<span class="count"><?php echo (int) ( isset( $summary[ $sev ] ) ? $summary[ $sev ] : 0 ); ?></span>
						<span class="label"><?php echo esc_html( $severity_label[ $sev ] ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
		</div>

		<!-- Severity tabs -->
		<div class="wpuss-tabs">
			<nav class="wpuss-tab-nav" role="tablist" aria-label="<?php esc_attr_e( 'Findings by severity', 'wp-ultimate-security-scan' ); ?>">
				<?php foreach ( $severity_order as $sev ) : ?>
					<button
						id="wpuss-tab-btn-<?php echo esc_attr( $sev ); ?>"
						class="wpuss-tab-btn sev-<?php echo esc_attr( $sev ); ?><?php echo esc_attr( $sev === $active_tab ? ' is-active' : '' ); ?>"
						data-tab="<?php echo esc_attr( $sev ); ?>"
						role="tab"
						aria-selected="<?php echo esc_attr( $sev === $active_tab ? 'true' : 'false' ); ?>"
						aria-controls="wpuss-tab-<?php echo esc_attr( $sev ); ?>"
						<?php disabled( 0, $tabs[ $sev ]['count'] ); ?>
					>
						<?php echo esc_html( $severity_label[ $sev ] ); ?>
						<span class="wpuss-tab-count"><?php echo (int) $tabs[ $sev ]['count']; ?></span>
					</button>
				<?php endforeach; ?>
			</nav>

			<div class="wpuss-tab-panels">
				<?php foreach ( $severity_order as $sev ) : ?>
					<div
						id="wpuss-tab-<?php echo esc_attr( $sev ); ?>"
						class="wpuss-tab-panel<?php echo esc_attr( $sev === $active_tab ? ' is-active' : '' ); ?>"
						role="tabpanel"
						aria-labelledby="wpuss-tab-btn-<?php echo esc_attr( $sev ); ?>"
					>
						<?php if ( empty( $tabs[ $sev ]['groups'] ) ) : ?>
							<p class="description"><?php esc_html_e( 'No issues at this severity level.', 'wp-ultimate-security-scan' ); ?></p>
						<?php else : ?>
							<?php foreach ( $tabs[ $sev ]['groups'] as $issue_title => $instances ) :
								$count       = count( $instances );
								$first       = $instances[0];
								$check_id    = isset( $first['check_id'] ) ? (string) $first['check_id'] : '';
								$ctx         = ( ! empty( $first['context'] ) ) ? json_decode( $first['context'], true ) : array();
								$plugin_name = ( is_array( $ctx ) && ! empty( $ctx['plugin_name'] ) ) ? (string) $ctx['plugin_name'] : '';
							?>
								<details class="wpuss-finding sev-<?php echo esc_attr( $sev ); ?>">
									<summary>
										<span class="wpuss-finding-title"><?php echo esc_html( $issue_title ); ?></span>
										<?php if ( '' !== $check_id ) : ?>
											<span class="wpuss-finding-check"><?php echo esc_html( $check_id ); ?></span>
										<?php endif; ?>
										<?php if ( 1 === $count && '' !== $plugin_name ) : ?>
											<span class="wpuss-issue-badge"><?php echo esc_html( $plugin_name ); ?></span>
										<?php endif; ?>
										<?php if ( $count > 1 ) : ?>
											<span class="wpuss-issue-badge">
												<?php echo esc_html(
													sprintf(
														/* translators: %d: number of affected items */
														_n( '%d instance', '%d instances', $count, 'wp-ultimate-security-scan' ),
														$count
													)
												); ?>
											</span>
										<?php endif; ?>
									</summary>
									<div class="wpuss-finding-body">
										<?php if ( ! empty( $first['description'] ) ) : ?>
											<p><?php echo wp_kses_post( $first['description'] ); ?></p>
										<?php endif; ?>
										<?php if ( ! empty( $first['recommendation'] ) ) : ?>
											<p><strong><?php esc_html_e( 'Recommendation:', 'wp-ultimate-security-scan' ); ?></strong>
											<?php echo wp_kses_post( $first['recommendation'] ); ?></p>
										<?php endif; ?>
										<?php if ( 1 === $count ) : ?>
											<?php if ( ! empty( $first['target'] ) ) : ?>
												<p><strong><?php esc_html_e( 'Target:', 'wp-ultimate-security-scan' ); ?></strong>
												<code><?php echo esc_html( $first['target'] ); ?></code></p>
											<?php endif; ?>
										<?php else : ?>
											<div class="wpuss-instances">
												<p class="wpuss-instances-label"><?php esc_html_e( 'Affected items:', 'wp-ultimate-security-scan' ); ?></p>
												<ul class="wpuss-target-list">
													<?php foreach ( $instances as $inst ) : ?>
														<?php if ( ! empty( $inst['target'] ) ) : ?>
															<li><code><?php echo esc_html( $inst['target'] ); ?></code></li>
														<?php endif; ?>
													<?php endforeach; ?>
												</ul>
											</div>
										<?php endif; ?>
									</div>
								</details>
							<?php endforeach; ?>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
	<?php endif; ?>
</div>
