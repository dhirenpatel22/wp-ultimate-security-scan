<?php
/**
 * Settings view.
 *
 * @package WP_Ultimate_Security_Scan
 *
 * @var array $settings Passed from render_settings_page().
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap wpuss-wrap">
	<h1><?php esc_html_e( 'Scan Settings', 'wp-ultimate-security-scan' ); ?></h1>
	<?php settings_errors( 'wpuss_settings' ); ?>

	<form method="post" action="">
		<?php wp_nonce_field( 'wpuss_save_settings' ); ?>

		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row">
						<label for="wpuss_cpu_limit"><?php esc_html_e( 'Maximum CPU usage', 'wp-ultimate-security-scan' ); ?></label>
					</th>
					<td>
						<input name="wpuss_settings[cpu_limit]" id="wpuss_cpu_limit" type="number" min="5" max="80" value="<?php echo esc_attr( $settings['cpu_limit'] ); ?>" />
						<span>%</span>
						<p class="description"><?php esc_html_e( 'The scanner sleeps between units of work so it never takes more than this percentage of CPU. Default 20%.', 'wp-ultimate-security-scan' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="wpuss_chunk_time"><?php esc_html_e( 'Chunk time budget (seconds)', 'wp-ultimate-security-scan' ); ?></label>
					</th>
					<td>
						<input name="wpuss_settings[chunk_time_limit]" id="wpuss_chunk_time" type="number" min="1" max="10" value="<?php echo esc_attr( $settings['chunk_time_limit'] ); ?>" />
						<p class="description"><?php esc_html_e( 'Maximum wall-clock time a single AJAX chunk of work is allowed to take before yielding.', 'wp-ultimate-security-scan' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="wpuss_max_file"><?php esc_html_e( 'Skip files larger than (MB)', 'wp-ultimate-security-scan' ); ?></label>
					</th>
					<td>
						<?php
						// Bytes are stored internally; the form expresses the value in whole MB.
						$max_file_mb = isset( $settings['max_scan_file_size'] )
							? max( 1, (int) round( (int) $settings['max_scan_file_size'] / MB_IN_BYTES ) )
							: 2;
						?>
						<input name="wpuss_settings[max_scan_file_size_mb]" id="wpuss_max_file" type="number" step="1" min="1" max="20" value="<?php echo esc_attr( $max_file_mb ); ?>" />
						<span>MB</span>
						<p class="description"><?php esc_html_e( 'Very large PHP files are rarely malware and very expensive to regex. Accepted range: 1–20 MB. Default 2 MB.', 'wp-ultimate-security-scan' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<?php esc_html_e( 'Pause when tab is hidden', 'wp-ultimate-security-scan' ); ?>
					</th>
					<td>
						<label>
							<input name="wpuss_settings[pause_on_blur]" type="checkbox" value="1" <?php checked( $settings['pause_on_blur'] ); ?> />
							<?php esc_html_e( 'Automatically pause the scan if you switch tabs or minimize the window.', 'wp-ultimate-security-scan' ); ?>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="wpuss_wpscan_api_key"><?php esc_html_e( 'WPScan API Key', 'wp-ultimate-security-scan' ); ?></label>
					</th>
					<td>
						<input
							name="wpuss_settings[wpscan_api_key]"
							id="wpuss_wpscan_api_key"
							type="password"
							class="regular-text"
							value="<?php echo esc_attr( $settings['wpscan_api_key'] ?? '' ); ?>"
							autocomplete="new-password"
						/>
						<p class="description">
							<?php
							printf(
								/* translators: %s: link to wpscan.com */
								esc_html__( 'Optional. When set, the Vulnerability Database check queries %s for up-to-date CVE data on every installed plugin and theme. Free tier: 25 requests/day. Get a key at wpscan.com/register.', 'wp-ultimate-security-scan' ),
								'<strong>wpscan.com</strong>'
							);
							?>
							<?php if ( ! empty( $settings['wpscan_api_key'] ) ) : ?>
								<br><span style="color:#00a32a;">&#10003; <?php esc_html_e( 'API key is configured.', 'wp-ultimate-security-scan' ); ?></span>
							<?php else : ?>
								<br><em><?php esc_html_e( 'Without a key, only the built-in curated CVE list is used.', 'wp-ultimate-security-scan' ); ?></em>
							<?php endif; ?>
						</p>
					</td>
				</tr>
			</tbody>
		</table>

		<?php submit_button( __( 'Save Changes', 'wp-ultimate-security-scan' ), 'primary', 'wpuss_settings_submit' ); ?>
	</form>
</div>
