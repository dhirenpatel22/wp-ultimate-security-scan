<?php
/**
 * Uninstall handler for WPUSS.
 *
 * Runs only when the plugin is deleted through the WP UI (not deactivated).
 * Removes all persistent data created by the plugin.
 *
 * @package WP_Ultimate_Security_Scan
 */

// Fired only by WordPress when plugin is deleted.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Delete options.
$options = array(
	'wpuss_version',
	'wpuss_settings',
	'wpuss_last_scan',
	'wpuss_last_report',
	'wpuss_cpu_limit',
	'wpuss_scan_state',
);

foreach ( $options as $option ) {
	delete_option( $option );
	delete_site_option( $option ); // Multisite safety.
}

// Delete transients created by the scanner.
// Direct query is acceptable in uninstall — we are deleting bulk rows and the
// public transient API does not support wildcard deletion.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_wpuss_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_wpuss_' ) . '%'
	)
);

// Clear any scheduled cron events.
$crons = array( 'wpuss_run_scan_chunk', 'wpuss_daily_maintenance' );
foreach ( $crons as $cron ) {
	$timestamp = wp_next_scheduled( $cron );
	while ( false !== $timestamp ) {
		wp_unschedule_event( $timestamp, $cron );
		$timestamp = wp_next_scheduled( $cron );
	}
}

// Drop custom table if created.
$table = $wpdb->prefix . 'wpuss_findings';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange
$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
