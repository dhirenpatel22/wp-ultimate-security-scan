<?php
/**
 * Findings logger — persists scan results to a custom table.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Logger
 */
class WPUSS_Logger {

	const SEVERITY_INFO     = 'info';
	const SEVERITY_LOW      = 'low';
	const SEVERITY_MEDIUM   = 'medium';
	const SEVERITY_HIGH     = 'high';
	const SEVERITY_CRITICAL = 'critical';

	/**
	 * Get table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'wpuss_findings';
	}

	/**
	 * Create the findings table on activation.
	 *
	 * @return void
	 */
	public static function create_table() {
		global $wpdb;

		$table           = self::table();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			scan_id VARCHAR(64) NOT NULL,
			check_id VARCHAR(100) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			title VARCHAR(255) NOT NULL,
			description TEXT NOT NULL,
			recommendation TEXT NULL,
			target VARCHAR(500) NULL,
			context LONGTEXT NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY (id),
			KEY scan_id (scan_id),
			KEY severity (severity),
			KEY check_id (check_id)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Record a finding.
	 *
	 * @param string $scan_id        Current scan identifier.
	 * @param string $check_id       Slug of the check module.
	 * @param string $severity       One of the SEVERITY_* constants.
	 * @param string $title          Short human title.
	 * @param string $description    Longer description.
	 * @param string $recommendation Suggested fix.
	 * @param string $target         Optional target (file, setting, user id).
	 * @param array  $context        Optional extra structured context.
	 * @return int|false             Inserted row ID, or false on failure.
	 */
	public function record( $scan_id, $check_id, $severity, $title, $description = '', $recommendation = '', $target = '', $context = array() ) {
		global $wpdb;

		$valid_severities = array(
			self::SEVERITY_INFO,
			self::SEVERITY_LOW,
			self::SEVERITY_MEDIUM,
			self::SEVERITY_HIGH,
			self::SEVERITY_CRITICAL,
		);
		if ( ! in_array( $severity, $valid_severities, true ) ) {
			$severity = self::SEVERITY_LOW;
		}

		$data = array(
			'scan_id'        => substr( sanitize_text_field( $scan_id ), 0, 64 ),
			'check_id'       => substr( sanitize_key( $check_id ), 0, 100 ),
			'severity'       => $severity,
			'title'          => substr( sanitize_text_field( $title ), 0, 255 ),
			'description'    => wp_kses_post( $description ),
			'recommendation' => wp_kses_post( $recommendation ),
			'target'         => substr( sanitize_text_field( $target ), 0, 500 ),
			'context'        => wp_json_encode( $context ),
			'created_at'     => current_time( 'mysql', true ),
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$ok = $wpdb->insert( self::table(), $data );
		return $ok ? (int) $wpdb->insert_id : false;
	}

	/**
	 * Retrieve findings for a scan.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return array
	 */
	public function get_findings( $scan_id ) {
		global $wpdb;
		$table = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE scan_id = %s ORDER BY FIELD(severity, 'critical','high','medium','low','info'), id ASC",
				$scan_id
			),
			ARRAY_A
		);

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Count findings by severity for a scan.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return array
	 */
	public function get_summary( $scan_id ) {
		global $wpdb;
		$table = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) AS total FROM {$table} WHERE scan_id = %s GROUP BY severity",
				$scan_id
			),
			ARRAY_A
		);

		$summary = array(
			self::SEVERITY_CRITICAL => 0,
			self::SEVERITY_HIGH     => 0,
			self::SEVERITY_MEDIUM   => 0,
			self::SEVERITY_LOW      => 0,
			self::SEVERITY_INFO     => 0,
		);
		foreach ( (array) $rows as $row ) {
			$summary[ $row['severity'] ] = (int) $row['total'];
		}
		return $summary;
	}

	/**
	 * Prune findings older than the given age.
	 *
	 * @param int $max_age_seconds Age in seconds.
	 * @return int Rows deleted.
	 */
	public function prune_old( $max_age_seconds ) {
		global $wpdb;
		$table   = self::table();
		$cutoff  = gmdate( 'Y-m-d H:i:s', time() - (int) $max_age_seconds );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->query(
			$wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff )
		);
	}

	/**
	 * Delete all findings for a specific scan.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return int Rows deleted.
	 */
	public function clear_scan( $scan_id ) {
		global $wpdb;
		$table = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->query(
			$wpdb->prepare( "DELETE FROM {$table} WHERE scan_id = %s", $scan_id )
		);
	}
}
