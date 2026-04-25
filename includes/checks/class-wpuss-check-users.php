<?php
/**
 * User & authentication security checks.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Users
 */
class WPUSS_Check_Users extends WPUSS_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'users';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Users & Authentication', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'admin_user', 'admin_count', 'weak_hashes', 'empty_passwords', 'display_name_login' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		switch ( $step ) {
			case 'admin_user':
				$this->check_default_admin();
				break;
			case 'admin_count':
				$this->check_admin_count();
				break;
			case 'weak_hashes':
				$this->check_password_hashes();
				break;
			case 'empty_passwords':
				$this->check_empty_passwords();
				break;
			case 'display_name_login':
				$this->check_display_name_matches_login();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Default 'admin' username.
	 *
	 * @return void
	 */
	private function check_default_admin() {
		$user = get_user_by( 'login', 'admin' );
		if ( $user && user_can( $user->ID, 'manage_options' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( "An administrator named 'admin' exists", 'wp-ultimate-security-scan' ),
				__( "The username 'admin' is the first target of brute-force attacks. Having a privileged account with this exact name halves the work an attacker needs to do.", 'wp-ultimate-security-scan' ),
				__( 'Create a new administrator with a non-obvious username, transfer content ownership, and delete the old account.', 'wp-ultimate-security-scan' ),
				'user:' . $user->ID
			);
		}
	}

	/**
	 * Too many admins.
	 *
	 * @return void
	 */
	private function check_admin_count() {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
			)
		);
		$count  = count( $admins );

		if ( $count >= 5 ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Unusually high number of administrators', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %d: count */
					__( '%d administrator accounts exist. Each is a potential point of compromise.', 'wp-ultimate-security-scan' ),
					$count
				),
				__( 'Review each administrator. Downgrade those who do not strictly need the role to Editor or a custom role.', 'wp-ultimate-security-scan' )
			);
		}
	}

	/**
	 * Look for users with non-phpass password hashes (legacy or broken).
	 *
	 * @return void
	 */
	private function check_password_hashes() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			"SELECT ID, user_login, user_pass FROM {$wpdb->users} LIMIT 500",
			ARRAY_A
		);

		foreach ( (array) $rows as $row ) {
			$hash = isset( $row['user_pass'] ) ? $row['user_pass'] : '';
			// WordPress phpass hashes start with $P$ or $H$ and are 34 chars.
			$is_phpass = ( strlen( $hash ) >= 34 && ( 0 === strpos( $hash, '$P$' ) || 0 === strpos( $hash, '$H$' ) ) );
			// bcrypt hashes start with $2y$, modern WP (6.8+) may use these.
			$is_bcrypt = ( 0 === strpos( $hash, '$2y$' ) || 0 === strpos( $hash, '$argon2' ) );

			if ( ! $is_phpass && ! $is_bcrypt && '' !== $hash ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					__( 'Non-standard password hash detected', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: login */
						__( "User '%s' has a password hash that does not match WordPress' phpass or bcrypt format. This may be a legacy md5/sha1 hash.", 'wp-ultimate-security-scan' ),
						$row['user_login']
					),
					__( 'Force a password reset for this user. Legacy hashes crack orders of magnitude faster than modern ones.', 'wp-ultimate-security-scan' ),
					'user:' . $row['ID']
				);
			}
		}
	}

	/**
	 * Users with empty password hashes.
	 *
	 * @return void
	 */
	private function check_empty_passwords() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			"SELECT ID, user_login FROM {$wpdb->users} WHERE user_pass = '' OR user_pass IS NULL",
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'User with empty password detected', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: %s: login */
					__( "User '%s' has no password set. This is usually only legitimate for SSO accounts — otherwise it is a critical vulnerability.", 'wp-ultimate-security-scan' ),
					$row['user_login']
				),
				__( "Force a password reset or disable the account.", 'wp-ultimate-security-scan' ),
				'user:' . $row['ID']
			);
		}
	}

	/**
	 * display_name equals user_login (leaks username on the front end).
	 *
	 * @return void
	 */
	private function check_display_name_matches_login() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			"SELECT ID, user_login FROM {$wpdb->users} WHERE user_login = display_name LIMIT 200",
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			if ( user_can( $row['ID'], 'edit_posts' ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_LOW,
					__( 'Display name exposes the login name', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: %s: login */
						__( "User '%s' has the same display name as login name. This reveals the login to anyone reading a byline.", 'wp-ultimate-security-scan' ),
						$row['user_login']
					),
					__( 'Set the display name to the first name, full name or nickname in the user profile.', 'wp-ultimate-security-scan' ),
					'user:' . $row['ID']
				);
			}
		}
	}
}
