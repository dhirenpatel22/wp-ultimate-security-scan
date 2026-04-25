<?php
/**
 * Database configuration checks.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Database
 */
class WPUSS_Check_Database extends WPUSS_Check_Base {

	/**
	 * ID.
	 *
	 * @return string
	 */
	public function get_id() {
		return 'database';
	}

	/**
	 * Label.
	 *
	 * @return string
	 */
	public function get_label() {
		return __( 'Database', 'wp-ultimate-security-scan' );
	}

	/**
	 * Steps.
	 *
	 * @return array
	 */
	public function get_steps() {
		return array( 'unknown_admins', 'suspicious_options' );
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
			case 'unknown_admins':
				$this->check_unknown_admins();
				break;
			case 'suspicious_options':
				$this->check_suspicious_options();
				break;
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	/**
	 * Very-recently-created admin accounts (possible compromise indicator).
	 *
	 * @return void
	 */
	private function check_unknown_admins() {
		$since   = gmdate( 'Y-m-d H:i:s', time() - ( 7 * DAY_IN_SECONDS ) );
		$recent  = get_users(
			array(
				'role'     => 'administrator',
				'number'   => 20,
				'date_query' => array(
					array(
						'after' => $since,
					),
				),
			)
		);

		foreach ( (array) $recent as $u ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'Administrator created in the last 7 days', 'wp-ultimate-security-scan' ),
				sprintf(
					/* translators: 1: login, 2: date */
					__( "Administrator '%1\$s' was created on %2\$s. If you did not create this account, your site may be compromised.", 'wp-ultimate-security-scan' ),
					$u->user_login,
					$u->user_registered
				),
				__( 'Verify with your team. If unfamiliar, revoke access, rotate all admin passwords, and scan for backdoors.', 'wp-ultimate-security-scan' ),
				'user:' . $u->ID
			);
		}
	}

	/**
	 * Options that are not permitted to be modified suspiciously.
	 *
	 * @return void
	 */
	private function check_suspicious_options() {
		// Admins registerable to anyone is risky.
		if ( get_option( 'users_can_register' ) && 'administrator' === get_option( 'default_role' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'Open registration with administrator default role', 'wp-ultimate-security-scan' ),
				__( 'Anyone can register and is automatically granted administrator. This is almost certainly a compromise.', 'wp-ultimate-security-scan' ),
				__( 'Disable public registration or set the default role to Subscriber in Settings → General.', 'wp-ultimate-security-scan' )
			);
		}

		// Unexpected siteurl/home mismatch.
		$site_url = get_option( 'siteurl' );
		$home     = get_option( 'home' );
		if ( $site_url && $home ) {
			$site_host = wp_parse_url( $site_url, PHP_URL_HOST );
			$home_host = wp_parse_url( $home, PHP_URL_HOST );
			if ( $site_host && $home_host && $site_host !== $home_host ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					__( 'siteurl and home point to different domains', 'wp-ultimate-security-scan' ),
					sprintf(
						/* translators: 1: siteurl, 2: home */
						__( 'siteurl (%1$s) and home (%2$s) resolve to different hosts. Malware often sets one of these to an attacker-controlled domain.', 'wp-ultimate-security-scan' ),
						$site_url,
						$home
					),
					__( 'Confirm both values in Settings → General are correct. If not, revert and investigate.', 'wp-ultimate-security-scan' )
				);
			}
		}
	}
}
