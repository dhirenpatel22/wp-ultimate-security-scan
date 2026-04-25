<?php
/**
 * Scanner engine.
 *
 * Holds scan state, runs one chunk at a time, respects CPU and time budget,
 * and advances deterministically through all registered check modules.
 *
 * State is kept in an option so a scan can survive page reloads, cron runs,
 * or AJAX pauses.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Scanner
 */
class WPUSS_Scanner {

	const STATE_OPTION = 'wpuss_scan_state';

	const STATUS_IDLE      = 'idle';
	const STATUS_RUNNING   = 'running';
	const STATUS_PAUSED    = 'paused';
	const STATUS_COMPLETED = 'completed';
	const STATUS_ABORTED   = 'aborted';

	/**
	 * Logger.
	 *
	 * @var WPUSS_Logger
	 */
	private $logger;

	/**
	 * Throttle.
	 *
	 * @var WPUSS_Throttle
	 */
	private $throttle;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->logger = new WPUSS_Logger();

		$settings = (array) get_option( 'wpuss_settings', array() );
		$cpu      = isset( $settings['cpu_limit'] ) ? (int) $settings['cpu_limit'] : 20;
		$chunk    = isset( $settings['chunk_time_limit'] ) ? (float) $settings['chunk_time_limit'] : 2.0;

		$this->throttle = new WPUSS_Throttle( $cpu, $chunk );
	}

	/**
	 * All registered check modules, in order.
	 *
	 * @return array<int,string> Class names.
	 */
	public function get_check_classes() {
		return array(
			'WPUSS_Check_Core',
			'WPUSS_Check_Core_Integrity',
			'WPUSS_Check_Users',
			'WPUSS_Check_Database',
			'WPUSS_Check_Filesystem',
			'WPUSS_Check_Plugins',
			'WPUSS_Check_Themes',
			'WPUSS_Check_Config',
			'WPUSS_Check_Code_Patterns',
			'WPUSS_Check_Injection',
			'WPUSS_Check_Access_Control',
			'WPUSS_Check_Security_Config',
			'WPUSS_Check_Components',
			'WPUSS_Check_SSRF',
			'WPUSS_Check_Vuln_DB',
		);
	}

	/**
	 * Retrieve the current state (or a fresh one).
	 *
	 * @return array
	 */
	public function get_state() {
		$default = array(
			'status'       => self::STATUS_IDLE,
			'scan_id'      => '',
			'started_at'   => 0,
			'updated_at'   => 0,
			'check_index'  => 0,
			'step_index'   => 0,
			'cursor'       => array(),
			'total_steps'  => 0,
			'done_steps'   => 0,
			'last_message' => '',
			'owner_id'     => 0,
		);

		$state = get_option( self::STATE_OPTION, array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		return array_merge( $default, $state );
	}

	/**
	 * Persist state.
	 *
	 * @param array $state State.
	 * @return void
	 */
	private function save_state( array $state ) {
		$state['updated_at'] = time();
		update_option( self::STATE_OPTION, $state, false );
	}

	/**
	 * Start a new scan, discarding any previous state.
	 *
	 * @return array New state.
	 */
	public function start() {
		// Generate a new scan id.
		$scan_id = 'scan_' . gmdate( 'Ymd_His' ) . '_' . wp_generate_password( 8, false, false );

		// Count total steps for progress reporting.
		$total = 0;
		foreach ( $this->get_check_classes() as $cls ) {
			if ( ! class_exists( $cls ) ) {
				continue;
			}
			$instance = new $cls( $scan_id, $this->logger );
			$total   += count( $instance->get_steps() );
		}

		// Purge any stale findings for unfinished scans (defensive).
		$previous = $this->get_state();
		if ( ! empty( $previous['scan_id'] ) && $previous['status'] !== self::STATUS_COMPLETED ) {
			$this->logger->clear_scan( $previous['scan_id'] );
		}

		$state = array(
			'status'       => self::STATUS_RUNNING,
			'scan_id'      => $scan_id,
			'started_at'   => time(),
			'updated_at'   => time(),
			'check_index'  => 0,
			'step_index'   => 0,
			'cursor'       => array(),
			'total_steps'  => $total,
			'done_steps'   => 0,
			'last_message' => __( 'Scan started.', 'wp-ultimate-security-scan' ),
			'owner_id'     => get_current_user_id(),
		);
		$this->save_state( $state );
		return $state;
	}

	/**
	 * Pause a running scan (from the UI).
	 *
	 * @return array
	 */
	public function pause() {
		$state = $this->get_state();
		if ( self::STATUS_RUNNING === $state['status'] ) {
			$state['status']       = self::STATUS_PAUSED;
			$state['last_message'] = __( 'Scan paused.', 'wp-ultimate-security-scan' );
			$this->save_state( $state );
		}
		return $state;
	}

	/**
	 * Resume a paused scan.
	 *
	 * @return array
	 */
	public function resume() {
		$state = $this->get_state();
		if ( self::STATUS_PAUSED === $state['status'] ) {
			$state['status']       = self::STATUS_RUNNING;
			$state['last_message'] = __( 'Scan resumed.', 'wp-ultimate-security-scan' );
			$this->save_state( $state );
		}
		return $state;
	}

	/**
	 * Abort a scan entirely.
	 *
	 * @return array
	 */
	public function abort() {
		$state = $this->get_state();
		if ( in_array( $state['status'], array( self::STATUS_RUNNING, self::STATUS_PAUSED ), true ) ) {
			$state['status']       = self::STATUS_ABORTED;
			$state['last_message'] = __( 'Scan aborted by user.', 'wp-ultimate-security-scan' );
			$this->save_state( $state );
		}
		return $state;
	}

	/**
	 * Run a single chunk of work and return updated state.
	 *
	 * @param bool $from_cron True when invoked from wp-cron.
	 * @return array
	 */
	public function run_chunk( $from_cron = false ) {
		$state = $this->get_state();

		if ( self::STATUS_RUNNING !== $state['status'] ) {
			return $state;
		}

		$classes = $this->get_check_classes();
		$this->throttle->start_chunk();

		while ( $state['check_index'] < count( $classes ) && ! $this->throttle->should_yield() ) {
			$cls = $classes[ $state['check_index'] ];
			if ( ! class_exists( $cls ) ) {
				$state['check_index']++;
				$state['step_index'] = 0;
				$state['cursor']     = array();
				continue;
			}

			$check = new $cls( $state['scan_id'], $this->logger );
			$steps = $check->get_steps();

			if ( $state['step_index'] >= count( $steps ) ) {
				$state['check_index']++;
				$state['step_index'] = 0;
				$state['cursor']     = array();
				continue;
			}

			$step = $steps[ $state['step_index'] ];
			$state['last_message'] = sprintf(
				/* translators: 1: check label, 2: step id */
				__( 'Running %1$s → %2$s', 'wp-ultimate-security-scan' ),
				$check->get_label(),
				$step
			);

			$started = microtime( true );
			try {
				$result = $check->run_step( $step, (array) $state['cursor'] );
			} catch ( \Throwable $e ) {
				// Don't kill the scan on a single failed check.
				$this->logger->record(
					$state['scan_id'],
					$check->get_id(),
					WPUSS_Logger::SEVERITY_INFO,
					__( 'Check module error', 'wp-ultimate-security-scan' ),
					$e->getMessage()
				);
				$result = array( 'continue' => false, 'cursor' => array() );
			}
			$elapsed = microtime( true ) - $started;

			$continue = isset( $result['continue'] ) ? (bool) $result['continue'] : false;
			$cursor   = isset( $result['cursor'] ) && is_array( $result['cursor'] ) ? $result['cursor'] : array();

			if ( $continue ) {
				// Same step again with updated cursor; don't advance step counter.
				$state['cursor'] = $cursor;
			} else {
				$state['step_index']++;
				$state['cursor']   = array();
				$state['done_steps'] = min( $state['total_steps'], $state['done_steps'] + 1 );
			}

			// Throttle proportional to work just done.
			$this->throttle->throttle( $elapsed );

			// Re-read status in case UI paused us mid-chunk.
			$fresh = $this->get_state();
			if ( self::STATUS_RUNNING !== $fresh['status'] ) {
				// Preserve counters we advanced — merge current iteration state back in.
				$state['status'] = $fresh['status'];
				break;
			}
		}

		// Done?
		if ( self::STATUS_RUNNING === $state['status'] && $state['check_index'] >= count( $classes ) ) {
			$state['status']       = self::STATUS_COMPLETED;
			$state['last_message'] = __( 'Scan complete.', 'wp-ultimate-security-scan' );
			$state['done_steps']   = $state['total_steps'];

			update_option( 'wpuss_last_scan', $state['scan_id'], false );
		}

		$this->save_state( $state );

		// If we were called from cron and the scan is still running, re-schedule.
		if ( $from_cron && self::STATUS_RUNNING === $state['status'] && ! wp_next_scheduled( 'wpuss_run_scan_chunk' ) ) {
			wp_schedule_single_event( time() + 10, 'wpuss_run_scan_chunk' );
		}

		return $state;
	}

	/**
	 * Compute progress percentage.
	 *
	 * @param array $state State.
	 * @return int 0-100
	 */
	public function get_progress( array $state ) {
		if ( empty( $state['total_steps'] ) ) {
			return 0;
		}
		return (int) min( 100, floor( ( $state['done_steps'] * 100 ) / $state['total_steps'] ) );
	}
}
