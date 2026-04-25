<?php
/**
 * CPU throttle helper.
 *
 * Keeps the scanner's CPU usage at or below a configured percentage by
 * measuring how long a unit of work took and then sleeping for a
 * proportional amount of time before continuing.
 *
 * Example: if cpu_limit = 20 (%), the scanner will sleep 4× the time
 * the last unit of work took (work / total = 20%).
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Throttle
 */
class WPUSS_Throttle {

	/**
	 * Max percentage of CPU the scanner is allowed to use (1-100).
	 *
	 * @var int
	 */
	private $cpu_limit;

	/**
	 * Max wall-clock time for a single scan chunk, in seconds.
	 *
	 * @var float
	 */
	private $chunk_time_limit;

	/**
	 * Chunk start timestamp (microtime float).
	 *
	 * @var float
	 */
	private $chunk_started_at = 0.0;

	/**
	 * Constructor.
	 *
	 * @param int   $cpu_limit         Percentage (1-100).
	 * @param float $chunk_time_limit  Seconds.
	 */
	public function __construct( $cpu_limit = 20, $chunk_time_limit = 2.0 ) {
		$cpu_limit       = (int) $cpu_limit;
		$this->cpu_limit = max( 1, min( 100, $cpu_limit ) );

		$chunk_time_limit       = (float) $chunk_time_limit;
		$this->chunk_time_limit = max( 0.25, min( 10.0, $chunk_time_limit ) );
	}

	/**
	 * Mark the start of a scan chunk.
	 *
	 * @return void
	 */
	public function start_chunk() {
		$this->chunk_started_at = microtime( true );
	}

	/**
	 * Has the current chunk exceeded its time budget?
	 *
	 * @return bool
	 */
	public function should_yield() {
		if ( 0.0 === $this->chunk_started_at ) {
			return false;
		}
		return ( microtime( true ) - $this->chunk_started_at ) >= $this->chunk_time_limit;
	}

	/**
	 * Sleep proportionally to keep CPU usage at or below the configured limit.
	 *
	 * @param float $work_seconds Time the last unit of work took.
	 * @return void
	 */
	public function throttle( $work_seconds ) {
		$work_seconds = max( 0.0, (float) $work_seconds );
		if ( $work_seconds <= 0.0 ) {
			return;
		}

		// total_time * (cpu_limit/100) = work_seconds.
		// => sleep_seconds = work_seconds * (100 - cpu_limit) / cpu_limit.
		$sleep_seconds = $work_seconds * ( 100 - $this->cpu_limit ) / $this->cpu_limit;

		// Hard cap sleep at 2 seconds so we never stall for too long.
		$sleep_seconds = min( 2.0, $sleep_seconds );

		if ( $sleep_seconds > 0.0 ) {
			// usleep expects microseconds.
			usleep( (int) ( $sleep_seconds * 1000000 ) );
		}
	}

	/**
	 * Convenience — run a callable with automatic throttling.
	 *
	 * @param callable $work Function to execute.
	 * @return mixed Return value of $work.
	 */
	public function run_throttled( callable $work ) {
		$started = microtime( true );
		$result  = call_user_func( $work );
		$elapsed = microtime( true ) - $started;
		$this->throttle( $elapsed );
		return $result;
	}
}
