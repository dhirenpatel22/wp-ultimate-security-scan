<?php
/**
 * Base class for all security check modules.
 *
 * A "check module" inspects one concern area (core, users, code, etc.)
 * and can be broken into discrete "steps" so the scanner can yield
 * between them and keep CPU usage low.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Base
 */
abstract class WPUSS_Check_Base {

	/**
	 * Scan identifier.
	 *
	 * @var string
	 */
	protected $scan_id;

	/**
	 * Logger.
	 *
	 * @var WPUSS_Logger
	 */
	protected $logger;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Current scan ID.
	 * @param WPUSS_Logger $logger  Logger instance.
	 */
	public function __construct( $scan_id, WPUSS_Logger $logger ) {
		$this->scan_id = $scan_id;
		$this->logger  = $logger;
	}

	/**
	 * Unique identifier for this check module (used in findings & UI).
	 *
	 * @return string
	 */
	abstract public function get_id();

	/**
	 * Human-readable label.
	 *
	 * @return string
	 */
	abstract public function get_label();

	/**
	 * List of step identifiers this check can run.
	 *
	 * Each step should be small enough to fit inside one CPU-throttled unit
	 * of work (roughly a few hundred ms).
	 *
	 * @return array<int,string>
	 */
	abstract public function get_steps();

	/**
	 * Execute a single step.
	 *
	 * May return an array with 'continue' => true if there is more work
	 * for this step, in which case the scanner will call it again without
	 * advancing the step pointer.
	 *
	 * @param string $step    Step identifier.
	 * @param array  $cursor  Opaque cursor stored between invocations.
	 * @return array { 'continue' => bool, 'cursor' => array }
	 */
	abstract public function run_step( $step, array $cursor = array() );

	/**
	 * Helper — record a finding with this check's id.
	 *
	 * @param string $severity       Severity.
	 * @param string $title          Title.
	 * @param string $description    Description.
	 * @param string $recommendation Recommendation.
	 * @param string $target         Target.
	 * @param array  $context        Context.
	 * @return void
	 */
	protected function finding( $severity, $title, $description = '', $recommendation = '', $target = '', $context = array() ) {
		$this->logger->record(
			$this->scan_id,
			$this->get_id(),
			$severity,
			$title,
			$description,
			$recommendation,
			$target,
			$context
		);
	}
}
