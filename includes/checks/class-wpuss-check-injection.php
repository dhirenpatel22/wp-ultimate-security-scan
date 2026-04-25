<?php
/**
 * Injection vulnerability detection.
 *
 * Uses a two-phase approach:
 *
 * Phase 1 — Direct patterns: single-expression matches (unserialize directly
 *   on superglobal, etc.) that are always risky.
 *
 * Phase 2 — Intra-file taint tracking: extract variable names that are
 *   assigned from user-controlled sources ($_POST, $_GET, wrapper functions,
 *   etc.) and check whether any of those variable names appear inside
 *   dangerous sinks (unserialize, maybe_unserialize, $wpdb->query, eval,
 *   echo without escaping, shell execution, file inclusion).
 *
 * Phase 3 — Co-occurrence heuristics: if a file both reads user input AND
 *   calls maybe_unserialize(), flag it for review (catches multi-method and
 *   multi-step flows like the Formidable Forms PHP object injection class).
 *
 * All findings are heuristic. False positives are possible; the goal is to
 * direct a human reviewer to the suspicious location.
 *
 * @package WP_Ultimate_Security_Scan
 */

defined( 'ABSPATH' ) || exit;

/**
 * Class WPUSS_Check_Injection
 */
class WPUSS_Check_Injection extends WPUSS_Check_Base {

	/**
	 * Max file size to scan (bytes).
	 *
	 * @var int
	 */
	private $max_file_size;

	/**
	 * Constructor.
	 *
	 * @param string       $scan_id Scan ID.
	 * @param WPUSS_Logger $logger  Logger.
	 */
	public function __construct( $scan_id, WPUSS_Logger $logger ) {
		parent::__construct( $scan_id, $logger );
		$settings            = (array) get_option( 'wpuss_settings', array() );
		$this->max_file_size = isset( $settings['max_scan_file_size'] )
			? (int) $settings['max_scan_file_size']
			: 2 * MB_IN_BYTES;
	}

	/** @return string */
	public function get_id() {
		return 'injection';
	}

	/** @return string */
	public function get_label() {
		return __( 'Injection Vulnerabilities', 'wp-ultimate-security-scan' );
	}

	/** @return array */
	public function get_steps() {
		return array( 'scan_plugins', 'scan_themes', 'check_php_settings' );
	}

	/**
	 * Run step.
	 *
	 * @param string $step   Step.
	 * @param array  $cursor Cursor.
	 * @return array
	 */
	public function run_step( $step, array $cursor = array() ) {
		if ( 'scan_plugins' === $step ) {
			return $this->scan_tree( WP_PLUGIN_DIR, $cursor );
		}
		if ( 'scan_themes' === $step ) {
			return $this->scan_tree( get_theme_root(), $cursor );
		}
		if ( 'check_php_settings' === $step ) {
			$this->check_php_settings();
		}
		return array( 'continue' => false, 'cursor' => array() );
	}

	// -----------------------------------------------------------------------
	// Directory walker
	// -----------------------------------------------------------------------

	/**
	 * Walk a directory tree resumably, 25 PHP files per call.
	 *
	 * @param string $root   Root directory.
	 * @param array  $cursor Cursor state.
	 * @return array
	 */
	private function scan_tree( $root, array $cursor ) {
		if ( ! is_dir( $root ) ) {
			return array( 'continue' => false, 'cursor' => array() );
		}
		if ( empty( $cursor ) ) {
			$cursor = array( 'queue' => array( $root ), 'checked' => 0 );
		}

		$files_per_call = 25;
		$processed      = 0;

		while ( ! empty( $cursor['queue'] ) && $processed < $files_per_call ) {
			$current = array_shift( $cursor['queue'] );
			$handle  = @opendir( $current ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $handle ) {
				continue;
			}
			while ( false !== ( $entry = readdir( $handle ) ) && $processed < $files_per_call ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$full = $current . DIRECTORY_SEPARATOR . $entry;
				if ( false !== strpos( $full, 'wp-ultimate-security-scan' ) ) {
					continue;
				}
				if ( is_dir( $full ) ) {
					if ( in_array( $entry, array( 'node_modules', 'vendor', '.git' ), true ) ) {
						continue;
					}
					$cursor['queue'][] = $full;
				} elseif ( preg_match( '/\.php$/i', $entry ) ) {
					$this->scan_file( $full );
					$processed++;
					$cursor['checked']++;
				}
			}
			closedir( $handle );
		}

		return array(
			'continue' => ! empty( $cursor['queue'] ),
			'cursor'   => $cursor,
		);
	}

	// -----------------------------------------------------------------------
	// File scanner — three phases
	// -----------------------------------------------------------------------

	/**
	 * Scan one PHP file for injection patterns.
	 *
	 * @param string $path Absolute path.
	 * @return void
	 */
	private function scan_file( $path ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $size || $size > $this->max_file_size || 0 === $size ) {
			return;
		}
		$contents = @file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents || '' === $contents ) {
			return;
		}

		$this->phase1_direct_patterns( $path, $contents );
		$this->phase2_taint_tracking( $path, $contents );
		$this->phase3_cooccurrence( $path, $contents );
	}

	// -----------------------------------------------------------------------
	// Phase 1 — Direct, single-expression patterns
	// -----------------------------------------------------------------------

	/**
	 * Check for injection patterns where user input and the dangerous sink
	 * appear in the same expression.
	 *
	 * @param string $path     File path.
	 * @param string $contents File contents.
	 * @return void
	 */
	private function phase1_direct_patterns( $path, $contents ) {

		// PHP Object Injection — unserialize() / maybe_unserialize() directly on superglobal.
		if ( preg_match( '/\b(?:unserialize|maybe_unserialize)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'PHP Object Injection: deserialization of direct user input', 'wp-ultimate-security-scan' ),
				__( 'unserialize() or maybe_unserialize() is called directly on a superglobal. An attacker can craft a serialized payload that triggers object instantiation leading to RCE or privilege escalation via gadget chains.', 'wp-ultimate-security-scan' ),
				__( 'Never deserialize user-controlled data. Use json_decode() / wp_json_encode() for data interchange. If deserialization is unavoidable, use allowed_classes to restrict instantiable classes.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Variable variable injection: $$_GET / $$_POST.
		if ( preg_match( '/\$\$_(?:GET|POST|REQUEST|COOKIE)\[/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'Variable variable injection from user input', 'wp-ultimate-security-scan' ),
				__( 'Using $$_GET or $$_POST creates variable names from user input, letting attackers overwrite any variable in scope.', 'wp-ultimate-security-scan' ),
				__( 'Remove variable variables on user-controlled names. Access keys explicitly using a strict allowlist.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Mass variable injection via extract() on superglobals.
		if ( preg_match( '/\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'Mass variable extraction from user input', 'wp-ultimate-security-scan' ),
				__( 'extract($_POST) injects attacker-controlled keys into the current variable scope, enabling overwrite attacks.', 'wp-ultimate-security-scan' ),
				__( "Remove extract() on user input. Access keys explicitly: \$foo = sanitize_text_field( \$_POST['foo'] ?? '' );", 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Code injection — create_function() is eval() in disguise, removed in PHP 8.
		if ( preg_match( '/\bcreate_function\s*\(/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Deprecated create_function() — potential code injection', 'wp-ultimate-security-scan' ),
				__( 'create_function() is essentially eval() and was removed in PHP 8. If user input reaches its arguments it enables arbitrary code execution.', 'wp-ultimate-security-scan' ),
				__( 'Replace with a proper closure (anonymous function).', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Code injection — preg_replace() with /e modifier (removed in PHP 7.0).
		if ( preg_match( '/preg_replace\s*\(\s*["\'][^"\']*\/e[imsuUxAJD]*["\'][^,]*,/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'preg_replace() /e modifier — code injection', 'wp-ultimate-security-scan' ),
				__( 'The /e modifier executes the replacement string as PHP code. This is a critical RCE vector, removed in PHP 7.0.', 'wp-ultimate-security-scan' ),
				__( 'Replace with preg_replace_callback() and a safe callback.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// Code injection — call_user_func() with user-controlled callable.
		if ( preg_match( '/\bcall_user_func(?:_array)?\s*\([^;]*\$_(?:GET|POST|REQUEST)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'call_user_func() with user-controlled callable', 'wp-ultimate-security-scan' ),
				__( 'Passing user input as the function name to call_user_func() lets attackers invoke any PHP function including exec(), system(), eval().', 'wp-ultimate-security-scan' ),
				__( 'Validate the callable against a strict allowlist before calling.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// SQL injection — sprintf() in $wpdb query with superglobal.
		if ( preg_match( '/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\(\s*(?:sprintf|vsprintf)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'SQL injection: sprintf() building $wpdb query with user input', 'wp-ultimate-security-scan' ),
				__( 'sprintf() with user input inside a $wpdb query is SQL injection — sprintf() does not escape SQL values.', 'wp-ultimate-security-scan' ),
				__( 'Use $wpdb->prepare() with %s / %d / %f placeholders.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// SQL injection — string interpolation of superglobal in $wpdb query.
		if ( preg_match( '/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\(\s*"[^"]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'SQL injection: superglobal interpolated in $wpdb query string', 'wp-ultimate-security-scan' ),
				__( 'A superglobal is directly interpolated into a $wpdb query — this is textbook SQL injection.', 'wp-ultimate-security-scan' ),
				__( 'Use $wpdb->prepare() — never interpolate user data into SQL.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// XSS — printf() / vprintf() with superglobal.
		if ( preg_match( '/\b(?:printf|vprintf)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'XSS: printf() echoing unescaped user input', 'wp-ultimate-security-scan' ),
				__( 'printf() / vprintf() with user-supplied arguments outputs raw HTML — reflected XSS.', 'wp-ultimate-security-scan' ),
				__( 'Escape with esc_html(), esc_attr(), or esc_url() before passing to printf().', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// XSS — string interpolation of superglobal inside echo.
		if ( preg_match( '/echo\s+"[^"]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'XSS: superglobal interpolated inside echoed string', 'wp-ultimate-security-scan' ),
				__( 'Interpolating a superglobal directly inside a double-quoted echo string is reflected XSS.', 'wp-ultimate-security-scan' ),
				__( 'Wrap in esc_html(), esc_attr(), or esc_url() depending on context.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// LDAP injection.
		if ( preg_match( '/\b(?:ldap_search|ldap_list|ldap_read)\s*\([^;]*\$_(?:GET|POST|REQUEST)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'LDAP injection: LDAP query function called with user input', 'wp-ultimate-security-scan' ),
				__( 'Passing unsanitised user input to LDAP functions allows query manipulation.', 'wp-ultimate-security-scan' ),
				__( 'Escape with ldap_escape() (LDAP_ESCAPE_FILTER or LDAP_ESCAPE_DN).', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// XXE — SimpleXML with user-supplied XML string.
		if ( preg_match( '/\bsimplexml_load_string\s*\([^;]*\$_(?:GET|POST|REQUEST)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'XXE risk: SimpleXML parsing user-supplied XML', 'wp-ultimate-security-scan' ),
				__( 'Parsing attacker-controlled XML without disabling external entities can expose local files or enable SSRF.', 'wp-ultimate-security-scan' ),
				__( 'Use libxml_disable_entity_loader(true) and LIBXML_NONET | LIBXML_NOENT flags.', 'wp-ultimate-security-scan' ),
				$path
			);
		}
	}

	// -----------------------------------------------------------------------
	// Phase 2 — Intra-file taint tracking
	// -----------------------------------------------------------------------

	/**
	 * Extract variable names that are assigned from user-controlled sources,
	 * then check whether those names appear as arguments to dangerous sinks.
	 *
	 * This catches multi-line patterns like:
	 *   $values = $_POST['item_meta'];
	 *   ...
	 *   maybe_unserialize( $values[$id] );
	 *
	 * @param string $path     File path.
	 * @param string $contents File contents.
	 * @return void
	 */
	private function phase2_taint_tracking( $path, $contents ) {
		$tainted = $this->extract_tainted_vars( $contents );
		if ( empty( $tainted ) ) {
			return;
		}

		foreach ( $tainted as $var ) {
			$v = preg_quote( $var, '/' );

			// Deserialization of tainted variable.
			if ( preg_match( '/\b(?:unserialize|maybe_unserialize)\s*\([^;]*\$' . $v . '\b/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_CRITICAL,
					sprintf(
						/* translators: %s: PHP variable name */
						__( 'PHP Object Injection: $%s from user input reaches unserialize()/maybe_unserialize()', 'wp-ultimate-security-scan' ),
						$var
					),
					sprintf(
						/* translators: %s: PHP variable name */
						__( '$%s is derived from user-controlled input (superglobal or sanitized wrapper) and is later passed to unserialize() or maybe_unserialize(). This enables PHP object injection — attackers can trigger arbitrary class instantiation via gadget chains.', 'wp-ultimate-security-scan' ),
						$var
					),
					__( 'Never deserialize user data. Replace with json_decode(). If deserialization is unavoidable, restrict classes with the allowed_classes option.', 'wp-ultimate-security-scan' ),
					$path,
					array( 'tainted_var' => '$' . $var )
				);
			}

			// SQL injection via tainted variable in $wpdb query.
			if ( preg_match( '/\$wpdb\s*->\s*(?:query|get_(?:row|results|var|col))\s*\([^;]*\$' . $v . '\b/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_CRITICAL,
					sprintf(
						/* translators: %s: PHP variable name */
						__( 'SQL Injection: $%s from user input used in $wpdb query', 'wp-ultimate-security-scan' ),
						$var
					),
					sprintf(
						/* translators: %s: PHP variable name */
						__( '$%s is derived from user input and appears inside a $wpdb query method call. If this is string concatenation rather than a $wpdb->prepare() placeholder, it is SQL injection.', 'wp-ultimate-security-scan' ),
						$var
					),
					__( 'Use $wpdb->prepare() with typed placeholders (%s, %d, %f). Verify no string concatenation of $' . $var . ' reaches the SQL string.', 'wp-ultimate-security-scan' ),
					$path,
					array( 'tainted_var' => '$' . $var )
				);
			}

			// eval() on tainted variable.
			if ( preg_match( '/\beval\s*\([^;]*\$' . $v . '\b/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_CRITICAL,
					sprintf(
						/* translators: %s: PHP variable name */
						__( 'Code Injection: $%s from user input passed to eval()', 'wp-ultimate-security-scan' ),
						$var
					),
					sprintf(
						/* translators: %s: PHP variable name */
						__( '$%s originates from user input and reaches eval(). This is direct remote code execution.', 'wp-ultimate-security-scan' ),
						$var
					),
					__( 'Remove eval() entirely. There is almost never a legitimate use for eval() in plugin code.', 'wp-ultimate-security-scan' ),
					$path,
					array( 'tainted_var' => '$' . $var )
				);
			}

			// Shell execution of tainted variable.
			if ( preg_match( '/\b(?:shell_exec|exec|system|passthru|proc_open|popen)\s*\([^;]*\$' . $v . '\b/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_CRITICAL,
					sprintf(
						/* translators: %s: PHP variable name */
						__( 'Command Injection: $%s from user input in shell execution function', 'wp-ultimate-security-scan' ),
						$var
					),
					sprintf(
						/* translators: %s: PHP variable name */
						__( '$%s is from user input and reaches a shell execution function. Attackers can run arbitrary OS commands on the server.', 'wp-ultimate-security-scan' ),
						$var
					),
					__( 'Never pass user input to shell functions. If unavoidable, use escapeshellarg() and escapeshellcmd() and validate against a strict allowlist.', 'wp-ultimate-security-scan' ),
					$path,
					array( 'tainted_var' => '$' . $var )
				);
			}

			// File inclusion from tainted variable.
			if ( preg_match( '/\b(?:include|require)(?:_once)?\s*\(?\s*\$' . $v . '\b/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_CRITICAL,
					sprintf(
						/* translators: %s: PHP variable name */
						__( 'File Inclusion: $%s from user input in include/require', 'wp-ultimate-security-scan' ),
						$var
					),
					sprintf(
						/* translators: %s: PHP variable name */
						__( '$%s originates from user input and is used in a file inclusion statement. This enables local or remote file inclusion attacks.', 'wp-ultimate-security-scan' ),
						$var
					),
					__( 'Validate file paths against an explicit allowlist. Never include files whose name is user-controlled.', 'wp-ultimate-security-scan' ),
					$path,
					array( 'tainted_var' => '$' . $var )
				);
			}

			// XSS — echo of tainted variable without an escaping function.
			// Allow: esc_html($var), esc_attr($var), esc_url($var), wp_kses($var,...), intval($var), absint($var).
			// Detect: echo $var (bare), echo "$var", echo $var . "something".
			if ( preg_match( '/\becho\s+\$' . $v . '\b(?!\s*\))/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_HIGH,
					sprintf(
						/* translators: %s: PHP variable name */
						__( 'XSS: $%s from user input echoed without escaping', 'wp-ultimate-security-scan' ),
						$var
					),
					sprintf(
						/* translators: %s: PHP variable name */
						__( '$%s is derived from user input and is directly echoed without an escaping function. This is a stored or reflected XSS vulnerability.', 'wp-ultimate-security-scan' ),
						$var
					),
					__( 'Wrap in esc_html() for HTML context, esc_attr() for attribute context, or esc_url() for URL context before echoing.', 'wp-ultimate-security-scan' ),
					$path,
					array( 'tainted_var' => '$' . $var )
				);
			}

			// call_user_func with tainted callable.
			if ( preg_match( '/\bcall_user_func(?:_array)?\s*\(\s*\$' . $v . '\b/i', $contents ) ) {
				$this->finding(
					WPUSS_Logger::SEVERITY_CRITICAL,
					sprintf(
						/* translators: %s: PHP variable name */
						__( 'Code Injection: $%s from user input used as callable in call_user_func()', 'wp-ultimate-security-scan' ),
						$var
					),
					sprintf(
						/* translators: %s: PHP variable name */
						__( '$%s is from user input and is the first argument to call_user_func(), allowing attackers to invoke any PHP function.', 'wp-ultimate-security-scan' ),
						$var
					),
					__( 'Validate the callable against a strict allowlist before calling.', 'wp-ultimate-security-scan' ),
					$path,
					array( 'tainted_var' => '$' . $var )
				);
			}
		}
	}

	/**
	 * Extract names of variables that are assigned from user-controlled data.
	 *
	 * Covers:
	 *  - Direct assignment: $var = $_POST['key']
	 *  - Sanitized assignment: $var = sanitize_text_field($_POST['key'])
	 *  - wp_unslash wrapper: $var = wp_unslash($_POST['key'])
	 *  - Ternary/isset guard: $var = isset($_POST['k']) ? $_POST['k'] : ''
	 *  - wp_parse_str output array: wp_parse_str($_POST['q'], $var)
	 *  - get_param / get_post_param wrappers (common plugin pattern)
	 *
	 * @param string $contents File contents.
	 * @return array List of tainted variable names (no $ prefix).
	 */
	private function extract_tainted_vars( $contents ) {
		$tainted = array();

		$assignment_patterns = array(
			// $var = $_POST['k'] / $var = $_GET['k'] etc.
			'/\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*(?:\[[^\]]*\])?/i',
			// $var = wp_unslash($_POST['k'])
			'/\$(\w+)\s*=\s*wp_unslash\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
			// $var = sanitize_*(  $_POST['k'] ) — sanitized but still user-controlled
			'/\$(\w+)\s*=\s*sanitize_\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
			'/\$(\w+)\s*=\s*absint\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
			'/\$(\w+)\s*=\s*intval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
			// $var = isset($_POST['k']) ? $_POST['k'] : 'default'
			'/\$(\w+)\s*=\s*(?:isset\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\)?\s*\?/i',
			// wp_parse_str( $_POST['q'], $output ) — $output becomes tainted
			'/wp_parse_str\s*\([^,]*\$_(?:GET|POST|REQUEST|COOKIE)[^,]*,\s*\$(\w+)/i',
			// $var = FrmAppHelper::get_param(...) — Formidable Forms pattern
			// More broadly: any helper that contains "get_param" or "get_post_param"
			'/\$(\w+)\s*=\s*\w+::get_(?:post_)?param\s*\(/i',
			// $var = filter_input(INPUT_POST/GET, ...)
			'/\$(\w+)\s*=\s*filter_input\s*\(\s*INPUT_(?:POST|GET|REQUEST|COOKIE)/i',
		);

		foreach ( $assignment_patterns as $pattern ) {
			if ( preg_match_all( $pattern, $contents, $matches ) ) {
				$tainted = array_merge( $tainted, $matches[1] );
			}
		}

		// Also track arrays that are populated with user input via []= or array_push.
		// $arr[] = $_POST['key']  => taint $arr
		if ( preg_match_all( '/\$(\w+)\s*\[\s*[^\]]*\]\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents, $m ) ) {
			$tainted = array_merge( $tainted, $m[1] );
		}

		// Skip single-character variable names — too many false positives.
		$tainted = array_filter(
			$tainted,
			function ( $v ) {
				return strlen( $v ) > 1;
			}
		);

		return array_values( array_unique( $tainted ) );
	}

	// -----------------------------------------------------------------------
	// Phase 3 — Co-occurrence heuristics (catches multi-method / multi-file flows)
	// -----------------------------------------------------------------------

	/**
	 * Flag suspicious combinations that indicate injection risk even when the
	 * direct data flow is split across methods or files.
	 *
	 * This catches the "Formidable Forms class" of vulnerabilities where:
	 *   - An AJAX handler accepts $_POST data and passes it to a model
	 *   - A different method in the same file calls maybe_unserialize() on
	 *     what looks like field/form values
	 *
	 * @param string $path     File path.
	 * @param string $contents File contents.
	 * @return void
	 */
	private function phase3_cooccurrence( $path, $contents ) {
		$has_user_input        = (bool) preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\[/i', $contents );
		$has_nopriv_ajax       = (bool) preg_match( "/add_action\s*\(\s*['\"]wp_ajax_nopriv_/i", $contents );
		$has_any_ajax          = (bool) preg_match( "/add_action\s*\(\s*['\"]wp_ajax_/i", $contents );
		$has_maybe_unserialize = (bool) preg_match( '/\bmaybe_unserialize\s*\(/i', $contents );
		$has_unserialize       = (bool) preg_match( '/\bunserialize\s*\(/i', $contents );

		// Exclude calls that are obviously on DB results — these are typically safe.
		// Pattern: maybe_unserialize($wpdb->...) or maybe_unserialize(get_option(...)) etc.
		$safe_deserialize_context = (bool) preg_match(
			'/\b(?:maybe_unserialize|unserialize)\s*\(\s*(?:\$wpdb\s*->|get_option\s*\(|get_transient\s*\(|get_post_meta\s*\(|get_user_meta\s*\(|get_term_meta\s*\()/i',
			$contents
		);

		// --- Unauthenticated AJAX + deserialization ---
		if ( $has_nopriv_ajax && ( $has_maybe_unserialize || $has_unserialize ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_HIGH,
				__( 'Unauthenticated AJAX handler co-located with deserialization — PHP Object Injection risk', 'wp-ultimate-security-scan' ),
				__( 'This file registers a wp_ajax_nopriv_ AJAX action (accessible to unauthenticated visitors) AND calls unserialize() or maybe_unserialize(). If request data flows into the deserialization call without a separate authentication gate, this is an unauthenticated PHP object injection vulnerability.', 'wp-ultimate-security-scan' ),
				__( 'Trace the data flow from the nopriv AJAX handler to every unserialize/maybe_unserialize call. Ensure all paths require proper authentication and never pass user-controlled data to deserialization functions.', 'wp-ultimate-security-scan' ),
				$path
			);
		} elseif ( $has_user_input && $has_maybe_unserialize && ! $safe_deserialize_context ) {
			// User input read + maybe_unserialize on a non-trivially-safe value.
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'User input and maybe_unserialize() co-located — review for PHP Object Injection', 'wp-ultimate-security-scan' ),
				__( 'This file reads user-supplied data via a superglobal AND calls maybe_unserialize() on a variable. If user input flows (directly or via intermediate variables) to the deserialization call, this is a PHP object injection vulnerability. This pattern matches vulnerabilities such as CVE-2023-3681 (Formidable Forms) and similar plugin bugs.', 'wp-ultimate-security-scan' ),
				__( 'Audit every call to maybe_unserialize() in this file. Confirm each argument originates from a trusted source (database result, get_option, etc.) and never from $_POST, $_GET, or related wrappers.', 'wp-ultimate-security-scan' ),
				$path
			);
		} elseif ( $has_any_ajax && $has_maybe_unserialize && ! $safe_deserialize_context ) {
			// Authenticated AJAX + deserialization — lower severity but worth flagging.
			$this->finding(
				WPUSS_Logger::SEVERITY_LOW,
				__( 'AJAX handler and maybe_unserialize() co-located — verify no privilege escalation path', 'wp-ultimate-security-scan' ),
				__( 'This file registers an AJAX hook and calls maybe_unserialize(). If a subscriber-level user can reach a code path that calls maybe_unserialize() on their own input, this is a PHP object injection bug even without direct admin access.', 'wp-ultimate-security-scan' ),
				__( 'Verify the deserialization call is on DB-retrieved data only, and that the AJAX handler performs proper capability checks.', 'wp-ultimate-security-scan' ),
				$path
			);
		}

		// --- wp_parse_str mass assignment ---
		if ( preg_match( '/\bwp_parse_str\s*\([^,]*\$_(?:GET|POST|REQUEST|COOKIE)/i', $contents ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_MEDIUM,
				__( 'wp_parse_str() on user input — potential mass assignment', 'wp-ultimate-security-scan' ),
				__( 'wp_parse_str() parses a query string into named variables. When called on user input it can populate arbitrary variable names, similar to extract() or parse_str().', 'wp-ultimate-security-scan' ),
				__( 'Validate the resulting array against an allowlist of expected keys. Do not use the output variables without sanitising each one individually.', 'wp-ultimate-security-scan' ),
				$path
			);
		}
	}

	// -----------------------------------------------------------------------
	// PHP runtime settings
	// -----------------------------------------------------------------------

	/**
	 * Check PHP ini settings that amplify injection risk.
	 *
	 * @return void
	 */
	private function check_php_settings() {
		// register_globals turns every request var into a global — removed in PHP 5.4
		// but some legacy hosts re-enable it via user.ini.
		if ( ini_get( 'register_globals' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'PHP register_globals is enabled', 'wp-ultimate-security-scan' ),
				__( 'register_globals automatically injects GET/POST/COOKIE values as global variables, enabling variable injection across the entire codebase.', 'wp-ultimate-security-scan' ),
				__( 'Disable register_globals in php.ini immediately. It was removed from PHP 5.4.', 'wp-ultimate-security-scan' ),
				'php.ini'
			);
		}

		// allow_url_include — turns file inclusion bugs into remote code execution.
		if ( ini_get( 'allow_url_include' ) ) {
			$this->finding(
				WPUSS_Logger::SEVERITY_CRITICAL,
				__( 'PHP allow_url_include is enabled', 'wp-ultimate-security-scan' ),
				__( 'allow_url_include lets include/require load code from remote URLs. Any local file inclusion bug becomes remote code execution.', 'wp-ultimate-security-scan' ),
				__( 'Set allow_url_include = Off in php.ini.', 'wp-ultimate-security-scan' ),
				'php.ini'
			);
		}
	}
}
