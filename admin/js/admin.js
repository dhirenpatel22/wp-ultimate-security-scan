/**
 * WP Ultimate Security Scan — admin controller.
 *
 * Implements:
 *  - Start / pause / resume / abort buttons
 *  - A tick loop that sends AJAX "chunk" requests while the scan is running
 *    AND the tab is focused and visible
 *  - Auto-pause on blur / visibilitychange (matches server-side settings)
 *  - beforeunload warning while a scan is in progress
 *
 * @package WP_Ultimate_Security_Scan
 */

( function ( $ ) {
	'use strict';

	if ( typeof window.WPUSS === 'undefined' ) {
		return;
	}

	var cfg = window.WPUSS;
	var $panel = $( '#wpuss-scan-panel' );
	if ( ! $panel.length ) {
		return;
	}

	var tickTimer = null;
	var pollTimer = null;
	var inFlight  = false;
	var lastStatus = $panel.data( 'status' ) || 'idle';
	var awaitingResume = false; // user-intent flag: scan should continue once tab refocused.

	var $status    = $( '#wpuss-status-text' );
	var $msg       = $( '#wpuss-message' );
	var $fill      = $( '#wpuss-progress-fill' );
	var $pct       = $( '#wpuss-progress-pct' );
	var $steps     = $( '#wpuss-progress-steps' );
	var $summary   = $( '#wpuss-summary' );
	var $btnStart  = $( '#wpuss-btn-start' );
	var $btnPause  = $( '#wpuss-btn-pause' );
	var $btnResume = $( '#wpuss-btn-resume' );
	var $btnAbort  = $( '#wpuss-btn-abort' );

	// Friendly focus-loss banner + title handling.
	var $blurBanner = $( '#wpuss-blur-banner' );
	var $blurTitle  = $( '#wpuss-blur-title' );
	var $blurBody   = $( '#wpuss-blur-body' );
	var originalTitle = document.title;

	function setDocTitle( key ) {
		if ( cfg.i18n && cfg.i18n[ key ] ) {
			document.title = cfg.i18n[ key ];
		} else {
			document.title = originalTitle;
		}
	}

	function showBlurBanner() {
		$blurTitle.text( cfg.i18n.blurTitle || '' );
		$blurBody.text( cfg.i18n.blurBody || '' );
		$blurBanner.prop( 'hidden', false ).addClass( 'is-visible' );
	}

	function hideBlurBanner() {
		$blurBanner.removeClass( 'is-visible' ).prop( 'hidden', true );
	}

	function setButtons( status ) {
		switch ( status ) {
			case 'running':
				$btnStart.prop( 'disabled', true );
				$btnPause.prop( 'disabled', false );
				$btnResume.prop( 'disabled', true );
				$btnAbort.prop( 'disabled', false );
				break;
			case 'paused':
				$btnStart.prop( 'disabled', true );
				$btnPause.prop( 'disabled', true );
				$btnResume.prop( 'disabled', false );
				$btnAbort.prop( 'disabled', false );
				break;
			case 'completed':
			case 'aborted':
			case 'idle':
			default:
				$btnStart.prop( 'disabled', false );
				$btnPause.prop( 'disabled', true );
				$btnResume.prop( 'disabled', true );
				$btnAbort.prop( 'disabled', true );
				break;
		}
	}

	function updateUI( data ) {
		if ( ! data ) {
			return;
		}
		lastStatus = data.status || lastStatus;

		$status.text( data.status.charAt( 0 ).toUpperCase() + data.status.slice( 1 ) );
		$msg.text( data.message || '' );

		var pct = parseInt( data.progress, 10 ) || 0;
		$fill.css( 'width', pct + '%' );
		$pct.text( pct + '%' );
		$steps.text( ( data.done_steps || 0 ) + ' of ' + ( data.total_steps || 0 ) + ' checks' );

		if ( data.summary ) {
			$summary.show();
			$summary.find( '.count' ).each( function () {
				var sev = $( this ).data( 'sev' );
				$( this ).text( data.summary[ sev ] || 0 );
			} );
		}

		// Keep the tab title accurate so the user sees state from other tabs.
		if ( 'running' === lastStatus ) {
			if ( isTabActive() ) {
				setDocTitle( 'titleActive' );
			}
		} else if ( 'paused' === lastStatus ) {
			setDocTitle( 'titlePaused' );
		} else if ( 'completed' === lastStatus ) {
			setDocTitle( 'titleDone' );
			hideBlurBanner();
		} else if ( 'aborted' === lastStatus || 'idle' === lastStatus ) {
			document.title = originalTitle;
			hideBlurBanner();
		}

		setButtons( lastStatus );
	}

	function ajax( action ) {
		return $.ajax( {
			url: cfg.ajaxUrl,
			method: 'POST',
			dataType: 'json',
			data: {
				action: 'wpuss_' + action,
				_wpnonce: cfg.nonce
			}
		} );
	}

	function tick() {
		if ( inFlight ) {
			return;
		}
		// Only run work chunks while the tab is visible and focused.
		if ( cfg.pauseOnBlur && ! isTabActive() ) {
			return;
		}
		if ( 'running' !== lastStatus ) {
			return;
		}

		inFlight = true;
		ajax( 'tick' )
			.done( function ( resp ) {
				if ( resp && resp.success ) {
					updateUI( resp.data );
					if ( 'completed' === resp.data.status ) {
						$msg.text( cfg.i18n.finished );
						stopLoops();
					} else if ( 'aborted' === resp.data.status ) {
						stopLoops();
					}
				}
			} )
			.fail( function () {
				$msg.text( cfg.i18n.error );
			} )
			.always( function () {
				inFlight = false;
			} );
	}

	function poll() {
		if ( inFlight ) {
			return;
		}
		inFlight = true;
		ajax( 'status' )
			.done( function ( resp ) {
				if ( resp && resp.success ) {
					updateUI( resp.data );
				}
			} )
			.always( function () {
				inFlight = false;
			} );
	}

	function startLoops() {
		stopLoops();
		tickTimer = window.setInterval( tick, cfg.tickInterval );
		pollTimer = window.setInterval( poll, cfg.pollInterval );
	}

	function stopLoops() {
		if ( tickTimer ) {
			window.clearInterval( tickTimer );
			tickTimer = null;
		}
		if ( pollTimer ) {
			window.clearInterval( pollTimer );
			pollTimer = null;
		}
	}

	function isTabActive() {
		if ( 'undefined' !== typeof document.hidden ) {
			if ( document.hidden ) {
				return false;
			}
		}
		if ( 'undefined' !== typeof document.hasFocus ) {
			return document.hasFocus();
		}
		return true;
	}

	// --- Button handlers --- .

	$btnStart.on( 'click', function () {
		$btnStart.prop( 'disabled', true );
		$msg.text( cfg.i18n.starting );
		ajax( 'start' ).done( function ( resp ) {
			if ( resp && resp.success ) {
				updateUI( resp.data );
				awaitingResume = true;
				startLoops();
			}
		} );
	} );

	$btnPause.on( 'click', function () {
		ajax( 'pause' ).done( function ( resp ) {
			if ( resp && resp.success ) {
				updateUI( resp.data );
				awaitingResume = false;
			}
		} );
	} );

	$btnResume.on( 'click', function () {
		ajax( 'resume' ).done( function ( resp ) {
			if ( resp && resp.success ) {
				updateUI( resp.data );
				awaitingResume = true;
				startLoops();
			}
		} );
	} );

	$btnAbort.on( 'click', function () {
		if ( ! window.confirm( 'Abort this scan? Partial findings will be discarded.' ) ) {
			return;
		}
		ajax( 'abort' ).done( function ( resp ) {
			if ( resp && resp.success ) {
				updateUI( resp.data );
				awaitingResume = false;
				stopLoops();
			}
		} );
	} );

	// --- Focus / visibility handling — the "keep user on the tab" behavior --- .

	function onFocusLost() {
		if ( ! cfg.pauseOnBlur ) {
			return;
		}
		if ( 'running' === lastStatus ) {
			// Immediately flip the tab title so the user sees the pause from the tab bar.
			setDocTitle( 'titlePaused' );
			// Ask server to pause so no more work happens.
			ajax( 'pause' ).done( function ( resp ) {
				if ( resp && resp.success ) {
					updateUI( resp.data );
					$msg.text( cfg.i18n.paused );
					awaitingResume = true; // Remember: auto-resume on focus.
				}
			} );
		}
	}

	function onFocusGained() {
		hideBlurBanner();
		if ( ! cfg.pauseOnBlur ) {
			return;
		}
		// Auto-resume only if the user had started a scan and hadn't manually paused it.
		if ( awaitingResume && 'paused' === lastStatus ) {
			ajax( 'resume' ).done( function ( resp ) {
				if ( resp && resp.success ) {
					updateUI( resp.data );
					$msg.text( cfg.i18n.resumed );
					setDocTitle( 'titleActive' );
					startLoops();
				}
			} );
		} else if ( 'running' !== lastStatus ) {
			// Restore the default title when nothing is running.
			document.title = originalTitle;
		}
	}

	$( window ).on( 'blur', function () {
		if ( cfg.pauseOnBlur && 'running' === lastStatus ) {
			showBlurBanner();
		}
		onFocusLost();
	} );
	$( window ).on( 'focus', onFocusGained );
	document.addEventListener( 'visibilitychange', function () {
		if ( document.hidden ) {
			if ( cfg.pauseOnBlur && 'running' === lastStatus ) {
				showBlurBanner();
			}
			onFocusLost();
		} else {
			onFocusGained();
		}
	} );

	// Warn on leave while running.
	window.addEventListener( 'beforeunload', function ( e ) {
		if ( 'running' === lastStatus || 'paused' === lastStatus ) {
			e.preventDefault();
			e.returnValue = cfg.i18n.leaveWarn;
			return cfg.i18n.leaveWarn;
		}
	} );

	// Resume loops on page load if state was already active.
	if ( 'running' === lastStatus ) {
		awaitingResume = true;
		startLoops();
	} else if ( 'paused' === lastStatus ) {
		// Poll so the UI stays in sync but don't auto-resume — user paused deliberately.
		pollTimer = window.setInterval( poll, cfg.pollInterval );
	}

	// Initial state render.
	setButtons( lastStatus );

	// Kick off an initial status fetch so summary populates on reload.
	if ( $panel.data( 'scan-id' ) ) {
		poll();
	}
} )( jQuery );
