<?php
/**
 * Daily Call-Home Scheduler
 *
 * Handles automatic daily verification with call-home server
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_CallHome {

	const HOOK_NAME = 'bearmor_daily_callhome';

	/**
	 * Initialize
	 */
	public static function init() {
		// Schedule daily call-home on activation
		add_action( 'bearmor_plugin_activated', array( __CLASS__, 'schedule_daily_callhome' ) );
		
		// Handle the scheduled call-home
		add_action( self::HOOK_NAME, array( __CLASS__, 'daily_callhome' ) );
		
		// Clean up on deactivation
		add_action( 'bearmor_plugin_deactivated', array( __CLASS__, 'unschedule_daily_callhome' ) );
	}

	/**
	 * Schedule daily call-home
	 */
	public static function schedule_daily_callhome() {
		error_log( 'BEARMOR: Scheduling daily call-home' );
		
		// Only schedule if not already scheduled
		if ( ! wp_next_scheduled( self::HOOK_NAME ) ) {
			wp_schedule_event( time(), 'daily', self::HOOK_NAME );
			error_log( 'BEARMOR: Daily call-home scheduled' );
		}
	}

	/**
	 * Unschedule daily call-home
	 */
	public static function unschedule_daily_callhome() {
		error_log( 'BEARMOR: Unscheduling daily call-home' );
		wp_clear_scheduled_hook( self::HOOK_NAME );
	}

	/**
	 * Daily call-home verification
	 */
	public static function daily_callhome() {
		error_log( '=== BEARMOR: Daily call-home started ===' );
		
		$site_id = get_option( 'bearmor_site_id' );
		
		if ( ! $site_id ) {
			error_log( 'BEARMOR: Site ID not found, skipping call-home' );
			return;
		}
		
		error_log( 'BEARMOR: Verifying license for site: ' . $site_id );
		
		// Call verify endpoint
		$result = Bearmor_Site_Registration::call_home( 'verify', array(
			'site_id' => $site_id,
			'url'     => home_url(),
		) );
		
		if ( is_wp_error( $result ) ) {
			error_log( 'BEARMOR: Daily call-home failed: ' . $result->get_error_message() );
			return;
		}
		
		// Update license from response
		error_log( 'BEARMOR: Updating license from daily call-home' );
		Bearmor_License::update_from_response( $result );
		
		error_log( '=== BEARMOR: Daily call-home completed ===' );
	}

	/**
	 * Manually trigger call-home (for testing)
	 */
	public static function trigger_now() {
		error_log( 'BEARMOR: Manual call-home triggered' );
		self::daily_callhome();
	}
}
