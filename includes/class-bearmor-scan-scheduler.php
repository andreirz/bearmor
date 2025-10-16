<?php
/**
 * Scan Scheduler - WP Cron for automated scans
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Scan_Scheduler {

	/**
	 * Initialize scheduler
	 */
	public static function init() {
		// Schedule hooks
		add_action( 'bearmor_daily_malware_scan', array( __CLASS__, 'run_malware_scan' ) );
		add_action( 'bearmor_weekly_deep_scan', array( __CLASS__, 'run_deep_scan' ) );

		// Register schedules on plugin activation
		add_action( 'bearmor_activate', array( __CLASS__, 'schedule_scans' ) );
		add_action( 'bearmor_deactivate', array( __CLASS__, 'unschedule_scans' ) );
	}

	/**
	 * Schedule scans on plugin activation
	 */
	public static function schedule_scans() {
		// Get settings
		$malware_enabled = get_option( 'bearmor_malware_scan_enabled', true );
		$deep_scan_enabled = get_option( 'bearmor_deep_scan_enabled', false );

		// Schedule malware scan (daily at 2 AM)
		if ( $malware_enabled && ! wp_next_scheduled( 'bearmor_daily_malware_scan' ) ) {
			$time = strtotime( '02:00:00' );
			wp_schedule_event( $time, 'daily', 'bearmor_daily_malware_scan' );
			error_log( 'BEARMOR: Scheduled daily malware scan at 2 AM' );
		}

		// Schedule deep scan (weekly on Sunday at 3 AM)
		if ( $deep_scan_enabled && ! wp_next_scheduled( 'bearmor_weekly_deep_scan' ) ) {
			$time = strtotime( 'next Sunday 03:00:00' );
			wp_schedule_event( $time, 'weekly', 'bearmor_weekly_deep_scan' );
			error_log( 'BEARMOR: Scheduled weekly deep scan on Sunday at 3 AM' );
		}
	}

	/**
	 * Unschedule scans on plugin deactivation
	 */
	public static function unschedule_scans() {
		wp_clear_scheduled_hook( 'bearmor_daily_malware_scan' );
		wp_clear_scheduled_hook( 'bearmor_weekly_deep_scan' );
		error_log( 'BEARMOR: Unscheduled all scans' );
	}

	/**
	 * Run malware scan (WP Cron callback)
	 */
	public static function run_malware_scan() {
		error_log( 'BEARMOR: Starting scheduled malware scan' );

		if ( ! class_exists( 'Bearmor_Malware_Scanner' ) ) {
			error_log( 'BEARMOR: Malware scanner class not found' );
			return;
		}

		// Run scan
		$result = Bearmor_Malware_Scanner::run_scan();

		if ( is_wp_error( $result ) ) {
			error_log( 'BEARMOR: Malware scan error - ' . $result->get_error_message() );
		} else {
			error_log( 'BEARMOR: Malware scan completed - ' . $result['threats'] . ' threats found' );
		}
	}

	/**
	 * Run deep scan (WP Cron callback)
	 */
	public static function run_deep_scan() {
		error_log( 'BEARMOR: Starting scheduled deep scan' );

		if ( ! class_exists( 'Bearmor_DB_Scanner' ) ) {
			error_log( 'BEARMOR: Deep scan class not found' );
			return;
		}

		// Run database scan
		$db_result = Bearmor_DB_Scanner::scan();
		error_log( 'BEARMOR: Database scan completed' );

		// Run uploads scan
		if ( class_exists( 'Bearmor_Uploads_Scanner' ) ) {
			$uploads_result = Bearmor_Uploads_Scanner::scan();
			error_log( 'BEARMOR: Uploads scan completed' );
		}
	}

	/**
	 * Enable/disable scheduled scans
	 *
	 * @param string $scan_type 'malware' or 'deep'
	 * @param bool   $enabled Enable or disable
	 */
	public static function set_scan_enabled( $scan_type, $enabled ) {
		if ( $scan_type === 'malware' ) {
			update_option( 'bearmor_malware_scan_enabled', $enabled );
			
			if ( $enabled && ! wp_next_scheduled( 'bearmor_daily_malware_scan' ) ) {
				$time = strtotime( '02:00:00' );
				wp_schedule_event( $time, 'daily', 'bearmor_daily_malware_scan' );
			} elseif ( ! $enabled ) {
				wp_clear_scheduled_hook( 'bearmor_daily_malware_scan' );
			}
		} elseif ( $scan_type === 'deep' ) {
			update_option( 'bearmor_deep_scan_enabled', $enabled );
			
			if ( $enabled && ! wp_next_scheduled( 'bearmor_weekly_deep_scan' ) ) {
				$time = strtotime( 'next Sunday 03:00:00' );
				wp_schedule_event( $time, 'weekly', 'bearmor_weekly_deep_scan' );
			} elseif ( ! $enabled ) {
				wp_clear_scheduled_hook( 'bearmor_weekly_deep_scan' );
			}
		}
	}

	/**
	 * Get next scheduled scan time
	 *
	 * @param string $scan_type 'malware' or 'deep'
	 * @return int|false Timestamp or false
	 */
	public static function get_next_scan_time( $scan_type ) {
		if ( $scan_type === 'malware' ) {
			return wp_next_scheduled( 'bearmor_daily_malware_scan' );
		} elseif ( $scan_type === 'deep' ) {
			return wp_next_scheduled( 'bearmor_weekly_deep_scan' );
		}
		return false;
	}
}
