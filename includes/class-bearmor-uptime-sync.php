<?php
/**
 * Bearmor Security - Uptime Sync
 * Syncs uptime data from Home server hourly
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Uptime_Sync {

	/**
	 * Initialize
	 */
	public static function init() {
		add_action( 'bearmor_hourly_uptime_sync', array( __CLASS__, 'sync_uptime_data' ) );
		
		// Schedule cron if not already scheduled
		if ( ! wp_next_scheduled( 'bearmor_hourly_uptime_sync' ) ) {
			wp_schedule_event( time(), 'hourly', 'bearmor_hourly_uptime_sync' );
		}
	}

	/**
	 * Sync uptime data from Home server (hourly)
	 */
	public static function sync_uptime_data() {
		error_log( 'BEARMOR: Starting uptime sync' );
		
		// Get site_id
		$site_id = get_option( 'bearmor_site_id' );
		if ( ! $site_id ) {
			error_log( 'BEARMOR: No site_id found, skipping uptime sync' );
			return;
		}
		
		// Call Home API to get uptime data
		$uptime_data = self::fetch_uptime_from_home( $site_id );
		
		if ( is_wp_error( $uptime_data ) ) {
			error_log( 'BEARMOR: Failed to fetch uptime data: ' . $uptime_data->get_error_message() );
			return;
		}
		
		error_log( 'BEARMOR: Uptime data received: ' . wp_json_encode( $uptime_data ) );
		error_log( 'BEARMOR: Pings in response: ' . ( isset( $uptime_data['pings'] ) ? count( $uptime_data['pings'] ) : 'NOT SET' ) );
		
		// Store downtime events and pings
		self::store_downtime_events( $uptime_data );
		
		error_log( 'BEARMOR: Uptime sync complete' );
	}

	/**
	 * Fetch uptime data from Home server
	 */
	private static function fetch_uptime_from_home( $site_id ) {
		// Use the same call_home method as license verification (GET request)
		$response = Bearmor_Site_Registration::call_home( 'uptime/' . $site_id, array(), 'GET' );
		
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		
		return $response;
	}

	/**
	 * Store all pings and downtime events in local database
	 */
	private static function store_downtime_events( $uptime_data ) {
		global $wpdb;
		
		error_log( 'BEARMOR: Storing uptime data. Pings count: ' . ( ! empty( $uptime_data['pings'] ) ? count( $uptime_data['pings'] ) : 0 ) );
		
		// Store all pings (NEW)
		if ( ! empty( $uptime_data['pings'] ) ) {
			// Clear old pings (keep last 7 days only)
			$deleted = $wpdb->query( "DELETE FROM {$wpdb->prefix}bearmor_uptime_pings WHERE pinged_at < DATE_SUB(NOW(), INTERVAL 7 DAY)" );
			error_log( 'BEARMOR: Deleted old pings: ' . $deleted );
			
			$inserted = 0;
			$skipped = 0;
			
			foreach ( $uptime_data['pings'] as $ping ) {
				// Check if ping already exists
				$existing = $wpdb->get_var( $wpdb->prepare(
					"SELECT id FROM {$wpdb->prefix}bearmor_uptime_pings 
					WHERE pinged_at = %s",
					$ping->pinged_at
				) );
				
				if ( ! $existing ) {
					// Insert new ping
					$result = $wpdb->insert(
						$wpdb->prefix . 'bearmor_uptime_pings',
						array(
							'status'        => $ping->status,
							'response_time' => $ping->response_time,
							'pinged_at'     => $ping->pinged_at,
							'synced_at'     => current_time( 'mysql' ),
						),
						array( '%s', '%d', '%s', '%s' )
					);
					
					if ( $result ) {
						$inserted++;
					} else {
						error_log( 'BEARMOR: Failed to insert ping: ' . $wpdb->last_error );
					}
				} else {
					$skipped++;
				}
			}
			
			error_log( 'BEARMOR: Pings inserted: ' . $inserted . ', skipped (duplicates): ' . $skipped );
		} else {
			error_log( 'BEARMOR: No pings in uptime_data array' );
		}
		
		// Store downtime events (existing logic)
		if ( empty( $uptime_data['downtime_events'] ) ) {
			return;
		}
		
		foreach ( $uptime_data['downtime_events'] as $event ) {
			// Check if event already exists
			$existing = $wpdb->get_row( $wpdb->prepare(
				"SELECT id FROM {$wpdb->prefix}bearmor_uptime_history 
				WHERE start_time = %s",
				$event->start_time
			) );
			
			if ( $existing ) {
				// Update existing event (e.g., when it's closed)
				$wpdb->update(
					$wpdb->prefix . 'bearmor_uptime_history',
					array(
						'end_time'         => isset( $event->end_time ) ? $event->end_time : null,
						'duration_minutes' => isset( $event->duration_minutes ) ? $event->duration_minutes : null,
						'status'           => isset( $event->status ) ? $event->status : 'open',
						'synced_at'        => current_time( 'mysql' ),
					),
					array( 'start_time' => $event->start_time ),
					array( '%s', '%d', '%s', '%s' ),
					array( '%s' )
				);
				continue;
			}
			
			// Insert new event
			$wpdb->insert(
				$wpdb->prefix . 'bearmor_uptime_history',
				array(
					'start_time'       => $event->start_time,
					'end_time'         => isset( $event->end_time ) ? $event->end_time : null,
					'duration_minutes' => isset( $event->duration_minutes ) ? $event->duration_minutes : null,
					'status'           => isset( $event->status ) ? $event->status : 'open',
					'synced_at'        => current_time( 'mysql' ),
				),
				array( '%s', '%s', '%d', '%s', '%s' )
			);
		}
	}

	/**
	 * Get uptime stats for widget
	 */
	public static function get_uptime_stats() {
		global $wpdb;
		
		$seven_days_ago = date( 'Y-m-d H:i:s', strtotime( '-7 days' ) );
		
		// Get downtime events (for last downtime display)
		$downtime_events = $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}bearmor_uptime_history 
			WHERE start_time >= %s 
			ORDER BY start_time DESC",
			$seven_days_ago
		) );
		
		// Calculate uptime from actual pings
		$total_pings = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_uptime_pings 
			WHERE pinged_at >= %s",
			$seven_days_ago
		) );
		
		$up_pings = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_uptime_pings 
			WHERE pinged_at >= %s AND status = 'up'",
			$seven_days_ago
		) );
		
		$uptime_percent = $total_pings > 0 ? round( ( $up_pings / $total_pings ) * 100, 2 ) : 100;
		
		// Calculate total downtime in minutes (for reference)
		$total_downtime = 0;
		foreach ( $downtime_events as $event ) {
			if ( $event->duration_minutes ) {
				$total_downtime += $event->duration_minutes;
			}
		}
		
		return array(
			'uptime_percent'  => $uptime_percent,
			'total_downtime'  => $total_downtime,
			'downtime_events' => $downtime_events,
		);
	}
}

// Initialize
Bearmor_Uptime_Sync::init();
