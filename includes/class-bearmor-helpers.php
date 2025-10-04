<?php
/**
 * Bearmor Security Helper Functions
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Helper class with utility functions
 */
class Bearmor_Helpers {

	/**
	 * Get plugin settings
	 *
	 * @param string $key Optional. Specific setting key to retrieve.
	 * @return mixed
	 */
	public static function get_settings( $key = '' ) {
		$settings = get_option( 'bearmor_settings', array() );

		if ( ! empty( $key ) ) {
			return isset( $settings[ $key ] ) ? $settings[ $key ] : null;
		}

		return $settings;
	}

	/**
	 * Update plugin settings
	 *
	 * @param array $new_settings Settings to update.
	 * @return bool
	 */
	public static function update_settings( $new_settings ) {
		$current_settings = self::get_settings();
		$updated_settings = wp_parse_args( $new_settings, $current_settings );
		
		return update_option( 'bearmor_settings', $updated_settings );
	}

	/**
	 * Check if Pro features are enabled
	 *
	 * @return bool
	 */
	public static function is_pro_enabled() {
		$license_cache = get_transient( 'bearmor_license_cache' );
		
		if ( $license_cache && isset( $license_cache['pro_enabled'] ) ) {
			return (bool) $license_cache['pro_enabled'];
		}

		return false;
	}

	/**
	 * Get current plan (free/paid/pro)
	 *
	 * @return string
	 */
	public static function get_plan() {
		$license_cache = get_transient( 'bearmor_license_cache' );
		
		if ( $license_cache && isset( $license_cache['plan'] ) ) {
			return $license_cache['plan'];
		}

		return 'free';
	}

	/**
	 * Log audit action
	 *
	 * @param string $action_type Type of action performed.
	 * @param string $target_type Type of target (file, plugin, setting, etc.).
	 * @param string $target_path Path or identifier of target.
	 * @param string $details Optional. Additional details.
	 * @return int|false
	 */
	public static function log_audit( $action_type, $target_type, $target_path = '', $details = '' ) {
		global $wpdb;

		$data = array(
			'action_type'  => $action_type,
			'target_type'  => $target_type,
			'target_path'  => $target_path,
			'performed_by' => get_current_user_id(),
			'performed_at' => current_time( 'mysql' ),
			'details'      => $details,
		);

		$result = $wpdb->insert(
			$wpdb->prefix . 'bearmor_audit_log',
			$data,
			array( '%s', '%s', '%s', '%d', '%s', '%s' )
		);

		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Get unread notification count
	 *
	 * @return int
	 */
	public static function get_unread_notification_count() {
		global $wpdb;

		$count = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_notifications 
			WHERE read_at IS NULL AND dismissed_at IS NULL"
		);

		return (int) $count;
	}

	/**
	 * Check if current user can manage security
	 *
	 * @return bool
	 */
	public static function current_user_can_manage() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Get security score (0-100)
	 *
	 * @return int
	 */
	public static function get_security_score() {
		// Simple score for now - will be enhanced later
		return 85;
	}
}
