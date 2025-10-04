<?php
/**
 * Bearmor Security Settings Management
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings management class
 */
class Bearmor_Settings {

	/**
	 * Initialize settings
	 */
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
	}

	/**
	 * Register plugin settings
	 */
	public static function register_settings() {
		register_setting(
			'bearmor_settings_group',
			'bearmor_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( __CLASS__, 'sanitize_settings' ),
			)
		);
	}

	/**
	 * Sanitize settings before saving
	 *
	 * @param array $input Raw input data.
	 * @return array
	 */
	public static function sanitize_settings( $input ) {
		$sanitized = array();

		// Scan schedule
		if ( isset( $input['scan_schedule'] ) ) {
			$allowed_schedules = array( 'manual', 'daily', 'weekly' );
			$sanitized['scan_schedule'] = in_array( $input['scan_schedule'], $allowed_schedules, true ) 
				? $input['scan_schedule'] 
				: 'daily';
		}

		// Notification method
		if ( isset( $input['notification_method'] ) ) {
			$allowed_methods = array( 'dashboard', 'email', 'both' );
			$sanitized['notification_method'] = in_array( $input['notification_method'], $allowed_methods, true ) 
				? $input['notification_method'] 
				: 'dashboard';
		}

		// Email notifications
		$sanitized['email_notifications'] = isset( $input['email_notifications'] ) 
			? (bool) $input['email_notifications'] 
			: false;

		// Notification email
		if ( isset( $input['notification_email'] ) ) {
			$sanitized['notification_email'] = sanitize_email( $input['notification_email'] );
		}

		// Auto-quarantine
		$sanitized['auto_quarantine'] = isset( $input['auto_quarantine'] ) 
			? (bool) $input['auto_quarantine'] 
			: false;

		// Auto-disable vulnerable plugins
		$sanitized['auto_disable_vulnerable'] = isset( $input['auto_disable_vulnerable'] ) 
			? (bool) $input['auto_disable_vulnerable'] 
			: false;

		// Safe mode
		$sanitized['safe_mode'] = isset( $input['safe_mode'] ) 
			? (bool) $input['safe_mode'] 
			: true;

		// Preserve first activation timestamp
		$current_settings = Bearmor_Helpers::get_settings();
		if ( isset( $current_settings['first_activation'] ) ) {
			$sanitized['first_activation'] = $current_settings['first_activation'];
		}

		// Log settings change
		Bearmor_Helpers::log_audit(
			'setting_change',
			'setting',
			'global_settings',
			'Settings updated'
		);

		return $sanitized;
	}
}
