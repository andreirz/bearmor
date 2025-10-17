<?php
/**
 * License Management - Handles local license data and verification
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_License {

	/**
	 * Get current plan
	 *
	 * @return string Plan (free, trial, pro)
	 */
	public static function get_plan() {
		return get_option( 'bearmor_plan', 'free' );
	}

	/**
	 * Check if Pro is enabled
	 *
	 * @return bool Is Pro enabled
	 */
	public static function is_pro() {
		return get_transient( 'bearmor_pro_enabled' ) === true;
	}

	/**
	 * Get license expiry date
	 *
	 * @return string|null Expiry date or null
	 */
	public static function get_expiry() {
		return get_transient( 'bearmor_license_expires' );
	}

	/**
	 * Get last verification time
	 *
	 * @return string|null Last verification or null
	 */
	public static function get_last_verified() {
		return get_option( 'bearmor_last_verified' );
	}

	/**
	 * Get license status
	 *
	 * @return string Status (active, expired, failed, unknown)
	 */
	public static function get_status() {
		$plan = self::get_plan();

		if ( $plan === 'free' ) {
			return 'active';
		}

		// Check if Pro is enabled (from last verification)
		if ( self::is_pro() ) {
			$expiry = self::get_expiry();
			if ( $expiry && strtotime( $expiry ) < time() ) {
				return 'expired';
			}
			return 'active';
		}

		// Check grace period
		$last_verified = self::get_last_verified();
		if ( ! $last_verified ) {
			return 'unknown';
		}

		$grace_period = get_option( 'bearmor_grace_period', 7 );
		$days_since_verified = ( time() - strtotime( $last_verified ) ) / DAY_IN_SECONDS;

		if ( $days_since_verified > $grace_period ) {
			return 'failed';
		}

		return 'unknown';
	}

	/**
	 * Update license from verification response
	 *
	 * @param array $response Verification response from call-home
	 */
	public static function update_from_response( $response ) {
		if ( ! is_array( $response ) ) {
			return;
		}

		// Store Pro status in transient (24h cache)
		if ( isset( $response['pro_enabled'] ) ) {
			set_transient( 'bearmor_pro_enabled', (bool) $response['pro_enabled'], DAY_IN_SECONDS );
		}

		// Store plan
		if ( isset( $response['plan'] ) ) {
			update_option( 'bearmor_plan', $response['plan'] );
		}

		// Store expiry
		if ( isset( $response['expires'] ) ) {
			set_transient( 'bearmor_license_expires', $response['expires'], DAY_IN_SECONDS );
		}

		// Update last verified
		update_option( 'bearmor_last_verified', current_time( 'mysql' ) );

		error_log( 'BEARMOR: License updated - Pro: ' . ( $response['pro_enabled'] ? 'yes' : 'no' ) . ', Plan: ' . $response['plan'] );
	}

	/**
	 * Request trial license
	 *
	 * @return bool|WP_Error Success or error
	 */
	public static function request_trial() {
		$site_id = Bearmor_Site_Registration::get_site_id();

		if ( ! $site_id ) {
			return new WP_Error( 'no_site_id', 'Site not registered' );
		}

		// In production, this would call the call-home server
		// For now, we'll just update local options
		update_option( 'bearmor_plan', 'trial' );
		set_transient( 'bearmor_trial_requested', current_time( 'mysql' ), DAY_IN_SECONDS );

		error_log( 'BEARMOR: Trial requested for site: ' . $site_id );

		return true;
	}

	/**
	 * Get grace period setting
	 *
	 * @return int Grace period in days
	 */
	public static function get_grace_period() {
		return (int) get_option( 'bearmor_grace_period', 7 );
	}

	/**
	 * Set grace period
	 *
	 * @param int $days Grace period in days
	 */
	public static function set_grace_period( $days ) {
		update_option( 'bearmor_grace_period', (int) $days );
	}

	/**
	 * Check if Pro features should be available
	 *
	 * @return bool Should show Pro features
	 */
	public static function should_show_pro_features() {
		$plan = self::get_plan();

		// Free plan never shows Pro features
		if ( $plan === 'free' ) {
			return false;
		}

		// Check if Pro is enabled from last verification
		if ( self::is_pro() ) {
			$expiry = self::get_expiry();
			if ( ! $expiry || strtotime( $expiry ) > time() ) {
				return true;
			}
		}

		// Check grace period
		$last_verified = self::get_last_verified();
		if ( $last_verified ) {
			$grace_period = self::get_grace_period();
			$days_since_verified = ( time() - strtotime( $last_verified ) ) / DAY_IN_SECONDS;

			if ( $days_since_verified <= $grace_period ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get license info for display
	 *
	 * @return array License info
	 */
	public static function get_info() {
		return array(
			'site_id'         => Bearmor_Site_Registration::get_site_id(),
			'license_key'     => Bearmor_Site_Registration::get_license_key(),
			'plan'            => self::get_plan(),
			'status'          => self::get_status(),
			'pro_enabled'     => self::is_pro(),
			'expires'         => self::get_expiry(),
			'last_verified'   => self::get_last_verified(),
			'grace_period'    => self::get_grace_period(),
			'is_registered'   => Bearmor_Site_Registration::is_registered(),
		);
	}
}
