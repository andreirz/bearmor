<?php
/**
 * Site Registration - Handles registration with call-home server
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Site_Registration {

	const CALL_HOME_URL = 'http://bearmorhome.local';
	const CALL_HOME_ENDPOINT = '/wp-json/bearmor-home/v1/register';

	/**
	 * Initialize
	 */
	public static function init() {
		error_log( 'BEARMOR: Bearmor_Site_Registration::init() called' );
		// Generate site_id on plugin activation
		add_action( 'bearmor_plugin_activated', array( __CLASS__, 'generate_site_id' ) );
		add_action( 'bearmor_plugin_activated', array( __CLASS__, 'register_site' ) );
		error_log( 'BEARMOR: Hooks registered for bearmor_plugin_activated' );
	}

	/**
	 * Generate unique site_id on first activation
	 */
	public static function generate_site_id() {
		// Check if already generated
		$site_id = get_option( 'bearmor_site_id' );
		if ( $site_id ) {
			error_log( 'BEARMOR: Site ID already exists: ' . $site_id );
			return $site_id;
		}

		// Generate new UUID
		$site_id = wp_generate_uuid4();

		// Store in options
		update_option( 'bearmor_site_id', $site_id );
		update_option( 'bearmor_site_id_created', current_time( 'mysql' ) );

		error_log( 'BEARMOR: Generated site ID: ' . $site_id );

		return $site_id;
	}

	/**
	 * Register site with call-home server
	 */
	public static function register_site() {
		error_log( 'BEARMOR: register_site() called' );
		
		$site_id = get_option( 'bearmor_site_id' );

		// Check if already registered
		$license_key = get_option( 'bearmor_license_key' );
		if ( $license_key ) {
			error_log( 'BEARMOR: Site already registered' );
			return true;
		}

		if ( ! $site_id ) {
			error_log( 'BEARMOR: No site ID found for registration' );
			return false;
		}

		// Prepare registration data
		$payload = array(
			'site_id'    => $site_id,
			'url'        => home_url(),
			'created_at' => current_time( 'mysql' ),
		);

		// Call registration endpoint
		$response = self::call_home( 'register', $payload );

		if ( is_wp_error( $response ) ) {
			error_log( 'BEARMOR: Registration failed - ' . $response->get_error_message() );
			return false;
		}

		// Store license info
		if ( isset( $response['license_key'] ) ) {
			update_option( 'bearmor_license_key', $response['license_key'] );
			update_option( 'bearmor_plan', $response['plan'] ?? 'free' );
			update_option( 'bearmor_registration_time', current_time( 'mysql' ) );

			error_log( 'BEARMOR: Site registered successfully - License: ' . $response['license_key'] );

			return true;
		}

		error_log( 'BEARMOR: Registration response missing license_key' );
		return false;
	}

	/**
	 * Call home server API
	 *
	 * @param string $endpoint Endpoint name (register, verify, uptime)
	 * @param array  $payload Data to send
	 * @return array|WP_Error Response or error
	 */
	public static function call_home( $endpoint, $payload = array() ) {
		$url = self::CALL_HOME_URL . '/index.php?rest_route=/bearmor-home/v1/' . $endpoint;

		error_log( 'BEARMOR: Calling home - URL: ' . $url );
		error_log( 'BEARMOR: Payload: ' . wp_json_encode( $payload ) );

		$args = array(
			'method'      => 'POST',
			'timeout'     => 10,
			'redirection' => 5,
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => array(
				'Content-Type' => 'application/json',
				'User-Agent'   => 'Bearmor-Security/' . BEARMOR_VERSION,
			),
			'body'        => wp_json_encode( $payload ),
		);

		$response = wp_remote_post( $url, $args );

		if ( is_wp_error( $response ) ) {
			error_log( 'BEARMOR: Call-home error: ' . $response->get_error_message() );
			return $response;
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		error_log( 'BEARMOR: Response status: ' . $status_code );
		error_log( 'BEARMOR: Response body: ' . substr( $body, 0, 500 ) );

		if ( $status_code !== 200 ) {
			error_log( 'BEARMOR: Call-home error - status ' . $status_code );
			return new WP_Error( 'call_home_error', 'Call-home server returned status ' . $status_code );
		}

		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			error_log( 'BEARMOR: Invalid JSON response: ' . $body );
			return new WP_Error( 'invalid_response', 'Invalid response from call-home server' );
		}

		error_log( 'BEARMOR: Call-home success: ' . wp_json_encode( $data ) );
		return $data;
	}

	/**
	 * Get site ID
	 *
	 * @return string|null Site ID or null
	 */
	public static function get_site_id() {
		return get_option( 'bearmor_site_id' );
	}

	/**
	 * Get license key
	 *
	 * @return string|null License key or null
	 */
	public static function get_license_key() {
		return get_option( 'bearmor_license_key' );
	}

	/**
	 * Check if site is registered
	 *
	 * @return bool Is registered
	 */
	public static function is_registered() {
		return (bool) self::get_license_key();
	}
}
