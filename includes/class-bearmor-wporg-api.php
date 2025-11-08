<?php
/**
 * Bearmor WordPress.org API Class
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WordPress.org API integration for WP Core checksums only
 */
class Bearmor_WPOrg_API {

	/**
	 * Get WordPress core checksums
	 *
	 * @param string $version WordPress version (e.g., '6.4.2').
	 * @return array|false Array of checksums or false on failure.
	 */
	public static function get_core_checksums( $version = null ) {
		if ( ! $version ) {
			global $wp_version;
			$version = $wp_version;
		}

		// Check cache first
		$cache_key = 'bearmor_core_checksums_' . $version;
		$cached = get_transient( $cache_key );
		if ( $cached !== false ) {
			error_log( 'Bearmor: Using cached checksums for WP ' . $version . ' - count: ' . count( $cached ) );
			return $cached;
		}

		// Fetch from WordPress.org API
		$url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . $version;
		error_log( 'Bearmor: Fetching checksums from: ' . $url );
		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );

		if ( is_wp_error( $response ) ) {
			error_log( 'Bearmor: API request failed: ' . $response->get_error_message() );
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		error_log( 'Bearmor: Raw API response (first 500 chars): ' . substr( $body, 0, 500 ) );
		$data = json_decode( $body, true );
		error_log( 'Bearmor: Decoded data keys: ' . implode( ', ', array_keys( $data ) ) );

		if ( ! isset( $data['checksums'][ $version ] ) ) {
			error_log( 'Bearmor: No checksums for version ' . $version . ' in API response' );
			return false;
		}

		$checksums = $data['checksums'][ $version ];
		error_log( 'Bearmor: API returned ' . count( $checksums ) . ' checksums for WP ' . $version );

		// Cache for 24 hours
		set_transient( $cache_key, $checksums, DAY_IN_SECONDS );

		return $checksums;
	}
}
