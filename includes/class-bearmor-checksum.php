<?php
/**
 * Bearmor Checksum Class
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Checksum management class
 */
class Bearmor_Checksum {

	/**
	 * Calculate file checksum
	 *
	 * @param string $file_path Full path to file.
	 * @return string|false SHA256 hash or false on failure.
	 */
	public static function calculate( $file_path ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return false;
		}

		return hash_file( 'sha256', $file_path );
	}

	/**
	 * Store baseline checksum
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @param string $checksum SHA256 hash.
	 * @param int    $file_size File size in bytes.
	 * @return bool
	 */
	public static function store_baseline( $file_path, $checksum, $file_size ) {
		global $wpdb;

		$data = array(
			'file_path'    => $file_path,
			'checksum'     => $checksum,
			'file_size'    => $file_size,
			'last_checked' => current_time( 'mysql' ),
			'status'       => 'baseline',
		);

		$existing = $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM {$wpdb->prefix}bearmor_file_checksums WHERE file_path = %s",
			$file_path
		) );

		if ( $existing ) {
			return $wpdb->update(
				$wpdb->prefix . 'bearmor_file_checksums',
				$data,
				array( 'file_path' => $file_path ),
				array( '%s', '%s', '%d', '%s', '%s' ),
				array( '%s' )
			) !== false;
		} else {
			return $wpdb->insert(
				$wpdb->prefix . 'bearmor_file_checksums',
				$data,
				array( '%s', '%s', '%d', '%s', '%s' )
			) !== false;
		}
	}

	/**
	 * Get stored checksum
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @return object|null
	 */
	public static function get_stored( $file_path ) {
		global $wpdb;

		return $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}bearmor_file_checksums WHERE file_path = %s",
			$file_path
		) );
	}

	/**
	 * Update file status
	 *
	 * @param string $file_path File path.
	 * @param string $status Status (baseline, changed, new, deleted, safe).
	 * @return bool
	 */
	public static function update_status( $file_path, $status ) {
		global $wpdb;

		return $wpdb->update(
			$wpdb->prefix . 'bearmor_file_checksums',
			array(
				'status'       => $status,
				'last_checked' => current_time( 'mysql' ),
			),
			array( 'file_path' => $file_path ),
			array( '%s', '%s' ),
			array( '%s' )
		) !== false;
	}

	/**
	 * Log file change
	 *
	 * @param string $file_path File path.
	 * @param string $old_checksum Old hash.
	 * @param string $new_checksum New hash.
	 * @return int|false
	 */
	public static function log_change( $file_path, $old_checksum, $new_checksum ) {
		global $wpdb;

		$result = $wpdb->insert(
			$wpdb->prefix . 'bearmor_file_changes',
			array(
				'file_path'    => $file_path,
				'old_checksum' => $old_checksum,
				'new_checksum' => $new_checksum,
				'detected_at'  => current_time( 'mysql' ),
				'action_taken' => 'none',
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);

		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Get all changed files
	 *
	 * @return array
	 */
	public static function get_changed_files() {
		global $wpdb;

		return $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}bearmor_file_checksums 
			WHERE status = 'changed' 
			ORDER BY last_checked DESC"
		);
	}

	/**
	 * Get changed files count
	 *
	 * @return int
	 */
	public static function get_changed_count() {
		global $wpdb;

		return (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_checksums WHERE status = 'changed'"
		);
	}
}
