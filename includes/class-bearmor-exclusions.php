<?php
/**
 * File Exclusions - Pattern matching for scan exclusions
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Bearmor_Exclusions {

	/**
	 * Default exclusion patterns
	 */
	const DEFAULT_PATTERNS = array(
		'node_modules/',
		'vendor/',
		'.git/',
		'.gitignore',
		'*.min.js',
		'*.min.css',
		'wp-content/cache/',
		'wp-content/backup-*/',
	);

	/**
	 * Get all exclusion patterns
	 *
	 * @return array Patterns
	 */
	public static function get_patterns() {
		$custom = get_option( 'bearmor_scan_exclusions', array() );
		$default = self::DEFAULT_PATTERNS;

		// Merge and remove duplicates
		$patterns = array_unique( array_merge( $default, $custom ) );

		return array_values( $patterns );
	}

	/**
	 * Add custom exclusion pattern
	 *
	 * @param string $pattern Pattern to exclude
	 * @return bool Success
	 */
	public static function add_pattern( $pattern ) {
		$pattern = sanitize_text_field( $pattern );

		if ( empty( $pattern ) ) {
			return false;
		}

		$patterns = get_option( 'bearmor_scan_exclusions', array() );

		if ( in_array( $pattern, $patterns, true ) ) {
			return false; // Already exists
		}

		$patterns[] = $pattern;
		update_option( 'bearmor_scan_exclusions', $patterns );

		error_log( 'BEARMOR: Added exclusion pattern: ' . $pattern );

		return true;
	}

	/**
	 * Remove exclusion pattern
	 *
	 * @param string $pattern Pattern to remove
	 * @return bool Success
	 */
	public static function remove_pattern( $pattern ) {
		$patterns = get_option( 'bearmor_scan_exclusions', array() );
		$key = array_search( $pattern, $patterns, true );

		if ( $key === false ) {
			return false;
		}

		unset( $patterns[ $key ] );
		update_option( 'bearmor_scan_exclusions', array_values( $patterns ) );

		error_log( 'BEARMOR: Removed exclusion pattern: ' . $pattern );

		return true;
	}

	/**
	 * Check if file should be excluded
	 *
	 * @param string $file_path File path
	 * @return bool True if excluded
	 */
	public static function should_exclude( $file_path ) {
		$patterns = self::get_patterns();

		foreach ( $patterns as $pattern ) {
			if ( self::matches_pattern( $file_path, $pattern ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if file matches pattern
	 *
	 * @param string $file_path File path
	 * @param string $pattern Pattern (glob-style)
	 * @return bool Match
	 */
	private static function matches_pattern( $file_path, $pattern ) {
		// Normalize paths
		$file_path = str_replace( '\\', '/', $file_path );
		$pattern = str_replace( '\\', '/', $pattern );

		// Exact match
		if ( $file_path === $pattern ) {
			return true;
		}

		// Directory match (ends with /)
		if ( substr( $pattern, -1 ) === '/' ) {
			return strpos( $file_path, $pattern ) === 0;
		}

		// Wildcard match
		if ( strpos( $pattern, '*' ) !== false ) {
			return fnmatch( $pattern, $file_path );
		}

		// Substring match
		return strpos( $file_path, $pattern ) !== false;
	}

	/**
	 * Filter file list by exclusions
	 *
	 * @param array $files List of files
	 * @return array Filtered list
	 */
	public static function filter_files( $files ) {
		return array_filter( $files, function( $file ) {
			return ! self::should_exclude( $file );
		} );
	}

	/**
	 * Get exclusion patterns as text (for UI)
	 *
	 * @return string Patterns (one per line)
	 */
	public static function get_patterns_text() {
		$patterns = get_option( 'bearmor_scan_exclusions', array() );
		return implode( "\n", $patterns );
	}

	/**
	 * Set exclusion patterns from text (for UI)
	 *
	 * @param string $text Patterns (one per line)
	 */
	public static function set_patterns_text( $text ) {
		$lines = explode( "\n", $text );
		$patterns = array();

		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( ! empty( $line ) ) {
				$patterns[] = sanitize_text_field( $line );
			}
		}

		update_option( 'bearmor_scan_exclusions', $patterns );
		error_log( 'BEARMOR: Updated exclusion patterns - ' . count( $patterns ) . ' patterns' );
	}
}
