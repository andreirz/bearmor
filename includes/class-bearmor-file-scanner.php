<?php
/**
 * Bearmor File Scanner Class
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * File scanner class
 */
class Bearmor_File_Scanner {

	/**
	 * Excluded directories and patterns
	 */
	private static $excluded_patterns = array(
		'/wp-content/uploads/',
		'/wp-content/cache/',
		'/wp-content/backup/',
		'/wp-content/bearmor-quarantine/',
		'.log',
		'.tmp',
		'.cache',
		'/node_modules/',
		'/vendor/',
	);

	/**
	 * Allowed file extensions to scan (executable/injectable files only)
	 * Optimized for speed - skip images, videos, fonts, etc.
	 */
	private static $allowed_extensions = array(
		'php',
		'js',
		'html',
		'htm',
		'css',
	);

	/**
	 * Run baseline scan
	 *
	 * @return array Scan results.
	 */
	public static function run_baseline_scan() {
		$results = array(
			'scanned' => 0,
			'stored'  => 0,
			'errors'  => 0,
			'time'    => 0,
		);

		$start_time = microtime( true );

		// Scan WP core
		$core_files = self::get_core_files();
		foreach ( $core_files as $file ) {
			if ( self::should_exclude( $file ) ) {
				continue;
			}

			$results['scanned']++;
			$checksum = Bearmor_Checksum::calculate( $file );
			
			if ( $checksum ) {
				$relative_path = str_replace( ABSPATH, '', $file );
				$file_size = filesize( $file );
				
				if ( Bearmor_Checksum::store_baseline( $relative_path, $checksum, $file_size ) ) {
					$results['stored']++;
				} else {
					$results['errors']++;
				}
			} else {
				$results['errors']++;
			}
		}

		// Scan plugins
		$plugin_files = self::get_plugin_files();
		foreach ( $plugin_files as $file ) {
			if ( self::should_exclude( $file ) ) {
				continue;
			}

			$results['scanned']++;
			$checksum = Bearmor_Checksum::calculate( $file );
			
			if ( $checksum ) {
				$relative_path = str_replace( ABSPATH, '', $file );
				$file_size = filesize( $file );
				
				if ( Bearmor_Checksum::store_baseline( $relative_path, $checksum, $file_size ) ) {
					$results['stored']++;
				} else {
					$results['errors']++;
				}
			} else {
				$results['errors']++;
			}
		}

		// Scan themes
		$theme_files = self::get_theme_files();
		foreach ( $theme_files as $file ) {
			if ( self::should_exclude( $file ) ) {
				continue;
			}

			$results['scanned']++;
			$checksum = Bearmor_Checksum::calculate( $file );
			
			if ( $checksum ) {
				$relative_path = str_replace( ABSPATH, '', $file );
				$file_size = filesize( $file );
				
				if ( Bearmor_Checksum::store_baseline( $relative_path, $checksum, $file_size ) ) {
					$results['stored']++;
				} else {
					$results['errors']++;
				}
			} else {
				$results['errors']++;
			}
		}

		$results['time'] = round( microtime( true ) - $start_time, 2 );

		// Update last scan time
		update_option( 'bearmor_last_scan_time', current_time( 'mysql' ) );
		update_option( 'bearmor_last_scan_status', 'completed' );

		return $results;
	}

	/**
	 * Run integrity check
	 * - WP Core: Compare against WordPress.org API
	 * - Plugins/Themes: Compare against baseline (created on activation/update)
	 *
	 * @return array Check results.
	 */
	public static function run_integrity_check() {
		$results = array(
			'checked' => 0,
			'changed' => 0,
			'time'    => 0,
		);

		$start_time = microtime( true );

		error_log( 'Bearmor: Starting integrity check' );

		// 1. Check WordPress Core Files against API
		error_log( 'Bearmor: About to check core files' );
		$core_results = self::check_core_files();
		error_log( 'Bearmor: Core check returned - checked: ' . $core_results['checked'] . ', changed: ' . $core_results['changed'] );
		$results['checked'] += $core_results['checked'];
		$results['changed'] += $core_results['changed'];

		// 2. Check Plugins against baseline
		$plugin_results = self::check_plugins_baseline();
		$results['checked'] += $plugin_results['checked'];
		$results['changed'] += $plugin_results['changed'];

		// 3. Check Themes against baseline
		$theme_results = self::check_themes_baseline();
		$results['checked'] += $theme_results['checked'];
		$results['changed'] += $theme_results['changed'];

		// 4. Check wp-config.php
		$config_results = self::check_wp_config();
		$results['checked'] += $config_results['checked'];
		$results['changed'] += $config_results['changed'];

		// 5. Check mu-plugins if exists
		$mu_results = self::check_mu_plugins();
		$results['checked'] += $mu_results['checked'];
		$results['changed'] += $mu_results['changed'];

		$results['time'] = round( microtime( true ) - $start_time, 2 );

		// Update last scan time
		update_option( 'bearmor_last_scan_time', current_time( 'mysql' ) );
		update_option( 'bearmor_last_scan_status', 'completed' );

		return $results;
	}

	/**
	 * Check WordPress core files against official checksums from WordPress.org API
	 *
	 * @return array Results.
	 */
	private static function check_core_files() {
		$results = array( 'checked' => 0, 'changed' => 0 );

		// Get official checksums from WordPress.org
		$official_checksums = Bearmor_WPOrg_API::get_core_checksums();
		if ( ! $official_checksums ) {
			// Log API failure for debugging
			error_log( 'Bearmor: WP Core API failed or returned no checksums' );
			return $results; // API failed, skip core check
		}
		
		error_log( 'Bearmor: WP Core API returned ' . count( $official_checksums ) . ' checksums' );

		foreach ( $official_checksums as $file => $expected_hash ) {
			$full_path = ABSPATH . $file;
			
			if ( ! file_exists( $full_path ) || self::should_exclude( $full_path ) ) {
				continue;
			}

			$results['checked']++;
			$current_hash = md5_file( $full_path );

			if ( $current_hash !== $expected_hash ) {
				// Core file modified!
				$relative_path = str_replace( ABSPATH, '', $full_path );
				Bearmor_Checksum::store_baseline( $relative_path, $current_hash, filesize( $full_path ) );
				Bearmor_Checksum::update_status( $relative_path, 'changed' );
				Bearmor_Checksum::log_change( $relative_path, $expected_hash, $current_hash );
				$results['changed']++;
			}
		}

		return $results;
	}

	/**
	 * Check plugins against baseline (created on activation/update)
	 *
	 * @return array Results.
	 */
	private static function check_plugins_baseline() {
		$results = array( 'checked' => 0, 'changed' => 0 );

		$all_plugins = get_plugins();

		foreach ( $all_plugins as $plugin_file => $plugin_data ) {
			$plugin_slug = dirname( $plugin_file );
			if ( $plugin_slug === '.' ) {
				$plugin_slug = basename( $plugin_file, '.php' );
			}

			// Get stored baseline for this plugin
			$baseline = get_option( 'bearmor_plugin_baseline_' . $plugin_slug );
			
			if ( ! $baseline ) {
				// No baseline yet - create it
				self::create_plugin_baseline( $plugin_slug );
				continue;
			}

			// Compare current files against baseline
			$plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;
			$check_result = self::compare_against_baseline( $plugin_dir, $baseline, 'wp-content/plugins/' . $plugin_slug );
			$results['checked'] += $check_result['checked'];
			$results['changed'] += $check_result['changed'];
		}

		return $results;
	}

	/**
	 * Check themes against baseline (created on activation/update)
	 *
	 * @return array Results.
	 */
	private static function check_themes_baseline() {
		$results = array( 'checked' => 0, 'changed' => 0 );

		$all_themes = wp_get_themes();

		foreach ( $all_themes as $theme_slug => $theme_obj ) {
			// Get stored baseline for this theme
			$baseline = get_option( 'bearmor_theme_baseline_' . $theme_slug );
			
			if ( ! $baseline ) {
				// No baseline yet - create it
				self::create_theme_baseline( $theme_slug );
				continue;
			}

			// Compare current files against baseline
			$theme_dir = $theme_obj->get_stylesheet_directory();
			$check_result = self::compare_against_baseline( $theme_dir, $baseline, 'wp-content/themes/' . $theme_slug );
			$results['checked'] += $check_result['checked'];
			$results['changed'] += $check_result['changed'];
		}

		return $results;
	}

	/**
	 * Check wp-config.php against baseline
	 *
	 * @return array Results.
	 */
	private static function check_wp_config() {
		$results = array( 'checked' => 0, 'changed' => 0 );

		$config_path = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $config_path ) ) {
			return $results;
		}

		$results['checked']++;

		// Get baseline
		$baseline_hash = get_option( 'bearmor_wpconfig_baseline' );
		if ( ! $baseline_hash ) {
			// Create baseline
			$baseline_hash = hash_file( 'sha1', $config_path );
			update_option( 'bearmor_wpconfig_baseline', $baseline_hash, false );
			return $results;
		}

		// Compare
		$current_hash = hash_file( 'sha1', $config_path );
		if ( $current_hash !== $baseline_hash ) {
			// wp-config.php modified!
			Bearmor_Checksum::store_baseline( 'wp-config.php', $current_hash, filesize( $config_path ) );
			Bearmor_Checksum::update_status( 'wp-config.php', 'changed' );
			Bearmor_Checksum::log_change( 'wp-config.php', $baseline_hash, $current_hash );
			$results['changed']++;
		}

		return $results;
	}

	/**
	 * Check mu-plugins against baseline
	 *
	 * @return array Results.
	 */
	private static function check_mu_plugins() {
		$results = array( 'checked' => 0, 'changed' => 0 );

		$mu_dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $mu_dir ) ) {
			return $results;
		}

		// Get baseline
		$baseline = get_option( 'bearmor_muplugins_baseline' );
		if ( ! $baseline ) {
			// Create baseline
			$baseline = self::generate_baseline_hashes( $mu_dir );
			update_option( 'bearmor_muplugins_baseline', $baseline, false );
			return $results;
		}

		// Compare
		$check_result = self::compare_against_baseline( $mu_dir, $baseline, 'wp-content/mu-plugins' );
		$results['checked'] += $check_result['checked'];
		$results['changed'] += $check_result['changed'];

		return $results;
	}

	/**
	 * Create baseline for a plugin (fast, optimized)
	 *
	 * @param string $plugin_slug Plugin slug.
	 * @return bool Success.
	 */
	public static function create_plugin_baseline( $plugin_slug ) {
		$plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;
		if ( ! is_dir( $plugin_dir ) ) {
			return false;
		}

		$baseline = self::generate_baseline_hashes( $plugin_dir );
		update_option( 'bearmor_plugin_baseline_' . $plugin_slug, $baseline, false );
		
		// Clear old change records for this plugin
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}bearmor_file_changes WHERE file_path LIKE %s",
				'wp-content/plugins/' . $plugin_slug . '/%'
			)
		);
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->prefix}bearmor_file_checksums SET status = 'ok' WHERE file_path LIKE %s",
				'wp-content/plugins/' . $plugin_slug . '/%'
			)
		);
		
		return true;
	}

	/**
	 * Create baseline for a theme (fast, optimized)
	 *
	 * @param string $theme_slug Theme slug.
	 * @return bool Success.
	 */
	public static function create_theme_baseline( $theme_slug ) {
		$theme = wp_get_theme( $theme_slug );
		if ( ! $theme->exists() ) {
			return false;
		}

		$theme_dir = $theme->get_stylesheet_directory();
		$baseline = self::generate_baseline_hashes( $theme_dir );
		update_option( 'bearmor_theme_baseline_' . $theme_slug, $baseline, false );
		
		// Clear old change records for this theme
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}bearmor_file_changes WHERE file_path LIKE %s",
				'wp-content/themes/' . $theme_slug . '/%'
			)
		);
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->prefix}bearmor_file_checksums SET status = 'ok' WHERE file_path LIKE %s",
				'wp-content/themes/' . $theme_slug . '/%'
			)
		);
		
		return true;
	}

	/**
	 * Generate baseline hashes for a directory (optimized with sha1)
	 *
	 * @param string $dir Directory path.
	 * @return array Associative array of file => hash.
	 */
	public static function generate_baseline_hashes( $dir ) {
		$hashes = array();

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || self::should_exclude( $file->getPathname() ) ) {
				continue;
			}

			$relative_path = str_replace( $dir . '/', '', $file->getPathname() );
			$hashes[ $relative_path ] = hash_file( 'sha1', $file->getPathname() );
		}

		return $hashes;
	}

	/**
	 * Compare current files against baseline
	 *
	 * @param string $dir Directory path.
	 * @param array  $baseline Baseline hashes.
	 * @param string $relative_base Relative base for logging.
	 * @return array Results.
	 */
	private static function compare_against_baseline( $dir, $baseline, $relative_base ) {
		$results = array( 'checked' => 0, 'changed' => 0 );

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || self::should_exclude( $file->getPathname() ) ) {
				continue;
			}

			$relative_path = str_replace( $dir . '/', '', $file->getPathname() );
			$results['checked']++;

			$current_hash = hash_file( 'sha1', $file->getPathname() );

			if ( ! isset( $baseline[ $relative_path ] ) ) {
				// New file added
				$full_relative = $relative_base . '/' . $relative_path;
				Bearmor_Checksum::store_baseline( $full_relative, $current_hash, filesize( $file->getPathname() ) );
				Bearmor_Checksum::update_status( $full_relative, 'changed' );
				Bearmor_Checksum::log_change( $full_relative, '', $current_hash );
				$results['changed']++;
			} elseif ( $baseline[ $relative_path ] !== $current_hash ) {
				// File modified
				$full_relative = $relative_base . '/' . $relative_path;
				Bearmor_Checksum::store_baseline( $full_relative, $current_hash, filesize( $file->getPathname() ) );
				Bearmor_Checksum::update_status( $full_relative, 'changed' );
				Bearmor_Checksum::log_change( $full_relative, $baseline[ $relative_path ], $current_hash );
				$results['changed']++;
			}
		}

		return $results;
	}

	/**
	 * Get WP core files
	 *
	 * @return array
	 */
	private static function get_core_files() {
		$files = array();
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( ABSPATH, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$path = $file->getPathname();
				// Only core files (not in wp-content)
				if ( strpos( $path, WP_CONTENT_DIR ) === false ) {
					$files[] = $path;
				}
			}
		}

		return $files;
	}

	/**
	 * Get plugin files
	 *
	 * @return array
	 */
	private static function get_plugin_files() {
		$files = array();
		$plugin_dir = WP_PLUGIN_DIR;

		if ( ! is_dir( $plugin_dir ) ) {
			return $files;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $plugin_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	/**
	 * Get theme files
	 *
	 * @return array
	 */
	private static function get_theme_files() {
		$files = array();
		$themes_dir = get_theme_root();

		if ( ! is_dir( $themes_dir ) ) {
			return $files;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $themes_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	/**
	 * Check if file should be excluded
	 *
	 * @param string $file_path File path.
	 * @return bool
	 */
	private static function should_exclude( $file_path ) {
		// Check excluded patterns
		foreach ( self::$excluded_patterns as $pattern ) {
			if ( strpos( $file_path, $pattern ) !== false ) {
				return true;
			}
		}

		// Check file extension (only scan allowed extensions)
		$extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
		if ( ! empty( $extension ) && ! in_array( $extension, self::$allowed_extensions, true ) ) {
			return true; // Exclude files with non-allowed extensions
		}

		return false;
	}
}
