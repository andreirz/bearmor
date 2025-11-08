<?php
/**
 * Bearmor File Actions Class
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * File actions class (lock, quarantine, restore)
 */
class Bearmor_File_Actions {

	/**
	 * Lock a file (rename with .locked extension in safe mode)
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @return bool|WP_Error
	 */
	public static function lock_file( $file_path ) {
		$full_path = ABSPATH . $file_path;

		if ( ! file_exists( $full_path ) ) {
			return new WP_Error( 'file_not_found', 'File not found' );
		}

		$settings = get_option( 'bearmor_settings', array() );
		$safe_mode = isset( $settings['safe_mode'] ) ? $settings['safe_mode'] : true;

		if ( $safe_mode ) {
			// Safe mode: rename file
			$locked_path = $full_path . '.locked';
			if ( rename( $full_path, $locked_path ) ) {
				// Log action
				Bearmor_Helpers::log_audit( 'lock', 'file', $file_path, 'File locked (renamed)' );
				
				// Update file change record
				global $wpdb;
				$wpdb->update(
					$wpdb->prefix . 'bearmor_file_changes',
					array( 'action_taken' => 'locked', 'action_by' => get_current_user_id() ),
					array( 'file_path' => $file_path ),
					array( '%s', '%d' ),
					array( '%s' )
				);

				return true;
			}
		} else {
			// chmod 000 (not recommended for shared hosting)
			if ( chmod( $full_path, 0000 ) ) {
				Bearmor_Helpers::log_audit( 'lock', 'file', $file_path, 'File locked (chmod 000)' );
				return true;
			}
		}

		return new WP_Error( 'lock_failed', 'Failed to lock file' );
	}

	/**
	 * Unlock a file
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @return bool|WP_Error
	 */
	public static function unlock_file( $file_path ) {
		$locked_path = ABSPATH . $file_path . '.locked';
		$original_path = ABSPATH . $file_path;

		if ( file_exists( $locked_path ) ) {
			// Restore from .locked
			if ( rename( $locked_path, $original_path ) ) {
				Bearmor_Helpers::log_audit( 'unlock', 'file', $file_path, 'File unlocked' );
				return true;
			}
		} elseif ( file_exists( $original_path ) ) {
			// Restore permissions
			if ( chmod( $original_path, 0644 ) ) {
				Bearmor_Helpers::log_audit( 'unlock', 'file', $file_path, 'File permissions restored' );
				return true;
			}
		}

		return new WP_Error( 'unlock_failed', 'Failed to unlock file' );
	}

	/**
	 * Quarantine a file (with smart deactivation)
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @param string $reason Reason for quarantine.
	 * @return array|WP_Error Array with success message and warnings, or WP_Error on failure.
	 */
	public static function quarantine_file( $file_path, $reason = 'Manual quarantine' ) {
		$full_path = ABSPATH . $file_path;
		$warnings = array();

		if ( ! file_exists( $full_path ) ) {
			return new WP_Error( 'file_not_found', 'File not found' );
		}

		// Detect file type and handle deactivation
		$file_type = self::detect_file_type( $file_path );

		// Handle WP Core files
		if ( $file_type === 'wp_core' ) {
			return new WP_Error( 
				'core_file_blocked', 
				'Cannot quarantine WordPress core files. Please use "Restore from WordPress.org" instead.' 
			);
		}

		// Handle Plugin files
		if ( $file_type === 'plugin' ) {
			$plugin_slug = self::get_plugin_from_path( $file_path );
			if ( $plugin_slug && is_plugin_active( $plugin_slug ) ) {
				deactivate_plugins( $plugin_slug );
				$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_slug );
				$warnings[] = '⚠️ Plugin "' . $plugin_data['Name'] . '" has been deactivated.';
			}
		}

		// Handle Theme files
		if ( $file_type === 'theme' ) {
			$theme_slug = self::get_theme_from_path( $file_path );
			$current_theme = get_stylesheet();
			
			if ( $theme_slug && $theme_slug === $current_theme ) {
				// Switch to default theme
				$default_theme = WP_DEFAULT_THEME; // Usually 'twentytwentyfour'
				if ( ! $default_theme ) {
					$default_theme = 'twentytwentyfour';
				}
				
				switch_theme( $default_theme );
				$warnings[] = '⚠️ Active theme switched to "' . $default_theme . '" before quarantine.';
			}
		}

		// Create quarantine directory if needed
		$quarantine_dir = WP_CONTENT_DIR . '/bearmor-quarantine';
		if ( ! file_exists( $quarantine_dir ) ) {
			wp_mkdir_p( $quarantine_dir );
		}

		// Generate unique quarantine filename
		$timestamp = time();
		$quarantine_filename = $timestamp . '_' . basename( $file_path );
		$quarantine_path = $quarantine_dir . '/' . $quarantine_filename;

		// Move file to quarantine
		if ( rename( $full_path, $quarantine_path ) ) {
			// Store in database
			global $wpdb;
			$wpdb->insert(
				$wpdb->prefix . 'bearmor_quarantine',
				array(
					'file_path'         => $file_path,
					'quarantined_path'  => 'wp-content/bearmor-quarantine/' . $quarantine_filename,
					'reason'            => $reason,
					'quarantined_at'    => current_time( 'mysql' ),
					'quarantined_by'    => get_current_user_id(),
					'status'            => 'quarantined',
				),
				array( '%s', '%s', '%s', '%s', '%d', '%s' )
			);

			// Log action
			Bearmor_Helpers::log_audit( 'quarantine', 'file', $file_path, $reason );

			// Update file change record
			$wpdb->update(
				$wpdb->prefix . 'bearmor_file_changes',
				array( 'action_taken' => 'quarantined', 'action_by' => get_current_user_id() ),
				array( 'file_path' => $file_path ),
				array( '%s', '%d' ),
				array( '%s' )
			);

			// Update checksum status to remove from "Changed Files" list
			$wpdb->update(
				$wpdb->prefix . 'bearmor_file_checksums',
				array( 'status' => 'deleted' ),
				array( 'file_path' => $file_path ),
				array( '%s' ),
				array( '%s' )
			);

			return array(
				'success'  => true,
				'message'  => 'File quarantined successfully!',
				'warnings' => $warnings,
			);
		}

		return new WP_Error( 'quarantine_failed', 'Failed to quarantine file' );
	}

	/**
	 * Detect file type (plugin, theme, core, other)
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @return string File type.
	 */
	private static function detect_file_type( $file_path ) {
		if ( strpos( $file_path, 'wp-content/plugins/' ) === 0 ) {
			return 'plugin';
		}
		if ( strpos( $file_path, 'wp-content/themes/' ) === 0 ) {
			return 'theme';
		}
		if ( strpos( $file_path, 'wp-content/' ) === 0 ) {
			return 'wp_content';
		}
		// WP core files (wp-admin, wp-includes, root files)
		return 'wp_core';
	}

	/**
	 * Get plugin slug from file path
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @return string|false Plugin slug or false.
	 */
	private static function get_plugin_from_path( $file_path ) {
		if ( strpos( $file_path, 'wp-content/plugins/' ) !== 0 ) {
			return false;
		}

		// Extract plugin directory
		$path_parts = explode( '/', str_replace( 'wp-content/plugins/', '', $file_path ) );
		$plugin_dir = $path_parts[0];

		// Find the main plugin file
		$plugins = get_plugins();
		foreach ( $plugins as $plugin_file => $plugin_data ) {
			if ( strpos( $plugin_file, $plugin_dir . '/' ) === 0 ) {
				return $plugin_file;
			}
		}

		return false;
	}

	/**
	 * Get theme slug from file path
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @return string|false Theme slug or false.
	 */
	private static function get_theme_from_path( $file_path ) {
		if ( strpos( $file_path, 'wp-content/themes/' ) !== 0 ) {
			return false;
		}

		// Extract theme directory
		$path_parts = explode( '/', str_replace( 'wp-content/themes/', '', $file_path ) );
		return $path_parts[0];
	}

	/**
	 * Restore a file from quarantine
	 *
	 * @param int $quarantine_id Quarantine record ID.
	 * @return bool|WP_Error
	 */
	public static function restore_from_quarantine( $quarantine_id ) {
		global $wpdb;

		$record = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}bearmor_quarantine WHERE id = %d AND status = 'quarantined'",
			$quarantine_id
		) );

		if ( ! $record ) {
			return new WP_Error( 'record_not_found', 'Quarantine record not found' );
		}

		$quarantined_path = ABSPATH . $record->quarantined_path;
		$original_path = ABSPATH . $record->file_path;

		if ( ! file_exists( $quarantined_path ) ) {
			return new WP_Error( 'file_not_found', 'Quarantined file not found' );
		}

		// Create directory if needed
		$dir = dirname( $original_path );
		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		// Restore file
		if ( rename( $quarantined_path, $original_path ) ) {
			// Update database
			$wpdb->update(
				$wpdb->prefix . 'bearmor_quarantine',
				array(
					'status'      => 'restored',
					'restored_at' => current_time( 'mysql' ),
					'restored_by' => get_current_user_id(),
				),
				array( 'id' => $quarantine_id ),
				array( '%s', '%s', '%d' ),
				array( '%d' )
			);

			// Log action
			Bearmor_Helpers::log_audit( 'restore', 'file', $record->file_path, 'File restored from quarantine' );

			return true;
		}

		return new WP_Error( 'restore_failed', 'Failed to restore file' );
	}

	/**
	 * Mark file as safe
	 *
	 * @param string $file_path File path relative to ABSPATH.
	 * @return bool
	 */
	public static function mark_safe( $file_path ) {
		// Update checksum status
		Bearmor_Checksum::update_status( $file_path, 'safe' );

		// Update file change record
		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'bearmor_file_changes',
			array( 'action_taken' => 'marked_safe', 'action_by' => get_current_user_id() ),
			array( 'file_path' => $file_path ),
			array( '%s', '%d' ),
			array( '%s' )
		);

		// Update baseline hash for wp-config.php
		if ( $file_path === 'wp-config.php' ) {
			$config_path = ABSPATH . 'wp-config.php';
			if ( file_exists( $config_path ) ) {
				$new_hash = hash_file( 'sha1', $config_path );
				update_option( 'bearmor_wpconfig_baseline', $new_hash, false );
			}
		}

		// Update baseline hash for mu-plugins files
		if ( strpos( $file_path, 'wp-content/mu-plugins/' ) === 0 ) {
			// Rebuild entire mu-plugins baseline
			$mu_dir = WPMU_PLUGIN_DIR;
			if ( is_dir( $mu_dir ) ) {
				require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-file-scanner.php';
				$baseline = Bearmor_File_Scanner::generate_baseline_hashes( $mu_dir );
				update_option( 'bearmor_muplugins_baseline', $baseline, false );
			}
		}

		// Update baseline for plugin files
		if ( strpos( $file_path, 'wp-content/plugins/' ) === 0 ) {
			// Extract plugin slug from path
			$path_parts = explode( '/', str_replace( 'wp-content/plugins/', '', $file_path ) );
			$plugin_slug = $path_parts[0];
			
			// Rebuild plugin baseline
			$plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;
			if ( is_dir( $plugin_dir ) ) {
				require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-file-scanner.php';
				$baseline = Bearmor_File_Scanner::generate_baseline_hashes( $plugin_dir );
				update_option( 'bearmor_plugin_baseline_' . $plugin_slug, $baseline, false );
			}
		}

		// Update baseline for theme files
		if ( strpos( $file_path, 'wp-content/themes/' ) === 0 ) {
			// Extract theme slug from path
			$path_parts = explode( '/', str_replace( 'wp-content/themes/', '', $file_path ) );
			$theme_slug = $path_parts[0];
			
			// Rebuild theme baseline
			$theme = wp_get_theme( $theme_slug );
			if ( $theme->exists() ) {
				require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-file-scanner.php';
				$theme_dir = $theme->get_stylesheet_directory();
				$baseline = Bearmor_File_Scanner::generate_baseline_hashes( $theme_dir );
				update_option( 'bearmor_theme_baseline_' . $theme_slug, $baseline, false );
			}
		}

		// Log action
		Bearmor_Helpers::log_audit( 'mark_safe', 'file', $file_path, 'File marked as safe and baseline updated' );

		return true;
	}
}
