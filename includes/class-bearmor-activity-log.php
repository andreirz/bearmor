<?php
/**
 * Activity Log Class
 * Tracks admin actions and WordPress events
 *
 * @package Bearmor_Security
 */

class Bearmor_Activity_Log {

	const MAX_RECORDS = 1000;

	/**
	 * Initialize hooks
	 */
	public static function init() {
		// Login tracking
		add_action( 'wp_login', array( __CLASS__, 'log_login' ), 10, 2 );
		add_action( 'wp_logout', array( __CLASS__, 'log_logout' ) );
		
		// Plugin tracking
		add_action( 'activated_plugin', array( __CLASS__, 'log_plugin_activated' ), 10, 2 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'log_plugin_deactivated' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'log_plugin_installed' ), 10, 2 );
		add_action( 'delete_plugin', array( __CLASS__, 'log_plugin_deleted' ) );
		
		// Theme tracking
		add_action( 'switch_theme', array( __CLASS__, 'log_theme_switched' ), 10, 3 );
		
		// User tracking
		add_action( 'user_register', array( __CLASS__, 'log_user_created' ) );
		add_action( 'delete_user', array( __CLASS__, 'log_user_deleted' ) );
		
		// Auto-cleanup old records
		add_action( 'bearmor_cleanup_activity_log', array( __CLASS__, 'cleanup_old_records' ) );
		
		// Schedule cleanup if not scheduled
		if ( ! wp_next_scheduled( 'bearmor_cleanup_activity_log' ) ) {
			wp_schedule_event( time(), 'daily', 'bearmor_cleanup_activity_log' );
		}
	}

	/**
	 * Create database table
	 */
	public static function create_table() {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_activity_log';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS $table_name (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			user_id BIGINT UNSIGNED NOT NULL,
			username VARCHAR(60) NOT NULL,
			action VARCHAR(50) NOT NULL,
			object_type VARCHAR(50),
			object_name VARCHAR(255),
			ip_address VARCHAR(45),
			user_agent TEXT,
			created_at DATETIME NOT NULL,
			INDEX idx_user_id (user_id),
			INDEX idx_action (action),
			INDEX idx_created_at (created_at)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Log an activity
	 */
	public static function log( $action, $object_type = null, $object_name = null, $user_id = null ) {
		global $wpdb;
		
		// Get user info
		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}
		
		$user = get_userdata( $user_id );
		$username = $user ? $user->user_login : 'system';
		
		// Get IP and user agent
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		
		// Insert log
		$wpdb->insert(
			$wpdb->prefix . 'bearmor_activity_log',
			array(
				'user_id'     => $user_id,
				'username'    => $username,
				'action'      => $action,
				'object_type' => $object_type,
				'object_name' => $object_name,
				'ip_address'  => $ip,
				'user_agent'  => $user_agent,
				'created_at'  => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		
		// Auto-cleanup if over limit
		self::enforce_limit();
	}

	/**
	 * Enforce record limit
	 */
	private static function enforce_limit() {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_activity_log';
		
		$count = $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
		
		if ( $count > self::MAX_RECORDS ) {
			$delete_count = $count - self::MAX_RECORDS;
			$wpdb->query( $wpdb->prepare(
				"DELETE FROM $table_name ORDER BY created_at ASC LIMIT %d",
				$delete_count
			) );
		}
	}

	/**
	 * Cleanup old records (90 days)
	 */
	public static function cleanup_old_records() {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_activity_log';
		
		$wpdb->query(
			"DELETE FROM $table_name WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)"
		);
	}

	/**
	 * Login tracking
	 */
	public static function log_login( $user_login, $user ) {
		self::log( 'login', 'user', $user_login, $user->ID );
	}

	public static function log_logout() {
		$user = wp_get_current_user();
		self::log( 'logout', 'user', $user->user_login );
	}

	/**
	 * Plugin tracking
	 */
	public static function log_plugin_activated( $plugin, $network_wide ) {
		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
		self::log( 'plugin_activated', 'plugin', $plugin_data['Name'] );
	}

	public static function log_plugin_deactivated( $plugin, $network_wide ) {
		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
		
		// Check if this is an auto-disable due to critical vulnerability
		$transient_key = 'bearmor_auto_disabling_' . md5( $plugin );
		if ( get_transient( $transient_key ) ) {
			delete_transient( $transient_key );
			self::log( 'plugin_auto_disabled', 'plugin', $plugin_data['Name'], 0 ); // System action
		} else {
			self::log( 'plugin_deactivated', 'plugin', $plugin_data['Name'] );
		}
	}

	public static function log_plugin_installed( $upgrader, $options ) {
		if ( $options['action'] === 'install' && $options['type'] === 'plugin' ) {
			if ( isset( $options['plugins'] ) && is_array( $options['plugins'] ) ) {
				foreach ( $options['plugins'] as $plugin ) {
					$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin );
					self::log( 'plugin_installed', 'plugin', $plugin_data['Name'] );
				}
			}
		}
	}

	public static function log_plugin_deleted( $plugin_file ) {
		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_file );
		self::log( 'plugin_deleted', 'plugin', $plugin_data['Name'] );
	}

	/**
	 * Theme tracking
	 */
	public static function log_theme_switched( $new_name, $new_theme, $old_theme ) {
		self::log( 'theme_switched', 'theme', $new_name );
	}

	/**
	 * User tracking
	 */
	public static function log_user_created( $user_id ) {
		$user = get_userdata( $user_id );
		self::log( 'user_created', 'user', $user->user_login );
	}

	public static function log_user_deleted( $user_id ) {
		$user = get_userdata( $user_id );
		if ( $user ) {
			self::log( 'user_deleted', 'user', $user->user_login );
		}
	}

	/**
	 * Get activity logs
	 */
	public static function get_logs( $args = array() ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_activity_log';
		
		$defaults = array(
			'limit'       => 50,
			'offset'      => 0,
			'action'      => null,
			'user_id'     => null,
			'date_from'   => null,
			'date_to'     => null,
			'search'      => null,
		);
		
		$args = wp_parse_args( $args, $defaults );
		
		$where = array( '1=1' );
		
		if ( $args['action'] ) {
			$where[] = $wpdb->prepare( 'action = %s', $args['action'] );
		}
		
		if ( $args['user_id'] ) {
			$where[] = $wpdb->prepare( 'user_id = %d', $args['user_id'] );
		}
		
		if ( $args['date_from'] ) {
			$where[] = $wpdb->prepare( 'created_at >= %s', $args['date_from'] );
		}
		
		if ( $args['date_to'] ) {
			$where[] = $wpdb->prepare( 'created_at <= %s', $args['date_to'] );
		}
		
		if ( $args['search'] ) {
			$search = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[] = $wpdb->prepare( '(username LIKE %s OR object_name LIKE %s)', $search, $search );
		}
		
		$where_sql = implode( ' AND ', $where );
		
		$sql = "SELECT * FROM $table_name 
				WHERE $where_sql 
				ORDER BY created_at DESC 
				LIMIT %d OFFSET %d";
		
		return $wpdb->get_results( $wpdb->prepare( $sql, $args['limit'], $args['offset'] ) );
	}

	/**
	 * Get total count
	 */
	public static function get_count( $args = array() ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'bearmor_activity_log';
		
		$where = array( '1=1' );
		
		if ( isset( $args['action'] ) && $args['action'] ) {
			$where[] = $wpdb->prepare( 'action = %s', $args['action'] );
		}
		
		if ( isset( $args['user_id'] ) && $args['user_id'] ) {
			$where[] = $wpdb->prepare( 'user_id = %d', $args['user_id'] );
		}
		
		if ( isset( $args['search'] ) && $args['search'] ) {
			$search = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[] = $wpdb->prepare( '(username LIKE %s OR object_name LIKE %s)', $search, $search );
		}
		
		$where_sql = implode( ' AND ', $where );
		
		return $wpdb->get_var( "SELECT COUNT(*) FROM $table_name WHERE $where_sql" );
	}

	/**
	 * Get action label
	 */
	public static function get_action_label( $action ) {
		$labels = array(
			'login'                     => '🔓 Logged In',
			'logout'                    => '🔒 Logged Out',
			'login_blocked_honeypot'    => '🍯 Blocked Login (Honeypot)',
			'plugin_installed'          => '📦 Installed Plugin',
			'plugin_activated'          => '✅ Activated Plugin',
			'plugin_deactivated'        => '⏸️ Deactivated Plugin',
			'plugin_auto_disabled'      => '<span style="color: #d63638; font-weight: 600;">🚨 Auto-Disabled Plugin (Critical Vulnerability)</span>',
			'plugin_deleted'            => '🗑️ Deleted Plugin',
			'theme_switched'            => '🎨 Switched Theme',
			'user_created'              => '👤 Created User',
			'user_deleted'              => '❌ Deleted User',
			'file_quarantined'          => '🔒 Quarantined File',
			'file_restored'             => '♻️ Restored File',
			'ip_blocked'                => '🚫 Blocked IP',
			'ip_unblocked'              => '✅ Unblocked IP',
			'settings_changed'          => '⚙️ Changed Settings',
			'hardening_applied'         => '🛡️ Applied Hardening',
		);
		
		return isset( $labels[ $action ] ) ? $labels[ $action ] : ucwords( str_replace( '_', ' ', $action ) );
	}
}
