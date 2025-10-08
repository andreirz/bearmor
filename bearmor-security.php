<?php
/**
 * Plugin Name: Bearmor Security
 * Plugin URI: https://bearmor.com
 * Description: Lightweight, robust WordPress security plugin for SMBs.
 * Version: 0.1.7
 * Author: Bearmor Security Team
 * Author URI: https://bearmor.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: bearmor-security
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Define plugin constants
define( 'BEARMOR_VERSION', '0.1.7' );
define( 'BEARMOR_PLUGIN_FILE', __FILE__ );
define( 'BEARMOR_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'BEARMOR_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Plugin activation
 */
function bearmor_activate() {
	// Generate unique site ID
	if ( ! get_option( 'bearmor_site_id' ) ) {
		add_option( 'bearmor_site_id', wp_generate_uuid4() );
	}

	// Set default settings
	if ( ! get_option( 'bearmor_settings' ) ) {
		$defaults = array(
			'scan_schedule'           => 'daily',
			'notification_email'      => get_option( 'admin_email' ),
			'auto_quarantine'         => false,
			'auto_disable_vulnerable' => false,
			'safe_mode'               => true,
			'first_activation'        => current_time( 'mysql' ),
		);
		add_option( 'bearmor_settings', $defaults );
	}

	// Create database tables
	global $wpdb;
	$charset_collate = $wpdb->get_charset_collate();
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';

	// File checksums table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_file_checksums (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		file_path VARCHAR(500) NOT NULL,
		checksum VARCHAR(64) NOT NULL,
		file_size BIGINT UNSIGNED,
		last_checked DATETIME NOT NULL,
		status ENUM('baseline', 'changed', 'new', 'deleted', 'safe') DEFAULT 'baseline',
		UNIQUE KEY file_path (file_path),
		KEY status (status),
		KEY last_checked (last_checked)
	) $charset_collate;";
	dbDelta( $sql );

	// File changes table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_file_changes (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		file_path VARCHAR(500) NOT NULL,
		old_checksum VARCHAR(64),
		new_checksum VARCHAR(64),
		detected_at DATETIME NOT NULL,
		action_taken ENUM('none', 'locked', 'quarantined', 'marked_safe') DEFAULT 'none',
		action_by BIGINT UNSIGNED,
		KEY detected_at (detected_at),
		KEY file_path (file_path)
	) $charset_collate;";
	dbDelta( $sql );

	// Quarantine table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_quarantine (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		file_path VARCHAR(500) NOT NULL,
		quarantined_path VARCHAR(500) NOT NULL,
		reason VARCHAR(255),
		quarantined_at DATETIME NOT NULL,
		quarantined_by BIGINT UNSIGNED,
		restored_at DATETIME,
		restored_by BIGINT UNSIGNED,
		status ENUM('quarantined', 'restored', 'deleted') DEFAULT 'quarantined',
		KEY status (status),
		KEY quarantined_at (quarantined_at)
	) $charset_collate;";
	dbDelta( $sql );

	// Malware detections table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_malware_detections (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		file_path VARCHAR(500) NOT NULL,
		pattern_id VARCHAR(100) NOT NULL,
		pattern_name VARCHAR(255) NOT NULL,
		severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
		category VARCHAR(100) NOT NULL,
		description TEXT,
		line_number INT UNSIGNED NOT NULL,
		code_snippet TEXT,
		matched_text TEXT,
		detected_at DATETIME NOT NULL,
		status ENUM('pending', 'whitelisted', 'quarantined', 'false_positive') DEFAULT 'pending',
		action_by BIGINT UNSIGNED,
		KEY file_path (file_path),
		KEY severity (severity),
		KEY status (status),
		KEY detected_at (detected_at)
	) $charset_collate;";
	dbDelta( $sql );
	
	// Add description column if it doesn't exist (for existing installations)
	$table_name = $wpdb->prefix . 'bearmor_malware_detections';
	$column_exists = $wpdb->get_results( "SHOW COLUMNS FROM {$table_name} LIKE 'description'" );
	if ( empty( $column_exists ) ) {
		$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN description TEXT AFTER category" );
	}

	// Login attempts table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_login_attempts (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		ip_address VARCHAR(45) NOT NULL,
		username VARCHAR(60),
		success TINYINT(1) DEFAULT 0,
		attempted_at DATETIME NOT NULL,
		user_agent TEXT,
		country_code VARCHAR(2),
		KEY ip_address (ip_address),
		KEY attempted_at (attempted_at),
		KEY success (success)
	) $charset_collate;";
	dbDelta( $sql );

	// Blocked IPs table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_blocked_ips (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		ip_address VARCHAR(45) NOT NULL UNIQUE,
		blocked_at DATETIME NOT NULL,
		expires_at DATETIME,
		reason VARCHAR(255),
		permanent TINYINT(1) DEFAULT 0,
		blocked_by BIGINT UNSIGNED,
		KEY expires_at (expires_at),
		KEY permanent (permanent)
	) $charset_collate;";
	dbDelta( $sql );

	// Login anomalies table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_login_anomalies (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		user_id BIGINT UNSIGNED NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		country_code VARCHAR(2),
		user_agent TEXT,
		anomaly_type VARCHAR(50) NOT NULL,
		anomaly_score INT NOT NULL,
		details TEXT,
		detected_at DATETIME NOT NULL,
		status ENUM('new', 'marked_safe', 'blocked') DEFAULT 'new',
		action_by BIGINT UNSIGNED,
		KEY user_id (user_id),
		KEY detected_at (detected_at),
		KEY anomaly_score (anomaly_score),
		KEY status (status)
	) $charset_collate;";
	dbDelta( $sql );

	// User profiles table (for tracking normal behavior)
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_user_profiles (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		user_id BIGINT UNSIGNED NOT NULL,
		known_ips TEXT,
		known_countries TEXT,
		known_user_agents TEXT,
		typical_login_hours VARCHAR(255),
		last_login_at DATETIME,
		last_login_ip VARCHAR(45),
		last_login_country VARCHAR(2),
		profile_created DATETIME NOT NULL,
		profile_updated DATETIME NOT NULL,
		UNIQUE KEY user_id (user_id),
		KEY user_id_index (user_id)
	) $charset_collate;";
	dbDelta( $sql );

	// Activity log table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_activity_log (
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
	dbDelta( $sql );

	// Vulnerabilities table
	$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bearmor_vulnerabilities (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		item_slug VARCHAR(255) NOT NULL,
		item_name VARCHAR(255) NOT NULL,
		item_version VARCHAR(50) NOT NULL,
		item_type ENUM('plugin', 'theme', 'core') DEFAULT 'plugin',
		severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
		title VARCHAR(255) NOT NULL,
		description TEXT,
		fixed_in VARCHAR(50),
		cve_references TEXT,
		detected_at DATETIME NOT NULL,
		status ENUM('active', 'whitelisted', 'fixed') DEFAULT 'active',
		KEY item_slug (item_slug),
		KEY severity (severity),
		KEY status (status),
		KEY detected_at (detected_at)
	) $charset_collate;";
	dbDelta( $sql );

	// Create quarantine directory
	$quarantine_dir = WP_CONTENT_DIR . '/bearmor-quarantine';
	if ( ! file_exists( $quarantine_dir ) ) {
		wp_mkdir_p( $quarantine_dir );
		// Protect directory
		file_put_contents( $quarantine_dir . '/.htaccess', "Order deny,allow\nDeny from all" );
		file_put_contents( $quarantine_dir . '/index.php', '<?php // Silence is golden' );
	}

	// Show baseline scan notice only on FIRST activation
	if ( ! get_option( 'bearmor_first_activation_done' ) ) {
		// Mark first activation
		add_option( 'bearmor_first_activation_done', true );
		
		// Show admin notice to run baseline scan
		add_option( 'bearmor_show_baseline_notice', true );
	}
}
register_activation_hook( __FILE__, 'bearmor_activate' );

/**
 * Plugin deactivation
 */
function bearmor_deactivate() {
	// Cleanup if needed
}
/**
 * Load required classes
 */
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-helpers.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-settings.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-checksum.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-file-scanner.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-file-actions.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-wporg-api.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-malware-patterns.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-malware-scanner.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-login-protection.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-anomaly-detector.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-hardening.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-2fa.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-activity-log.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-wpvulnerability-api.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-vulnerability-scanner.php';

/**
 * Initialize security features
 */
Bearmor_Login_Protection::init();
Bearmor_Anomaly_Detector::init();
Bearmor_Hardening::init();
Bearmor_2FA::init();
Bearmor_Activity_Log::init();
Bearmor_Vulnerability_Scanner::init();

/**
 * Show notice to run baseline scan
 */
function bearmor_baseline_scan_notice() {
	if ( get_option( 'bearmor_show_baseline_notice' ) && current_user_can( 'manage_options' ) ) {
		?>
		<div class="notice notice-warning is-dismissible">
			<p>
				<strong>Bearmor Security:</strong> Please run a baseline scan to start monitoring file changes.
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-file-changes' ) ); ?>" class="button button-primary" style="margin-left: 10px;">
					Run Baseline Scan
				</a>
			</p>
		</div>
		<?php
	}
}
add_action( 'admin_notices', 'bearmor_baseline_scan_notice' );

/**
 * Dismiss baseline scan notice after scan is run
 */
add_action( 'admin_init', function() {
	if ( isset( $_POST['bearmor_scan'] ) && $_POST['bearmor_scan'] === 'baseline' ) {
		delete_option( 'bearmor_show_baseline_notice' );
		update_option( 'bearmor_baseline_scan_done', true );
	}
} );

/**
 * Log WordPress core updates
 */
add_action( '_core_updated_successfully', function( $wp_version ) {
	// Just log the update
	if ( class_exists( 'Bearmor_Helpers' ) ) {
		Bearmor_Helpers::log_audit( 'wp_update', 'core', $wp_version, 'WordPress updated to ' . $wp_version . '. Run integrity check to verify.' );
	}
} );

/**
 * Create baseline when a plugin is activated for the first time
 */
add_action( 'activated_plugin', function( $plugin ) {
	$plugin_slug = dirname( $plugin );
	if ( $plugin_slug === '.' ) {
		$plugin_slug = basename( $plugin, '.php' );
	}

	// Check if baseline already exists
	$baseline = get_option( 'bearmor_plugin_baseline_' . $plugin_slug );
	if ( ! $baseline ) {
		// Create baseline asynchronously to avoid blocking
		wp_schedule_single_event( time() + 5, 'bearmor_create_plugin_baseline', array( $plugin_slug ) );
	}
} );

/**
 * Rebuild baseline when a plugin is updated
 */
add_action( 'upgrader_process_complete', function( $upgrader, $options ) {
	if ( $options['type'] === 'plugin' && isset( $options['plugins'] ) ) {
		foreach ( $options['plugins'] as $plugin ) {
			$plugin_slug = dirname( $plugin );
			if ( $plugin_slug === '.' ) {
				$plugin_slug = basename( $plugin, '.php' );
			}

			// Rebuild baseline asynchronously
			wp_schedule_single_event( time() + 5, 'bearmor_create_plugin_baseline', array( $plugin_slug ) );
		}
	}

	if ( $options['type'] === 'theme' && isset( $options['themes'] ) ) {
		foreach ( $options['themes'] as $theme_slug ) {
			// Rebuild baseline asynchronously
			wp_schedule_single_event( time() + 5, 'bearmor_create_theme_baseline', array( $theme_slug ) );
		}
	}
}, 10, 2 );

/**
 * Hook for async baseline creation
 */
add_action( 'bearmor_create_plugin_baseline', function( $plugin_slug ) {
	Bearmor_File_Scanner::create_plugin_baseline( $plugin_slug );
} );

add_action( 'bearmor_create_theme_baseline', function( $theme_slug ) {
	Bearmor_File_Scanner::create_theme_baseline( $theme_slug );
} );

/**
 * AJAX handler for file preview
 */
add_action( 'wp_ajax_bearmor_preview_file', function() {
	// Verify nonce
	if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( $_POST['nonce'], 'bearmor_preview' ) ) {
		wp_send_json_error( array( 'message' => 'Invalid nonce' ) );
	}

	// Check permissions
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Insufficient permissions' ) );
	}

	$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( $_POST['file_path'] ) : '';
	if ( empty( $file_path ) ) {
		wp_send_json_error( array( 'message' => 'No file path provided' ) );
	}

	$full_path = ABSPATH . $file_path;

	// Security check - file must exist and be within ABSPATH
	if ( ! file_exists( $full_path ) || strpos( realpath( $full_path ), ABSPATH ) !== 0 ) {
		wp_send_json_error( array( 'message' => 'File not found or access denied' ) );
	}

	// Read file content
	$content = file_get_contents( $full_path );
	if ( $content === false ) {
		wp_send_json_error( array( 'message' => 'Failed to read file' ) );
	}

	// Count lines
	$lines = explode( "\n", $content );
	$total_lines = count( $lines );
	$truncated = false;

	// If more than 100 lines, show first 50 and last 50
	if ( $total_lines > 100 ) {
		$first_50 = array_slice( $lines, 0, 50 );
		$last_50 = array_slice( $lines, -50 );
		$lines = array_merge( $first_50, array( '... [' . ( $total_lines - 100 ) . ' lines hidden] ...' ), $last_50 );
		$truncated = true;
	}

	// Build HTML with line numbers
	$html = '';
	if ( $truncated ) {
		$html .= '<div class="bearmor-preview-truncated">⚠️ File has ' . $total_lines . ' lines. Showing first 50 and last 50 lines.</div>';
	}

	$html .= '<pre>';
	$line_num = 1;
	foreach ( $lines as $line ) {
		if ( strpos( $line, '...' ) === 0 && strpos( $line, 'lines hidden' ) !== false ) {
			$html .= '<span style="color: #999; font-style: italic;">' . esc_html( $line ) . '</span>' . "\n";
			$line_num = $total_lines - 49; // Adjust line number for last 50
		} else {
			$html .= '<span class="line-numbers">' . str_pad( $line_num, 4, ' ', STR_PAD_LEFT ) . '</span>';
			$html .= esc_html( $line ) . "\n";
			$line_num++;
		}
	}
	$html .= '</pre>';

	wp_send_json_success( array( 'html' => $html ) );
} );

/**
 * AJAX handler for malware file preview with line highlighting
 */
add_action( 'wp_ajax_bearmor_preview_malware_file', function() {
	// Verify nonce
	if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( $_POST['nonce'], 'bearmor_preview' ) ) {
		wp_send_json_error( array( 'message' => 'Invalid nonce' ) );
	}

	// Check permissions
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Insufficient permissions' ) );
	}

	$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( $_POST['file_path'] ) : '';
	$line_number = isset( $_POST['line_number'] ) ? intval( $_POST['line_number'] ) : 0;
	
	if ( empty( $file_path ) ) {
		wp_send_json_error( array( 'message' => 'No file path provided' ) );
	}

	$full_path = ABSPATH . $file_path;

	// Security check - file must exist and be within ABSPATH
	if ( ! file_exists( $full_path ) || strpos( realpath( $full_path ), ABSPATH ) !== 0 ) {
		wp_send_json_error( array( 'message' => 'File not found or access denied' ) );
	}

	// Read file content
	$content = file_get_contents( $full_path );
	if ( $content === false ) {
		wp_send_json_error( array( 'message' => 'Failed to read file' ) );
	}

	// Get 10 lines before and after the threat line
	$lines = explode( "\n", $content );
	$total_lines = count( $lines );
	
	// Calculate range: 10 before, threat line, 10 after
	$start_line = max( 1, $line_number - 10 );
	$end_line = min( $total_lines, $line_number + 10 );
	
	// Build HTML with line numbers and highlighting
	$html = '<pre>';
	for ( $i = $start_line; $i <= $end_line; $i++ ) {
		// Check if this line exists in array (0-indexed)
		if ( ! isset( $lines[ $i - 1 ] ) ) {
			continue;
		}
		
		$is_threat_line = ( $i === $line_number );
		
		if ( $is_threat_line ) {
			$html .= '<span class="highlight-line">';
		}
		
		$html .= '<span class="line-numbers">' . str_pad( $i, 4, ' ', STR_PAD_LEFT ) . '</span>';
		$html .= esc_html( $lines[ $i - 1 ] );
		
		if ( $is_threat_line ) {
			$html .= '</span>';
		}
		
		$html .= "\n";
	}
	$html .= '</pre>';

	wp_send_json_success( array( 'html' => $html ) );
} );

/**
 * Add admin menu
 */
function bearmor_admin_menu() {
	add_menu_page(
		'Bearmor Security',
		'Bearmor Security',
		'manage_options',
		'bearmor-security',
		'bearmor_dashboard_page',
		'dashicons-shield',
		80
	);

	add_submenu_page(
		'bearmor-security',
		'File Changes',
		'File Changes',
		'manage_options',
		'bearmor-file-changes',
		'bearmor_file_changes_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Malware Alerts',
		'Malware Alerts',
		'manage_options',
		'bearmor-malware-alerts',
		'bearmor_malware_alerts_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Login Activity',
		'Login Activity',
		'manage_options',
		'bearmor-login-activity',
		'bearmor_login_activity_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Login Anomalies',
		'Login Anomalies',
		'manage_options',
		'bearmor-login-anomalies',
		'bearmor_login_anomalies_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Hardening',
		'Hardening',
		'manage_options',
		'bearmor-hardening',
		'bearmor_hardening_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Activity Log',
		'Activity Log',
		'manage_options',
		'bearmor-activity-log',
		'bearmor_activity_log_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Vulnerabilities',
		'Vulnerabilities',
		'manage_options',
		'bearmor-vulnerabilities',
		'bearmor_vulnerabilities_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Settings',
		'Settings',
		'manage_options',
		'bearmor-settings',
		'bearmor_settings_page'
	);
}
add_action( 'admin_menu', 'bearmor_admin_menu' );

/**
 * Dashboard page
 */
function bearmor_dashboard_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/dashboard.php';
}

/**
 * File Changes page
 */
function bearmor_file_changes_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/file-changes.php';
}

/**
 * Malware Alerts page
 */
function bearmor_malware_alerts_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/malware-alerts.php';
}

/**
 * Login Activity page
 */
function bearmor_login_activity_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/login-activity.php';
}

/**
 * Login Anomalies page
 */
function bearmor_login_anomalies_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/login-anomalies.php';
}

/**
 * Hardening page
 */
function bearmor_hardening_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/hardening.php';
}

/**
 * Activity Log page
 */
function bearmor_activity_log_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/activity-log.php';
}

/**
 * Vulnerabilities page
 */
function bearmor_vulnerabilities_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/vulnerabilities.php';
}

/**
 * Settings page
 */
function bearmor_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/settings.php';
}
