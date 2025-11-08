<?php
/**
 * Plugin Name: Bearmor Security
 * Plugin URI: https://bearmor.com
 * Description: Lightweight, robust WordPress security plugin for SMBs.
 * Version: 0.6.2
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
define( 'BEARMOR_VERSION', '0.6.2' );
define( 'BEARMOR_DB_VERSION', '1.1' ); // Database schema version
define( 'BEARMOR_PLUGIN_FILE', __FILE__ );
define( 'BEARMOR_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'BEARMOR_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// Load Plugin Update Checker
require BEARMOR_PLUGIN_DIR . 'plugin-update-checker/plugin-update-checker.php';
use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$bearmor_update_checker = PucFactory::buildUpdateChecker(
	'https://github.com/andreirz/bearmor/',
	__FILE__,
	'bearmor-security'
);

// Set the branch that contains the stable release
$bearmor_update_checker->setBranch('main');

// Load registration classes (will be used for call-home)
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-site-registration.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-license.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-callhome.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-placeholder.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-uptime-sync.php';

/**
 * Check and run database migrations on every load
 */
add_action( 'plugins_loaded', 'bearmor_check_db_version' );
function bearmor_check_db_version() {
	$current_db_version = get_option( 'bearmor_db_version', '1.0' );
	
	if ( version_compare( $current_db_version, BEARMOR_DB_VERSION, '<' ) ) {
		error_log( 'BEARMOR: Database migration needed. Current: ' . $current_db_version . ', Required: ' . BEARMOR_DB_VERSION );
		bearmor_run_db_migrations( $current_db_version );
		update_option( 'bearmor_db_version', BEARMOR_DB_VERSION );
		error_log( 'BEARMOR: Database migrated to version ' . BEARMOR_DB_VERSION );
	}
}

/**
 * Run database migrations
 */
function bearmor_run_db_migrations( $from_version ) {
	global $wpdb;
	
	// Migration 1.0 -> 1.1: Add missing columns
	if ( version_compare( $from_version, '1.1', '<' ) ) {
		error_log( 'BEARMOR: Running migration 1.0 -> 1.1' );
		
		// Add change_type to bearmor_file_changes
		$wpdb->query( "ALTER TABLE {$wpdb->prefix}bearmor_file_changes 
			ADD COLUMN IF NOT EXISTS change_type VARCHAR(20) DEFAULT 'modified' AFTER file_path" );
		
		// Add timestamp and description to bearmor_activity_log
		$wpdb->query( "ALTER TABLE {$wpdb->prefix}bearmor_activity_log 
			ADD COLUMN IF NOT EXISTS timestamp DATETIME DEFAULT CURRENT_TIMESTAMP AFTER id" );
		$wpdb->query( "ALTER TABLE {$wpdb->prefix}bearmor_activity_log 
			ADD COLUMN IF NOT EXISTS description TEXT AFTER action" );
		
		// Add description to bearmor_login_anomalies
		$wpdb->query( "ALTER TABLE {$wpdb->prefix}bearmor_login_anomalies 
			ADD COLUMN IF NOT EXISTS description TEXT AFTER anomaly_type" );
		
		// Increase field size for bearmor_ai_analyses
		$wpdb->query( "ALTER TABLE {$wpdb->prefix}bearmor_ai_analyses 
			MODIFY COLUMN summary_data LONGTEXT" );
		$wpdb->query( "ALTER TABLE {$wpdb->prefix}bearmor_ai_analyses 
			MODIFY COLUMN ai_prompt LONGTEXT" );
		
		error_log( 'BEARMOR: Migration 1.0 -> 1.1 complete' );
	}
}

/**
 * Plugin activation
 */
function bearmor_activate() {
	error_log( 'BEARMOR: Plugin activated' );
	
	// Generate unique site ID (registration happens on first call-home)
	if ( ! get_option( 'bearmor_site_id' ) ) {
		$site_id = wp_generate_uuid4();
		add_option( 'bearmor_site_id', $site_id );
		error_log( 'BEARMOR: Generated site ID: ' . $site_id );
	}

	// Set default settings
	if ( ! get_option( 'bearmor_settings' ) ) {
		$defaults = array(
			'scan_schedule'           => 'daily',
			'notification_email'      => get_option( 'admin_email' ),
			'auto_quarantine'         => false,
			'auto_disable_vulnerable' => false,
			'safe_mode'               => true,
			'firewall_enabled'        => true, // Firewall ON by default
			'first_activation'        => current_time( 'mysql' ),
		);
		add_option( 'bearmor_settings', $defaults );
	}

	// Create database tables
	global $wpdb;
	$charset_collate = $wpdb->get_charset_collate();
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';

	// File checksums table
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_file_checksums (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_file_changes (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_quarantine (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_malware_detections (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_login_attempts (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_blocked_ips (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_login_anomalies (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_user_profiles (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_activity_log (
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
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_vulnerabilities (
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

	// Firewall tables
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_firewall_blocks (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		ip_address VARCHAR(45) NOT NULL,
		request_uri TEXT NOT NULL,
		request_method VARCHAR(10),
		user_agent TEXT,
		rule_matched VARCHAR(255),
		blocked_at DATETIME NOT NULL,
		KEY idx_ip_address (ip_address),
		KEY idx_blocked_at (blocked_at)
	) $charset_collate;";
	dbDelta( $sql );

	// Deep scan results table
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_deep_scan_results (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		scan_type ENUM('database', 'uploads') NOT NULL,
		item_type VARCHAR(50) NOT NULL,
		item_id VARCHAR(255) NOT NULL,
		location TEXT NOT NULL,
		pattern VARCHAR(255),
		matched_code TEXT,
		severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
		status ENUM('pending', 'safe', 'removed') DEFAULT 'pending',
		detected_at DATETIME NOT NULL,
		KEY scan_type (scan_type),
		KEY status (status),
		KEY detected_at (detected_at)
	) $charset_collate;";
	dbDelta( $sql );

	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_firewall_whitelist (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		whitelist_type ENUM('ip', 'uri') NOT NULL,
		value VARCHAR(500) NOT NULL,
		added_at DATETIME NOT NULL,
		KEY idx_type (whitelist_type)
	) $charset_collate;";
	dbDelta( $sql );

	// AI Analyses table
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_ai_analyses (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		summary_data LONGTEXT NOT NULL,
		ai_prompt LONGTEXT NOT NULL,
		ai_response LONGTEXT NOT NULL,
		color_rating ENUM('green', 'gray', 'yellow', 'red') DEFAULT 'gray',
		model_used VARCHAR(50) NOT NULL,
		tokens_used INT NOT NULL,
		created_at DATETIME NOT NULL,
		KEY idx_created_at (created_at),
		KEY idx_color_rating (color_rating)
	) $charset_collate;";
	dbDelta( $sql );

	// Uptime history table (stores downtime periods from Home)
	$sql = "CREATE TABLE {$wpdb->prefix}bearmor_uptime_history (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		duration_minutes INT,
		status VARCHAR(50) DEFAULT 'open',
		synced_at DATETIME NOT NULL,
		KEY idx_start_time (start_time),
		KEY idx_status (status)
	) $charset_collate;";
	dbDelta( $sql );
	
	// Manually add missing columns if they don't exist (dbDelta doesn't modify existing tables)
	$table_name = $wpdb->prefix . 'bearmor_ai_analyses';
	$columns = $wpdb->get_results( "SHOW COLUMNS FROM {$table_name}" );
	$column_names = wp_list_pluck( $columns, 'Field' );
	
	if ( ! in_array( 'ai_prompt', $column_names ) ) {
		$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN ai_prompt LONGTEXT NOT NULL AFTER summary_data" );
	}
	
	if ( ! in_array( 'discretionary_score', $column_names ) ) {
		$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN discretionary_score INT DEFAULT 0 AFTER ai_response" );
	}
	
	if ( ! in_array( 'score_reason', $column_names ) ) {
		$wpdb->query( "ALTER TABLE {$table_name} ADD COLUMN score_reason TEXT AFTER discretionary_score" );
	}

	// Create quarantine directory
	$quarantine_dir = WP_CONTENT_DIR . '/bearmor-quarantine';
	if ( ! file_exists( $quarantine_dir ) ) {
		wp_mkdir_p( $quarantine_dir );
		// Protect directory
		file_put_contents( $quarantine_dir . '/.htaccess', "Order deny,allow\nDeny from all" );
		file_put_contents( $quarantine_dir . '/index.php', '<?php // Silence is golden' );
	}

	// Auto-schedule baseline scan if not done yet
	// Check if baseline table is empty (more reliable than option check)
	$baseline_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_checksums" );
	
	if ( $baseline_count == 0 ) {
		// Schedule baseline scan 2 minutes after activation
		if ( ! wp_next_scheduled( 'bearmor_initial_baseline_scan' ) ) {
			wp_schedule_single_event( time() + 120, 'bearmor_initial_baseline_scan' );
			error_log( 'BEARMOR: Baseline scan scheduled for 2 minutes from now' );
		}
		
		// Also set a flag to trigger on next admin page load (fallback if cron fails)
		update_option( 'bearmor_needs_baseline', true );
		error_log( 'BEARMOR: Baseline needed flag set' );
	}

	// Run database migrations on activation (belt and suspenders)
	bearmor_check_db_version();
	
	// Trigger activation hook for call-home and scheduling
	error_log( 'BEARMOR: Firing bearmor_plugin_activated hook' );
	do_action( 'bearmor_plugin_activated' );
	
	// Load scan scheduler and schedule scans based on default settings
	require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-scan-scheduler.php';
	Bearmor_Scan_Scheduler::schedule_scans();
	
	// Registration will happen on first call-home (daily via WP Cron)
	error_log( 'BEARMOR: Activation complete. Daily call-home and scans scheduled.' );
}
register_activation_hook( __FILE__, 'bearmor_activate' );

/**
 * Plugin deactivation
 */
function bearmor_deactivate() {
	error_log( 'BEARMOR: Plugin deactivated' );
	do_action( 'bearmor_plugin_deactivated' );
}
register_deactivation_hook( __FILE__, 'bearmor_deactivate' );

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
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-firewall.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-honeypot.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-db-scanner.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-uploads-scanner.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-summary-builder.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-ai-analyzer.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-pdf-generator.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-scan-scheduler.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-batch-processor.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-exclusions.php';
require_once BEARMOR_PLUGIN_DIR . 'includes/class-bearmor-security-score.php';

/**
 * Initialize security features
 */
Bearmor_CallHome::init();
Bearmor_Firewall::init();
Bearmor_Honeypot::init();
Bearmor_Login_Protection::init();
Bearmor_Anomaly_Detector::init();
Bearmor_Hardening::init();
Bearmor_2FA::init();
Bearmor_Scan_Scheduler::init();
Bearmor_Activity_Log::init();
Bearmor_Vulnerability_Scanner::init();

/**
 * Auto-run baseline scan (scheduled via WP Cron)
 */
function bearmor_run_initial_baseline_scan() {
	error_log( 'BEARMOR: Running automatic baseline scan...' );
	
	// Check if already done (check table, not option)
	global $wpdb;
	$baseline_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_checksums" );
	
	if ( $baseline_count > 0 ) {
		error_log( 'BEARMOR: Baseline already exists (' . $baseline_count . ' files), skipping' );
		delete_option( 'bearmor_needs_baseline' );
		return;
	}
	
	// Run the scan
	$results = Bearmor_File_Scanner::run_baseline_scan();
	
	// Remove the flag
	delete_option( 'bearmor_needs_baseline' );
	
	error_log( 'BEARMOR: Baseline scan complete - Scanned: ' . $results['scanned'] . ', Stored: ' . $results['stored'] );
}
add_action( 'bearmor_initial_baseline_scan', 'bearmor_run_initial_baseline_scan' );

/**
 * Auto-run baseline on admin_init if needed (fallback if cron fails)
 */
function bearmor_auto_baseline_fallback() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	
	// Check if baseline is needed
	if ( get_option( 'bearmor_needs_baseline' ) ) {
		global $wpdb;
		$baseline_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_checksums" );
		
		if ( $baseline_count == 0 ) {
			error_log( 'BEARMOR: Running baseline scan via admin_init fallback' );
			
			// Run baseline in background (don't block admin)
			wp_schedule_single_event( time() + 5, 'bearmor_initial_baseline_scan' );
			
			// Show notice that scan is starting
			add_action( 'admin_notices', function() {
				?>
				<div class="notice notice-info">
					<p><strong>Bearmor Security:</strong> Baseline scan is starting in the background. This may take a few minutes.</p>
				</div>
				<?php
			} );
			
			// Remove flag after scheduling
			delete_option( 'bearmor_needs_baseline' );
		}
	}
}
add_action( 'admin_init', 'bearmor_auto_baseline_fallback', 5 );

/**
 * Show notice to run baseline scan (only if auto-scan failed)
 */
function bearmor_baseline_scan_notice() {
	global $wpdb;
	$baseline_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_checksums" );
	
	// Only show if baseline doesn't exist and no scan is scheduled
	if ( $baseline_count == 0 && ! wp_next_scheduled( 'bearmor_initial_baseline_scan' ) && current_user_can( 'manage_options' ) ) {
		?>
		<div class="notice notice-warning is-dismissible" style="clear: both; display: block; width: 100%; float: none;">
			<p>
				<strong>Bearmor Security:</strong> Baseline scan not found. Click to start monitoring file changes.
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
 * Check if baseline needs to be created on existing installations
 * This runs once after plugin update to fix sites without baseline
 */
function bearmor_check_baseline_on_load() {
	// Only run once per admin session
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	
	// Check if we've already done this check
	$checked = get_transient( 'bearmor_baseline_checked' );
	if ( $checked ) {
		return;
	}
	
	// Set transient for 1 hour to avoid repeated checks
	set_transient( 'bearmor_baseline_checked', true, HOUR_IN_SECONDS );
	
	// Check if baseline exists
	global $wpdb;
	$baseline_count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_file_checksums" );
	
	if ( $baseline_count == 0 ) {
		// No baseline - set flag to trigger creation
		update_option( 'bearmor_needs_baseline', true );
		error_log( 'BEARMOR: No baseline found on existing installation, triggering auto-creation' );
	}
}
add_action( 'admin_init', 'bearmor_check_baseline_on_load', 1 );

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
		'Security Logs',
		'Security Logs',
		'manage_options',
		'bearmor-security-logs',
		'bearmor_activity_log_page'
	);

	add_submenu_page(
		'bearmor-security',
		'Deep Scan',
		'Deep Scan',
		'manage_options',
		'bearmor-deep-scan',
		'bearmor_deep_scan_page'
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
 * Hide admin notices on Bearmor pages
 */
function bearmor_hide_admin_notices() {
	$screen = get_current_screen();
	
	// Check if we're on a Bearmor page
	if ( $screen && strpos( $screen->id, 'bearmor' ) !== false ) {
		remove_all_actions( 'admin_notices' );
		remove_all_actions( 'all_admin_notices' );
	}
}
add_action( 'admin_head', 'bearmor_hide_admin_notices', 1 );

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
 * Deep Scan page
 */
function bearmor_deep_scan_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/deep-scan.php';
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
	
	// Handle refresh license action
	if ( isset( $_GET['action'] ) && $_GET['action'] === 'refresh_license' ) {
		error_log( '=== BEARMOR: Manual license refresh triggered ===' );
		$site_id = get_option( 'bearmor_site_id' );
		error_log( 'BEARMOR: Site ID: ' . ( $site_id ? $site_id : 'NOT FOUND' ) );
		
		if ( ! $site_id ) {
			error_log( 'BEARMOR: Site ID not found' );
			?>
			<div class="notice notice-error"><p><strong>Error:</strong> Site ID not found. Please reactivate the plugin.</p></div>
			<?php
		} else {
			error_log( 'BEARMOR: Calling verify endpoint' );
			$result = Bearmor_Site_Registration::call_home( 'verify', array(
				'site_id' => $site_id,
				'url'     => home_url(),
			) );
			error_log( 'BEARMOR: call_home result: ' . print_r( $result, true ) );
			
			if ( is_wp_error( $result ) ) {
				error_log( 'BEARMOR: Error from call_home: ' . $result->get_error_message() );
				?>
				<div class="notice notice-error"><p><strong>Error:</strong> <?php echo esc_html( $result->get_error_message() ); ?></p></div>
				<?php
			} else {
				error_log( 'BEARMOR: Updating license from response' );
				Bearmor_License::update_from_response( $result );
				?>
				<div class="notice notice-success"><p>License refreshed successfully!</p></div>
				<?php
			}
		}
		error_log( '=== BEARMOR: Manual license refresh complete ===' );
	}
	
	require_once BEARMOR_PLUGIN_DIR . 'admin/settings.php';
}

/**
 * Ajax handler for database scan
 */
add_action( 'wp_ajax_bearmor_scan_database', 'bearmor_ajax_scan_database' );
function bearmor_ajax_scan_database() {
	check_ajax_referer( 'bearmor_deep_scan', 'nonce' );
	
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}

	global $wpdb;
	$offset = isset( $_POST['offset'] ) ? intval( $_POST['offset'] ) : 0;
	$batch_size = 50;

	// Clear old results on first request
	if ( $offset === 0 ) {
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bearmor_deep_scan_results WHERE scan_type = 'database'" );
	}

	// Get counts for progress
	$counts = Bearmor_DB_Scanner::get_counts();
	$total = $counts['posts'] + $counts['comments'] + $counts['options'];

	// Scan posts
	if ( $offset < $counts['posts'] ) {
		$results = Bearmor_DB_Scanner::scan_batch( $batch_size, $offset );
		
		// Save results to database and add DB ID to results
		foreach ( $results as $key => $result ) {
			$wpdb->insert(
				$wpdb->prefix . 'bearmor_deep_scan_results',
				array(
					'scan_type'    => 'database',
					'item_type'    => $result['type'],
					'item_id'      => $result['id'],
					'location'     => $result['location'],
					'pattern'      => $result['pattern'],
					'matched_code' => $result['matched'],
					'severity'     => $result['severity'],
					'detected_at'  => current_time( 'mysql' ),
				)
			);
			// Add the database ID to the result for frontend
			$results[ $key ]['db_id'] = $wpdb->insert_id;
		}
		
		$next_offset = $offset + $batch_size;
		$progress = min( 100, round( ( $next_offset / $total ) * 100 ) );
		$status = "Scanning posts... ({$next_offset} / {$counts['posts']})";
		$complete = false;
	}
	// Scan comments
	elseif ( $offset < $counts['posts'] + $counts['comments'] ) {
		$comment_offset = $offset - $counts['posts'];
		$results = Bearmor_DB_Scanner::scan_comments_batch( $batch_size, $comment_offset );
		
		// Save results to database and add DB ID to results
		foreach ( $results as $key => $result ) {
			$wpdb->insert(
				$wpdb->prefix . 'bearmor_deep_scan_results',
				array(
					'scan_type'    => 'database',
					'item_type'    => $result['type'],
					'item_id'      => $result['id'],
					'location'     => $result['location'],
					'pattern'      => $result['pattern'],
					'matched_code' => $result['matched'],
					'severity'     => $result['severity'],
					'detected_at'  => current_time( 'mysql' ),
				)
			);
			$results[ $key ]['db_id'] = $wpdb->insert_id;
		}
		
		$next_offset = $offset + $batch_size;
		$progress = min( 100, round( ( $next_offset / $total ) * 100 ) );
		$status = "Scanning comments... (" . ( $comment_offset + $batch_size ) . " / {$counts['comments']})";
		$complete = false;
	}
	// Scan options
	elseif ( $offset < $total ) {
		$option_offset = $offset - $counts['posts'] - $counts['comments'];
		$results = Bearmor_DB_Scanner::scan_options_batch( $batch_size, $option_offset );
		
		// Save results to database and add DB ID to results
		foreach ( $results as $key => $result ) {
			$wpdb->insert(
				$wpdb->prefix . 'bearmor_deep_scan_results',
				array(
					'scan_type'    => 'database',
					'item_type'    => $result['type'],
					'item_id'      => $result['id'],
					'location'     => $result['location'],
					'pattern'      => $result['pattern'],
					'matched_code' => $result['matched'],
					'severity'     => $result['severity'],
					'detected_at'  => current_time( 'mysql' ),
				)
			);
			$results[ $key ]['db_id'] = $wpdb->insert_id;
		}
		
		$next_offset = $offset + $batch_size;
		$progress = min( 100, round( ( $next_offset / $total ) * 100 ) );
		$status = "Scanning options... (" . ( $option_offset + $batch_size ) . " / {$counts['options']})";
		$complete = $next_offset >= $total;
	}
	else {
		$results = array();
		$next_offset = $offset;
		$progress = 100;
		$status = "Scan complete!";
		$complete = true;
	}

	wp_send_json_success( array(
		'results'     => $results,
		'next_offset' => $next_offset,
		'progress'    => $progress,
		'status'      => $status,
		'complete'    => $complete,
	) );
}

/**
 * Ajax handler for uploads scan
 */
add_action( 'wp_ajax_bearmor_scan_uploads', 'bearmor_ajax_scan_uploads' );
function bearmor_ajax_scan_uploads() {
	check_ajax_referer( 'bearmor_deep_scan', 'nonce' );
	
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}

	global $wpdb;
	$offset = isset( $_POST['offset'] ) ? intval( $_POST['offset'] ) : 0;
	$batch_size = 50;

	// Clear cache and old results on first request
	if ( $offset === 0 ) {
		delete_transient( 'bearmor_uploads_file_count' );
		$wpdb->query( "DELETE FROM {$wpdb->prefix}bearmor_deep_scan_results WHERE scan_type = 'uploads'" );
	}

	// Get total file count (cached for performance)
	$total = get_transient( 'bearmor_uploads_file_count' );
	if ( false === $total ) {
		$total = Bearmor_Uploads_Scanner::get_file_count();
		set_transient( 'bearmor_uploads_file_count', $total, HOUR_IN_SECONDS );
	}

	// Handle empty uploads folder
	if ( $total == 0 ) {
		wp_send_json_success( array(
			'results'     => array(),
			'next_offset' => 0,
			'progress'    => 100,
			'status'      => 'No files in uploads folder',
			'complete'    => true,
		) );
	}

	// Scan batch
	$results = Bearmor_Uploads_Scanner::scan_batch( $batch_size, $offset );
	
	// Save results to database
	foreach ( $results as $result ) {
		$wpdb->insert(
			$wpdb->prefix . 'bearmor_deep_scan_results',
			array(
				'scan_type'    => 'uploads',
				'item_type'    => $result['type'],
				'item_id'      => $result['file'],
				'location'     => $result['location'],
				'pattern'      => $result['pattern'],
				'matched_code' => $result['matched'],
				'severity'     => $result['severity'],
				'detected_at'  => current_time( 'mysql' ),
			)
		);
	}
	
	$next_offset = $offset + $batch_size;
	$progress = min( 100, round( ( $next_offset / $total ) * 100 ) );
	$status = "Scanning files... ({$next_offset} / {$total})";
	$complete = $next_offset >= $total;

	wp_send_json_success( array(
		'results'     => $results,
		'next_offset' => $next_offset,
		'progress'    => $progress,
		'status'      => $status,
		'complete'    => $complete,
	) );
}

/**
 * Ajax handler for viewing threat details
 */
add_action( 'wp_ajax_bearmor_view_threat', 'bearmor_ajax_view_threat' );
function bearmor_ajax_view_threat() {
	check_ajax_referer( 'bearmor_deep_scan', 'nonce' );
	
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}

	global $wpdb;
	$id = isset( $_POST['id'] ) ? intval( $_POST['id'] ) : 0;
	
	$result = $wpdb->get_row(
		$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}bearmor_deep_scan_results WHERE id = %d", $id ),
		ARRAY_A
	);

	if ( ! $result ) {
		wp_send_json_error( array( 'message' => 'Threat not found' ) );
	}

	$html = '<table class="widefat">';
	$html .= '<tr><th>Location:</th><td>' . esc_html( $result['location'] ) . '</td></tr>';
	$html .= '<tr><th>Pattern:</th><td><code>' . esc_html( $result['pattern'] ) . '</code></td></tr>';
	$html .= '<tr><th>Severity:</th><td><strong>' . strtoupper( $result['severity'] ) . '</strong></td></tr>';
	$html .= '<tr><th>Full Matched Code:</th><td><pre style="background: #f5f5f5; padding: 10px; overflow-x: auto;">' . esc_html( $result['matched_code'] ) . '</pre></td></tr>';
	$html .= '<tr><th>Detected:</th><td>' . esc_html( $result['detected_at'] ) . '</td></tr>';
	$html .= '</table>';

	wp_send_json_success( array( 'html' => $html ) );
}

/**
 * Ajax handler for marking threat as safe
 */
add_action( 'wp_ajax_bearmor_mark_safe', 'bearmor_ajax_mark_safe' );
function bearmor_ajax_mark_safe() {
	check_ajax_referer( 'bearmor_deep_scan', 'nonce' );
	
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}

	global $wpdb;
	$id = isset( $_POST['id'] ) ? intval( $_POST['id'] ) : 0;
	
	$updated = $wpdb->update(
		$wpdb->prefix . 'bearmor_deep_scan_results',
		array( 'status' => 'safe' ),
		array( 'id' => $id ),
		array( '%s' ),
		array( '%d' )
	);

	if ( $updated !== false ) {
		wp_send_json_success( array( 'message' => 'Marked as safe' ) );
	} else {
		wp_send_json_error( array( 'message' => 'Failed to update' ) );
	}
}

/**
 * Ajax handler for cleaning threat (removing malicious code)
 */
add_action( 'wp_ajax_bearmor_clean_threat', 'bearmor_ajax_clean_threat' );
function bearmor_ajax_clean_threat() {
	check_ajax_referer( 'bearmor_deep_scan', 'nonce' );
	
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}

	global $wpdb;
	$id = isset( $_POST['id'] ) ? intval( $_POST['id'] ) : 0;
	$item_id = isset( $_POST['item_id'] ) ? intval( $_POST['item_id'] ) : 0;
	$item_type = isset( $_POST['item_type'] ) ? sanitize_text_field( $_POST['item_type'] ) : '';

	// Get the threat details
	$threat = $wpdb->get_row(
		$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}bearmor_deep_scan_results WHERE id = %d", $id ),
		ARRAY_A
	);

	if ( ! $threat ) {
		wp_send_json_error( array( 'message' => 'Threat not found' ) );
	}

	$success = false;

	// Remove malicious code based on type
	if ( $item_type === 'post_content' ) {
		// Get post content
		$post = get_post( $item_id );
		if ( $post ) {
			// SAFELY remove only the exact malicious code (not entire blocks)
			// First, try to find the exact match
			if ( strpos( $post->post_content, $threat['matched_code'] ) !== false ) {
				$cleaned_content = str_replace( $threat['matched_code'], '<!-- Malicious code removed by Bearmor Security -->', $post->post_content );
				$success = wp_update_post( array(
					'ID' => $item_id,
					'post_content' => $cleaned_content,
				), true ); // Return WP_Error on failure
				
				// Check if update failed
				if ( is_wp_error( $success ) ) {
					wp_send_json_error( array( 'message' => 'Failed to update post: ' . $success->get_error_message() ) );
				}
			} else {
				wp_send_json_error( array( 'message' => 'Malicious code not found in post (may have been already removed)' ) );
			}
		}
	} elseif ( $item_type === 'comment_content' ) {
		// Get comment
		$comment = get_comment( $item_id );
		if ( $comment ) {
			// Remove the malicious code
			if ( strpos( $comment->comment_content, $threat['matched_code'] ) !== false ) {
				$cleaned_content = str_replace( $threat['matched_code'], '[Removed by Bearmor Security]', $comment->comment_content );
				$success = wp_update_comment( array(
					'comment_ID' => $item_id,
					'comment_content' => $cleaned_content,
				) );
			} else {
				wp_send_json_error( array( 'message' => 'Malicious code not found in comment' ) );
			}
		}
	} elseif ( $item_type === 'option_value' ) {
		// Get option name from location
		preg_match( '/Option: (.+)/', $threat['location'], $matches );
		$option_name = isset( $matches[1] ) ? $matches[1] : '';
		
		if ( $option_name ) {
			$option_value = get_option( $option_name );
			if ( $option_value && strpos( $option_value, $threat['matched_code'] ) !== false ) {
				// Remove the malicious code
				$cleaned_value = str_replace( $threat['matched_code'], '', $option_value );
				$success = update_option( $option_name, $cleaned_value );
			} else {
				wp_send_json_error( array( 'message' => 'Malicious code not found in option' ) );
			}
		}
	}

	if ( $success ) {
		// Mark as removed in database
		$wpdb->update(
			$wpdb->prefix . 'bearmor_deep_scan_results',
			array( 'status' => 'removed' ),
			array( 'id' => $id ),
			array( '%s' ),
			array( '%d' )
		);
		wp_send_json_success( array( 'message' => 'Malicious code removed' ) );
	} else {
		wp_send_json_error( array( 'message' => 'Failed to clean threat' ) );
	}
}

/**
 * Ajax handler for quarantining file
 */
add_action( 'wp_ajax_bearmor_quarantine_file', 'bearmor_ajax_quarantine_file' );
function bearmor_ajax_quarantine_file() {
	check_ajax_referer( 'bearmor_deep_scan', 'nonce' );
	
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}

	global $wpdb;
	$id = isset( $_POST['id'] ) ? intval( $_POST['id'] ) : 0;
	$file = isset( $_POST['file'] ) ? sanitize_text_field( $_POST['file'] ) : '';

	if ( ! file_exists( $file ) ) {
		wp_send_json_error( array( 'message' => 'File not found' ) );
	}

	$success = Bearmor_Uploads_Scanner::quarantine_file( $file );

	if ( $success ) {
		$wpdb->update(
			$wpdb->prefix . 'bearmor_deep_scan_results',
			array( 'status' => 'removed' ),
			array( 'id' => $id ),
			array( '%s' ),
			array( '%d' )
		);
		wp_send_json_success( array( 'message' => 'File quarantined' ) );
	} else {
		wp_send_json_error( array( 'message' => 'Security: File must be in uploads directory' ) );
	}

	$success = Bearmor_Uploads_Scanner::delete_file( $file );

	if ( $success ) {
		$wpdb->update(
			$wpdb->prefix . 'bearmor_deep_scan_results',
			array( 'status' => 'removed' ),
			array( 'id' => $id ),
			array( '%s' ),
			array( '%d' )
		);
		wp_send_json_success( array( 'message' => 'File deleted successfully' ) );
	} else {
		wp_send_json_error( array( 'message' => 'Failed to delete file. Check file permissions.' ) );
	}
}

/**
 * AJAX handler for manual AI analysis trigger
 */
add_action( 'wp_ajax_bearmor_trigger_ai_analysis', 'bearmor_ajax_trigger_ai_analysis' );
function bearmor_ajax_trigger_ai_analysis() {
	error_log( 'BEARMOR AJAX: bearmor_trigger_ai_analysis called' );
	
	check_ajax_referer( 'bearmor_ai_analysis', 'nonce' );
	
	if ( ! current_user_can( 'manage_options' ) ) {
		error_log( 'BEARMOR AJAX: Access denied' );
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}
	
	error_log( 'BEARMOR AJAX: Starting analysis...' );
	
	// Run AI analysis
	$result = Bearmor_AI_Analyzer::analyze( 7 );
	
	error_log( 'BEARMOR AJAX: Analysis result: ' . print_r( $result, true ) );
	
	if ( is_wp_error( $result ) ) {
		error_log( 'BEARMOR AJAX: Error - ' . $result->get_error_message() );
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}
	
	error_log( 'BEARMOR AJAX: Success - sending response' );
	
	wp_send_json_success( array( 
		'message' => 'Analysis completed',
		'color'   => $result['color'],
		'tokens'  => $result['tokens_used']
	) );
}

/**
 * AJAX handler for PDF report generation
 */
add_action( 'wp_ajax_bearmor_generate_pdf_report', 'bearmor_ajax_generate_pdf_report' );
function bearmor_ajax_generate_pdf_report() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( array( 'message' => 'Access denied' ) );
	}
	
	$days = isset( $_POST['days'] ) ? intval( $_POST['days'] ) : 7;
	
	error_log( 'BEARMOR PDF: Generating report for ' . $days . ' days' );
	
	$result = Bearmor_PDF_Generator::generate( $days );
	
	if ( is_wp_error( $result ) ) {
		error_log( 'BEARMOR PDF Error: ' . $result->get_error_message() );
		wp_send_json_error( array( 'message' => $result->get_error_message() ) );
	}
	
	error_log( 'BEARMOR PDF: Report generated at ' . $result );
	
	wp_send_json_success( array( 
		'message' => 'Report generated successfully',
		'file'    => basename( $result ),
		'url'     => admin_url( 'admin-ajax.php?action=bearmor_download_pdf&file=' . basename( $result ) )
	) );
}

/**
 * AJAX handler for PDF report download
 */
add_action( 'wp_ajax_bearmor_download_pdf', 'bearmor_ajax_download_pdf' );
function bearmor_ajax_download_pdf() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Access denied' );
	}
	
	$file = isset( $_GET['file'] ) ? sanitize_file_name( $_GET['file'] ) : '';
	
	if ( empty( $file ) ) {
		wp_die( 'No file specified' );
	}
	
	Bearmor_PDF_Generator::download( $file );
}
