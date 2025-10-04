<?php
/**
 * Dashboard View
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get settings
$settings = get_option( 'bearmor_settings', array() );
$last_scan = get_option( 'bearmor_last_scan_time' );

// Enqueue dashboard styles
wp_enqueue_style( 'bearmor-dashboard', BEARMOR_PLUGIN_URL . 'assets/css/dashboard.css', array(), BEARMOR_VERSION );
?>

<div class="wrap bearmor-dashboard">
	<div class="bearmor-header">
		<h1>
			<span class="dashicons dashicons-shield" style="color: #8269FF;"></span>
			Bearmor Security
		</h1>
	</div>

	<!-- Top Row: Score + Quick Actions -->
	<div class="bearmor-top-row">
		<!-- Security Score -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-security-score.php'; ?>

		<!-- Quick Actions -->
		<div class="bearmor-quick-actions">
			<h3>Quick Actions</h3>
			<div class="bearmor-actions-grid">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="bearmor-action-card">
					<span class="dashicons dashicons-admin-settings"></span>
					<span>Settings</span>
				</a>
				<a href="#" class="bearmor-action-card">
					<span class="dashicons dashicons-shield-alt"></span>
					<span>Apply Hardening</span>
				</a>
				<a href="#" class="bearmor-action-card">
					<span class="dashicons dashicons-search"></span>
					<span>Run Scan</span>
				</a>
			</div>
		</div>
	</div>

	<!-- Widgets Grid -->
	<div class="bearmor-widgets-grid">
		
		<!-- Last Scan Widget -->
		<div class="bearmor-widget">
			<div class="bearmor-widget-icon">
				<span class="dashicons dashicons-search"></span>
			</div>
			<div class="bearmor-widget-content">
				<h3>Last Scan</h3>
				<p class="bearmor-widget-value">
					<?php echo $last_scan ? esc_html( human_time_diff( strtotime( $last_scan ), current_time( 'timestamp' ) ) . ' ago' ) : 'Never'; ?>
				</p>
				<a href="#" class="bearmor-widget-action">Run Scan Now</a>
			</div>
		</div>

		<!-- File Changes Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-file-changes.php'; ?>

		<!-- Login Activity Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-login-events.php'; ?>

		<!-- Login Anomalies Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-anomalies.php'; ?>

		<!-- Firewall Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-firewall.php'; ?>

		<!-- Uptime Widget (Pro) -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-uptime.php'; ?>

	</div>

	<!-- AI Security Summary (Full Width) -->
	<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-ai-summary.php'; ?>

</div>
