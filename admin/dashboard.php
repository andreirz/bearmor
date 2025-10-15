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
			<div class="bearmor-actions-grid">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="bearmor-action-card">
					<span class="dashicons dashicons-admin-settings"></span>
					<span>Settings</span>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-hardening' ) ); ?>" class="bearmor-action-card">
					<span class="dashicons dashicons-shield-alt"></span>
					<span>Apply Hardening</span>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-malware-alerts' ) ); ?>" class="bearmor-action-card">
					<span class="dashicons dashicons-search"></span>
					<span>Run Scan</span>
				</a>
			</div>
		</div>
	</div>

	<!-- Widgets Grid -->
	<div class="bearmor-widgets-grid">
		<!-- Last Scan Widget -->
		<?php
		$last_malware_scan = get_option( 'bearmor_last_malware_scan' );
		$scan_results = get_option( 'bearmor_malware_scan_results', array() );
		
		// Get threat counts by severity
		$threats = Bearmor_Malware_Scanner::get_threats( 'pending' );
		$critical_count = count( array_filter( $threats, function( $t ) { return $t->severity === 'critical'; } ) );
		$high_count = count( array_filter( $threats, function( $t ) { return $t->severity === 'high'; } ) );
		$medium_count = count( array_filter( $threats, function( $t ) { return $t->severity === 'medium'; } ) );
		$low_count = count( array_filter( $threats, function( $t ) { return $t->severity === 'low'; } ) );
		$total_threats = count( $threats );
		?>
		<div class="bearmor-widget">
			<div class="bearmor-widget-icon">
				<span class="dashicons dashicons-search"></span>
			</div>
			<div class="bearmor-widget-content">
				<h3>Last Scan</h3>
				<?php if ( $last_malware_scan ) : ?>
					<p style="font-size: 13px; color: #666; margin-bottom: 8px;">
						<?php echo esc_html( human_time_diff( strtotime( $last_malware_scan ), current_time( 'timestamp' ) ) . ' ago' ); ?>
					</p>
					<?php if ( $total_threats > 0 ) : ?>
						<div class="bearmor-scan-threats" style="font-size: 12px; color: #666; margin-bottom: 12px;">
							<?php if ( $critical_count > 0 ) : ?>
								<span style="color: #d63638; font-weight: 600;">🔴 <?php echo $critical_count; ?> Critical</span>
							<?php endif; ?>
							<?php if ( $high_count > 0 ) : ?>
								<span style="color: #f56e28; font-weight: 600; margin-left: 8px;">🟠 <?php echo $high_count; ?> High</span>
							<?php endif; ?>
							<?php if ( $medium_count > 0 ) : ?>
								<span style="color: #dba617; font-weight: 600; margin-left: 8px;">🟡 <?php echo $medium_count; ?> Medium</span>
							<?php endif; ?>
							<?php if ( $low_count > 0 ) : ?>
								<span style="color: #00a32a; font-weight: 600; margin-left: 8px;">🟢 <?php echo $low_count; ?> Low</span>
							<?php endif; ?>
						</div>
					<?php else : ?>
						<p style="font-size: 12px; color: #00a32a; margin-bottom: 12px;">✅ No threats detected</p>
					<?php endif; ?>
				<?php else : ?>
					<p class="bearmor-widget-value">Never</p>
				<?php endif; ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-malware-alerts' ) ); ?>" class="bearmor-widget-action">
					<?php echo $last_malware_scan ? 'View Threats' : 'Run Scan Now'; ?>
				</a>
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
