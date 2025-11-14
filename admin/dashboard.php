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

// Get license info
$license_info = Bearmor_License::get_info();
$is_pro = Bearmor_License::is_pro();
$plan = $license_info['plan'];
$expires = $license_info['expires'];
// Enqueue dashboard styles
wp_enqueue_style( 'bearmor-dashboard', BEARMOR_PLUGIN_URL . 'assets/css/dashboard.css', array(), BEARMOR_VERSION );
?>

<div class="wrap bearmor-dashboard">
	<h1>Bearmor Security</h1>

	<div class="bearmor-top-row">
		<!-- Quick Actions - Left (1/3) -->
		<div class="bearmor-quick-actions" style="position: relative;">
			<!-- Plan Badge - Top Right Corner -->
			<div style="position: absolute; top: 12px; right: 12px; z-index: 10;">
				<?php if ( $is_pro ) : ?>
					<div style="
						background: linear-gradient(135deg, #8269FF 0%, #6B52E8 100%);
						color: white;
						padding: 6px 12px;
						border-radius: 20px;
						font-size: 12px;
						font-weight: 600;
						cursor: help;
					" title="Pro features enabled">
						PRO
					</div>
				<?php else : ?>
					<div style="
						background: #999;
						color: white;
						padding: 6px 12px;
						border-radius: 20px;
						font-size: 12px;
						font-weight: 600;
						cursor: help;
					" title="Free tier">
						FREE
					</div>
				<?php endif; ?>
			</div>
			
			<!-- Left Column: Scans & Hardening -->
			<div class="bearmor-actions-column">
				<h4 style="margin: 0 0 12px 0; font-size: 13px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.5px;">Actions</h4>
				<div class="bearmor-actions-grid">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-hardening' ) ); ?>" class="bearmor-action-card">
						<span class="dashicons dashicons-shield-alt"></span>
						<span>Apply Hardening</span>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-malware-alerts' ) ); ?>" class="bearmor-action-card">
						<span class="dashicons dashicons-search"></span>
						<span>Run Malware Scan</span>
					</a>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-deep-scan' ) ); ?>" class="bearmor-action-card <?php echo ! $is_pro ? 'bearmor-action-locked' : ''; ?>" <?php echo ! $is_pro ? 'onclick="alert(\'Deep Scan is a PRO feature. Upgrade to unlock!\'); return false;"' : ''; ?>>
						<span class="dashicons dashicons-search"></span>
						<span>Run Deep Scan<?php echo ! $is_pro ? ' 🔒' : ''; ?></span>
					</a>
				</div>
			</div>
			
			<!-- Right Column: Settings & Reports -->
			<div class="bearmor-actions-column">
				<h4 style="margin: 0 0 12px 0; font-size: 13px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.5px;">&nbsp;</h4>
				<div class="bearmor-actions-grid">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="bearmor-action-card">
						<span class="dashicons dashicons-admin-settings"></span>
						<span>Settings</span>
					</a>
					<a href="#" class="bearmor-action-card" onclick="bearmor_generate_pdf_report(); return false;">
						<span class="dashicons dashicons-media-document"></span>
						<span>Generate PDF Report</span>
					</a>
				</div>
			</div>
		</div>

		<!-- Security Score - Middle (1/6) -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-security-score.php'; ?>

		<!-- AI Security Summary - Right (1/3) -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-ai-summary.php'; ?>
	</div>

<script>
function bearmor_generate_pdf_report() {
	if ( !confirm( 'Generate PDF report for the last 7 days?' ) ) {
		return;
	}
	
	var button = event.target.closest( '.bearmor-action-card' );
	var originalText = button.textContent;
	button.textContent = 'Generating...';
	button.style.pointerEvents = 'none';
	button.style.opacity = '0.6';
	
	jQuery.post( ajaxurl, {
		action: 'bearmor_generate_pdf_report',
		days: 7
	}, function( response ) {
		console.log( 'PDF Generation Response:', response );
		if ( response.success ) {
			// Open in new tab
			window.open( response.data.url, '_blank' );
			button.textContent = originalText;
			button.style.pointerEvents = 'auto';
			button.style.opacity = '1';
		} else {
			alert( 'Error: ' + ( response.data ? response.data.message : 'Unknown error' ) );
			button.textContent = originalText;
			button.style.pointerEvents = 'auto';
			button.style.opacity = '1';
		}
	}).fail( function( xhr, status, error ) {
		console.error( 'AJAX Error:', error, xhr.responseText );
		alert( 'Network error: ' + error );
		button.textContent = originalText;
		button.style.pointerEvents = 'auto';
		button.style.opacity = '1';
	});
}
</script>

	<!-- Widgets Grid (4+2 Layout) -->
	<div class="bearmor-widgets-grid">
		<!-- TOP ROW: 4 Security Widgets (25% each) -->
		
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
							<?php if ( $high_count > 0 ) : ?>
								<span style="color: #d63638; font-weight: 600;">🔴 <?php echo esc_html( $high_count ); ?> High</span>
							<?php endif; ?>
							<?php if ( $medium_count > 0 ) : ?>
								<span style="color: #f56e28; font-weight: 600; margin-left: 8px;">🟠 <?php echo esc_html( $medium_count ); ?> Medium</span>
							<?php endif; ?>
							<?php if ( $critical_count > 0 ) : ?>
								<span style="color: #d63638; font-weight: 600; margin-left: 8px;">🔴 <?php echo esc_html( $critical_count ); ?> Critical (legacy)</span>
							<?php endif; ?>
							<?php if ( $low_count > 0 ) : ?>
								<span style="color: #00a32a; font-weight: 600; margin-left: 8px;">🟢 <?php echo esc_html( $low_count ); ?> Low</span>
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

		<!-- Login Activity Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-login-events.php'; ?>

		<!-- Login Anomalies Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-anomalies.php'; ?>

		<!-- Firewall Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-firewall.php'; ?>

		<!-- BOTTOM ROW: File Changes + Uptime (50% each) -->
		
		<!-- File Changes Widget -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-file-changes.php'; ?>

		<!-- Uptime Widget (Pro) -->
		<?php require BEARMOR_PLUGIN_DIR . 'admin/partials/widget-uptime.php'; ?>

	</div>

</div>
