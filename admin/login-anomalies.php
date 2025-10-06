<?php
/**
 * Login Anomalies Admin Page
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Enqueue dashboard CSS
wp_enqueue_style( 'bearmor-dashboard', plugins_url( 'assets/css/dashboard.css', dirname( __FILE__ ) ), array(), '1.0.0' );

// Handle actions
if ( isset( $_POST['bearmor_mark_safe'] ) && isset( $_POST['anomaly_id'] ) && check_admin_referer( 'bearmor_mark_safe' ) ) {
	$anomaly_id = intval( $_POST['anomaly_id'] );
	Bearmor_Anomaly_Detector::mark_safe( $anomaly_id );
	echo '<div class="notice notice-success"><p><strong>Anomaly marked as safe!</strong></p></div>';
}

if ( isset( $_POST['bearmor_block_anomaly'] ) && isset( $_POST['anomaly_id'] ) && check_admin_referer( 'bearmor_block_anomaly' ) ) {
	$anomaly_id = intval( $_POST['anomaly_id'] );
	Bearmor_Anomaly_Detector::block_from_anomaly( $anomaly_id );
	echo '<div class="notice notice-success"><p><strong>IP blocked successfully!</strong></p></div>';
}

if ( isset( $_POST['bearmor_block_ip'] ) && isset( $_POST['ip_address'] ) && check_admin_referer( 'bearmor_block_ip' ) ) {
	$ip = sanitize_text_field( $_POST['ip_address'] );
	$permanent = isset( $_POST['permanent'] ) && $_POST['permanent'] === '1';
	Bearmor_Login_Protection::block_ip( $ip, null, 'Manually blocked by admin', $permanent );
	echo '<div class="notice notice-success"><p><strong>IP blocked successfully!</strong></p></div>';
}

if ( isset( $_POST['bearmor_unblock_ip'] ) && isset( $_POST['ip_address'] ) && check_admin_referer( 'bearmor_unblock_ip' ) ) {
	$ip = sanitize_text_field( $_POST['ip_address'] );
	Bearmor_Login_Protection::unblock_ip( $ip );
	echo '<div class="notice notice-success"><p><strong>IP unblocked successfully!</strong></p></div>';
}

if ( isset( $_POST['bearmor_whitelist_ip'] ) && isset( $_POST['ip_address'] ) && check_admin_referer( 'bearmor_whitelist_ip' ) ) {
	$ip = sanitize_text_field( $_POST['ip_address'] );
	Bearmor_Login_Protection::whitelist_ip( $ip );
	echo '<div class="notice notice-success"><p><strong>IP whitelisted successfully!</strong></p></div>';
}

if ( isset( $_POST['bearmor_remove_whitelist'] ) && isset( $_POST['ip_address'] ) && check_admin_referer( 'bearmor_remove_whitelist' ) ) {
	$ip = sanitize_text_field( $_POST['ip_address'] );
	Bearmor_Login_Protection::remove_from_whitelist( $ip );
	echo '<div class="notice notice-success"><p><strong>IP removed from whitelist!</strong></p></div>';
}

// Get data
$anomalies = Bearmor_Anomaly_Detector::get_anomalies( array( 'limit' => 100 ) );
$blocked_ips = Bearmor_Login_Protection::get_blocked_ips();
$whitelist = get_option( 'bearmor_ip_whitelist', array() );

// Get anomaly type labels
function bearmor_get_anomaly_label( $type ) {
	$labels = array(
		'impossible_travel' => '✈️ Impossible Travel',
		'tor_vpn'           => '🕵️ TOR/VPN',
		'new_country'       => '🌍 New Country',
		'new_device'        => '💻 New Device',
		'unusual_time'      => '⏰ Unusual Time',
	);
	return isset( $labels[ $type ] ) ? $labels[ $type ] : $type;
}

// Get score color
function bearmor_get_score_color( $score ) {
	if ( $score >= 80 ) {
		return '#d63638'; // Critical - Red
	} elseif ( $score >= 60 ) {
		return '#d63638'; // High - Red
	} elseif ( $score >= 40 ) {
		return '#dba617'; // Medium - Orange
	} else {
		return '#00a32a'; // Low - Green
	}
}
?>

<div class="wrap">
	<div class="bearmor-header">
		<h1>🚨 Login Anomalies</h1>
		<p class="bearmor-subtitle">Suspicious login patterns and security alerts</p>
	</div>

	<!-- Blocked & Whitelisted IPs (Same as Login Activity) -->
	<div style="margin: 20px 0;">
		<?php if ( ! empty( $blocked_ips ) || ! empty( $whitelist ) ) : ?>
			<h2>🚫 Blocked & Whitelisted IPs</h2>
			<table class="wp-list-table widefat fixed striped" style="margin-bottom: 0;">
				<thead>
					<tr>
						<th style="width: 20%;">IP Address</th>
						<th style="width: 15%;">Status</th>
						<th style="width: 15%;">Expires</th>
						<th style="width: 35%;">Reason</th>
						<th style="width: 15%;">Actions</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $blocked_ips as $block ) : ?>
						<tr style="background: #fff5f5;">
							<td><code><?php echo esc_html( $block->ip_address ); ?></code></td>
							<td><span style="color: #d63638; font-weight: 600;">🔴 Blocked</span></td>
							<td>
								<?php if ( $block->permanent ) : ?>
									<strong style="color: #d63638;">Permanent</strong>
								<?php elseif ( $block->expires_at ) : ?>
									<?php echo esc_html( human_time_diff( current_time( 'timestamp' ), strtotime( $block->expires_at ) ) ); ?>
								<?php else : ?>
									-
								<?php endif; ?>
							</td>
							<td style="font-size: 12px;"><?php echo esc_html( $block->reason ); ?></td>
							<td>
								<form method="post" style="display: inline;">
									<?php wp_nonce_field( 'bearmor_unblock_ip' ); ?>
									<input type="hidden" name="ip_address" value="<?php echo esc_attr( $block->ip_address ); ?>">
									<button type="submit" name="bearmor_unblock_ip" value="1" class="button button-small">
										Unblock
									</button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					
					<?php foreach ( $whitelist as $ip ) : ?>
						<tr style="background: #f0f9f4;">
							<td><code><?php echo esc_html( $ip ); ?></code></td>
							<td><span style="color: #00a32a; font-weight: 600;">✅ Whitelisted</span></td>
							<td>-</td>
							<td style="font-size: 12px; color: #666;">Never blocked</td>
							<td>
								<form method="post" style="display: inline;">
									<?php wp_nonce_field( 'bearmor_remove_whitelist' ); ?>
									<input type="hidden" name="ip_address" value="<?php echo esc_attr( $ip ); ?>">
									<button type="submit" name="bearmor_remove_whitelist" value="1" class="button button-small" onclick="return confirm('Remove from whitelist?');">
										Remove
									</button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php else : ?>
			<div style="background: #f0f9f4; border: 1px solid #00a32a; padding: 15px; border-radius: 5px; margin: 20px 0;">
				<p style="margin: 0; color: #00a32a;"><strong>✅ No blocked IPs</strong> - All login attempts are within normal limits.</p>
			</div>
		<?php endif; ?>
	</div>

	<!-- Detected Anomalies -->
	<div style="margin: 30px 0;">
		<h2>🚨 Detected Anomalies (Last 100)</h2>
		<?php if ( empty( $anomalies ) ) : ?>
			<div style="background: #f0f9f4; border: 1px solid #00a32a; padding: 15px; border-radius: 5px;">
				<p style="margin: 0; color: #00a32a;"><strong>✅ No anomalies detected</strong> - All logins appear normal.</p>
			</div>
		<?php else : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width: 8%;">Score</th>
						<th style="width: 12%;">Type</th>
						<th style="width: 12%;">User</th>
						<th style="width: 12%;">IP</th>
						<th style="width: 5%;">Country</th>
						<th style="width: 28%;">Details</th>
						<th style="width: 10%;">Time</th>
						<th style="width: 13%;">Actions</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $anomalies as $anomaly ) : ?>
						<?php
						$score_color = bearmor_get_score_color( $anomaly->anomaly_score );
						$row_style = $anomaly->status === 'marked_safe' ? 'opacity: 0.5;' : '';
						?>
						<tr style="<?php echo esc_attr( $row_style ); ?>">
							<td>
								<strong style="color: <?php echo esc_attr( $score_color ); ?>; font-size: 16px;">
									<?php echo esc_html( $anomaly->anomaly_score ); ?>
								</strong>
							</td>
							<td><?php echo esc_html( bearmor_get_anomaly_label( $anomaly->anomaly_type ) ); ?></td>
							<td>
								<strong><?php echo esc_html( $anomaly->user_login ); ?></strong><br>
								<span style="font-size: 11px; color: #666;"><?php echo esc_html( $anomaly->user_email ); ?></span>
							</td>
							<td><code style="font-size: 11px;"><?php echo esc_html( $anomaly->ip_address ); ?></code></td>
							<td style="font-size: 20px;" title="<?php echo ! empty( $anomaly->country_code ) ? esc_attr( $anomaly->country_code ) : ''; ?>">
								<?php 
								if ( ! empty( $anomaly->country_code ) ) {
									$code = strtoupper( $anomaly->country_code );
									$flag = '';
									for ( $i = 0; $i < 2; $i++ ) {
										$flag .= mb_chr( ord( $code[ $i ] ) + 127397, 'UTF-8' );
									}
									echo $flag;
								} else {
									echo '<span style="color: #999;">-</span>';
								}
								?>
							</td>
							<td style="font-size: 12px;"><?php echo esc_html( $anomaly->details ); ?></td>
							<td style="font-size: 11px; color: #666;">
								<?php echo esc_html( human_time_diff( strtotime( $anomaly->detected_at ), current_time( 'timestamp' ) ) . ' ago' ); ?>
							</td>
							<td>
								<?php if ( $anomaly->status === 'new' ) : ?>
									<form method="post" style="display: inline;">
										<?php wp_nonce_field( 'bearmor_mark_safe' ); ?>
										<input type="hidden" name="anomaly_id" value="<?php echo esc_attr( $anomaly->id ); ?>">
										<button type="submit" name="bearmor_mark_safe" value="1" class="button button-small" style="font-size: 11px;">
											Mark Safe
										</button>
									</form>
									<form method="post" style="display: inline; margin-left: 3px;">
										<?php wp_nonce_field( 'bearmor_block_anomaly' ); ?>
										<input type="hidden" name="anomaly_id" value="<?php echo esc_attr( $anomaly->id ); ?>">
										<button type="submit" name="bearmor_block_anomaly" value="1" class="button button-small" onclick="return confirm('Block this IP permanently?');" style="font-size: 11px;">
											Block IP
										</button>
									</form>
								<?php elseif ( $anomaly->status === 'marked_safe' ) : ?>
									<span style="color: #00a32a; font-size: 11px;">✅ Safe</span>
								<?php elseif ( $anomaly->status === 'blocked' ) : ?>
									<span style="color: #d63638; font-size: 11px;">🔴 Blocked</span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

	<!-- Help Section -->
	<div style="background: #f0f6fc; border: 1px solid #c3dafe; padding: 20px; border-radius: 5px; margin: 30px 0;">
		<h3 style="margin-top: 0;">ℹ️ Understanding Anomaly Scores</h3>
		<p><strong>Risk Levels:</strong></p>
		<ul style="margin: 0;">
			<li><strong style="color: #d63638;">80-100 (Critical):</strong> Immediate attention required - likely attack</li>
			<li><strong style="color: #d63638;">60-79 (High):</strong> Very suspicious - investigate immediately</li>
			<li><strong style="color: #dba617;">40-59 (Medium):</strong> Unusual activity - worth checking</li>
			<li><strong style="color: #00a32a;">0-39 (Low):</strong> Minor deviation from normal</li>
		</ul>
		<p style="margin-top: 15px;"><strong>Anomaly Types:</strong></p>
		<ul style="margin: 0;">
			<li><strong>✈️ Impossible Travel (90):</strong> Login from different countries within 2 hours</li>
			<li><strong>🌍 New Country (50):</strong> First login from this country</li>
			<li><strong>💻 New Device (40):</strong> Unknown browser or operating system</li>
			<li><strong>⏰ Unusual Time (30):</strong> Login at atypical hour</li>
		</ul>
	</div>
</div>
