<?php
/**
 * Login Activity Admin Page
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

// Get data - limit to last 100 total (both failed and successful)
$all_attempts = Bearmor_Login_Protection::get_login_attempts( array( 'success' => null, 'limit' => 100 ) );
$blocked_ips = Bearmor_Login_Protection::get_blocked_ips();
$whitelist = get_option( 'bearmor_ip_whitelist', array() );
?>

<div class="wrap">
	<div class="bearmor-header">
		<h1>🔐 Login Activity</h1>
		<p class="bearmor-subtitle">Monitor login attempts and manage blocked IPs</p>
	</div>

	<!-- Blocked & Whitelisted IPs (Most Important) -->
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

	<!-- Recent Login Attempts (Failed & Successful) -->
	<div style="margin: 30px 0;">
		<h2>📋 Recent Login Attempts (Last 100)</h2>
		<?php if ( empty( $all_attempts ) ) : ?>
			<p style="color: #666;">No login attempts recorded.</p>
		<?php else : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width: 10%;">Status</th>
						<th style="width: 15%;">IP Address</th>
						<th style="width: 8%;">Country</th>
						<th style="width: 12%;">Username</th>
						<th style="width: 10%;">Time</th>
						<th style="width: 30%;">User Agent</th>
						<th style="width: 15%;">Actions</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $all_attempts as $attempt ) : ?>
						<tr style="<?php echo $attempt->success ? 'background: #f0f9f4;' : 'background: #fff5f5;'; ?>">
							<td>
								<?php if ( $attempt->success ) : ?>
									<span style="color: #00a32a; font-weight: 600; font-size: 11px;">✅ Success</span>
								<?php else : ?>
									<span style="color: #d63638; font-weight: 600; font-size: 11px;">❌ Failed</span>
								<?php endif; ?>
							</td>
							<td><code style="font-size: 11px;"><?php echo esc_html( $attempt->ip_address ); ?></code></td>
							<td style="font-size: 16px;">
								<?php 
								if ( ! empty( $attempt->country_code ) ) {
									echo esc_html( $attempt->country_code );
								} else {
									echo '<span style="color: #999;">-</span>';
								}
								?>
							</td>
							<td><?php echo esc_html( $attempt->username ); ?></td>
							<td style="font-size: 11px; color: #666;"><?php echo esc_html( human_time_diff( strtotime( $attempt->attempted_at ), current_time( 'timestamp' ) ) . ' ago' ); ?></td>
							<td style="font-size: 10px; color: #999;"><?php echo esc_html( substr( $attempt->user_agent, 0, 40 ) ); ?></td>
							<td>
								<form method="post" style="display: inline;">
									<?php wp_nonce_field( 'bearmor_block_ip' ); ?>
									<input type="hidden" name="ip_address" value="<?php echo esc_attr( $attempt->ip_address ); ?>">
									<input type="hidden" name="permanent" value="1">
									<button type="submit" name="bearmor_block_ip" value="1" class="button button-small" onclick="return confirm('Block this IP permanently?');" style="font-size: 11px;">
										Block
									</button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>

	<!-- Help Section -->
	<div style="background: #f0f6fc; border: 1px solid #c3dafe; padding: 20px; border-radius: 5px; margin: 30px 0;">
		<h3 style="margin-top: 0;">ℹ️ Understanding Login Protection</h3>
		<p><strong>Rate Limiting:</strong></p>
		<ul style="margin: 0;">
			<li><strong>5 failed attempts</strong> → 5 minute lockout</li>
			<li><strong>10 failed attempts</strong> → 30 minute lockout</li>
			<li><strong>20 failed attempts</strong> → 24 hour lockout</li>
		</ul>
		<p style="margin-top: 15px;"><strong>Actions:</strong></p>
		<ul style="margin: 0;">
			<li><strong>Block IP:</strong> Permanently block an IP address</li>
			<li><strong>Unblock:</strong> Remove a block (temporary or permanent)</li>
			<li><strong>Whitelist:</strong> Never block this IP (e.g., your office IP)</li>
		</ul>
	</div>
</div>
