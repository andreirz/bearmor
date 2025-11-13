<?php
/**
 * Login Security Admin Page
 * Combined Login Activity + Login Anomalies
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Enqueue dashboard CSS
wp_enqueue_style( 'bearmor-dashboard', plugins_url( 'assets/css/dashboard.css', dirname( __FILE__ ) ), array(), '1.0.0' );

// Handle IP blocking/unblocking actions
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

// Handle anomaly actions
if ( isset( $_POST['bearmor_dismiss_anomaly'] ) && isset( $_POST['anomaly_id'] ) && check_admin_referer( 'bearmor_dismiss_anomaly' ) ) {
	global $wpdb;
	$anomaly_id = intval( $_POST['anomaly_id'] );
	$wpdb->update(
		$wpdb->prefix . 'bearmor_login_anomalies',
		array( 'status' => 'dismissed' ),
		array( 'id' => $anomaly_id ),
		array( '%s' ),
		array( '%d' )
	);
	echo '<div class="notice notice-success"><p><strong>Anomaly dismissed!</strong></p></div>';
}

// === LOGIN ACTIVITY ===
$activity_per_page = 25;
$activity_page = isset( $_GET['activity_paged'] ) ? max( 1, intval( $_GET['activity_paged'] ) ) : 1;
$activity_offset = ( $activity_page - 1 ) * $activity_per_page;

$all_attempts = Bearmor_Login_Protection::get_login_attempts( array( 
	'success' => null, 
	'limit' => $activity_per_page,
	'offset' => $activity_offset
) );

global $wpdb;
$activity_total = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_attempts" );
$activity_total_pages = ceil( $activity_total / $activity_per_page );

$blocked_ips = Bearmor_Login_Protection::get_blocked_ips();

// === LOGIN ANOMALIES ===
$anomaly_per_page = 25;
$anomaly_page = isset( $_GET['anomaly_paged'] ) ? max( 1, intval( $_GET['anomaly_paged'] ) ) : 1;
$anomaly_offset = ( $anomaly_page - 1 ) * $anomaly_per_page;

$anomalies = $wpdb->get_results(
	$wpdb->prepare(
		"SELECT a.*, u.user_login 
		FROM {$wpdb->prefix}bearmor_login_anomalies a
		LEFT JOIN {$wpdb->users} u ON a.user_id = u.ID
		WHERE a.status = 'new'
		ORDER BY a.detected_at DESC 
		LIMIT %d OFFSET %d",
		$anomaly_per_page,
		$anomaly_offset
	)
);

$anomaly_total = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_anomalies WHERE status = 'new'" );
$anomaly_total_pages = ceil( $anomaly_total / $anomaly_per_page );
?>

<div class="wrap">
	<h1>Login Security</h1>

	<!-- Two Column Layout -->
	<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
		
		<!-- LEFT: Login Activity -->
		<div>
			<h2 style="margin: 0 0 15px 0;">👤 Login Activity</h2>
			
			<!-- Blocked IPs Summary -->
			<?php if ( ! empty( $blocked_ips ) ) : ?>
				<div style="background: #fff5f5; border: 1px solid #d63638; padding: 12px; margin-bottom: 15px; border-radius: 5px;">
					<strong style="color: #d63638;">🚫 <?php echo count( $blocked_ips ); ?> Blocked IP<?php echo count( $blocked_ips ) > 1 ? 's' : ''; ?></strong>
				</div>
			<?php endif; ?>
			
			<!-- Login Attempts Table -->
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width: 25%;">Time</th>
						<th style="width: 30%;">User</th>
						<th style="width: 25%;">IP</th>
						<th style="width: 20%;">Status</th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $all_attempts ) ) : ?>
						<tr>
							<td colspan="4" style="text-align: center; padding: 20px; color: #666;">
								No login attempts recorded yet.
							</td>
						</tr>
					<?php else : ?>
						<?php foreach ( $all_attempts as $attempt ) : ?>
							<tr style="<?php echo $attempt->success ? '' : 'background: #fff5f5;'; ?>">
								<td style="font-size: 12px;">
									<?php echo esc_html( human_time_diff( strtotime( $attempt->attempted_at ), current_time( 'timestamp' ) ) . ' ago' ); ?>
								</td>
								<td>
									<code style="font-size: 11px;"><?php echo esc_html( $attempt->username ); ?></code>
								</td>
								<td>
									<code style="font-size: 11px;"><?php echo esc_html( $attempt->ip_address ); ?></code>
								</td>
								<td>
									<?php if ( $attempt->success ) : ?>
										<span style="color: #00a32a; font-weight: 600;">✓ Success</span>
									<?php else : ?>
										<span style="color: #d63638; font-weight: 600;">✗ Failed</span>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
			
			<!-- Pagination -->
			<?php if ( $activity_total_pages > 1 ) : ?>
				<div style="margin-top: 15px; text-align: center;">
					<?php
					$base_url = remove_query_arg( 'activity_paged' );
					for ( $i = 1; $i <= $activity_total_pages; $i++ ) :
						$class = ( $i === $activity_page ) ? 'button button-primary' : 'button';
						?>
						<a href="<?php echo esc_url( add_query_arg( 'activity_paged', $i, $base_url ) ); ?>" class="<?php echo $class; ?>" style="margin: 0 2px;">
							<?php echo $i; ?>
						</a>
					<?php endfor; ?>
				</div>
			<?php endif; ?>
		</div>

		<!-- RIGHT: Login Anomalies -->
		<div>
			<h2 style="margin: 0 0 15px 0;">⚠️ Login Anomalies</h2>
			
			<!-- Anomalies Table -->
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width: 25%;">Time</th>
						<th style="width: 25%;">User</th>
						<th style="width: 30%;">Reason</th>
						<th style="width: 20%;">Score</th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $anomalies ) ) : ?>
						<tr>
							<td colspan="4" style="text-align: center; padding: 20px; color: #666;">
								✅ No suspicious login activity detected.
							</td>
						</tr>
					<?php else : ?>
						<?php foreach ( $anomalies as $anomaly ) : ?>
							<?php
							$score_class = $anomaly->anomaly_score >= 80 ? '#d63638' : ( $anomaly->anomaly_score >= 50 ? '#f56e28' : '#666' );
							?>
							<tr>
								<td style="font-size: 12px;">
									<?php echo esc_html( human_time_diff( strtotime( $anomaly->detected_at ), current_time( 'timestamp' ) ) . ' ago' ); ?>
								</td>
								<td>
									<code style="font-size: 11px;"><?php echo esc_html( $anomaly->user_login ? $anomaly->user_login : 'Unknown' ); ?></code>
								</td>
								<td style="font-size: 12px;">
									<?php 
									// Format anomaly type into readable reason
									$reason = str_replace( '_', ' ', $anomaly->anomaly_type );
									$reason = ucwords( $reason );
									echo esc_html( $reason ); 
									?>
								</td>
								<td>
									<span style="color: <?php echo $score_class; ?>; font-weight: 600;">
										<?php echo esc_html( $anomaly->anomaly_score ); ?>/100
									</span>
								</td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
			
			<!-- Pagination -->
			<?php if ( $anomaly_total_pages > 1 ) : ?>
				<div style="margin-top: 15px; text-align: center;">
					<?php
					$base_url = remove_query_arg( 'anomaly_paged' );
					for ( $i = 1; $i <= $anomaly_total_pages; $i++ ) :
						$class = ( $i === $anomaly_page ) ? 'button button-primary' : 'button';
						?>
						<a href="<?php echo esc_url( add_query_arg( 'anomaly_paged', $i, $base_url ) ); ?>" class="<?php echo $class; ?>" style="margin: 0 2px;">
							<?php echo $i; ?>
						</a>
					<?php endfor; ?>
				</div>
			<?php endif; ?>
		</div>

	</div>
</div>
