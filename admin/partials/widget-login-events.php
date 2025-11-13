<?php
/**
 * Login Events Widget
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get failed login attempts in last 24 hours
global $wpdb;
$twenty_four_hours_ago = date( 'Y-m-d H:i:s', strtotime( '-24 hours' ) );
$failed_attempts = (int) $wpdb->get_var( $wpdb->prepare(
	"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_attempts 
	WHERE success = 0 
	AND attempted_at > %s",
	$twenty_four_hours_ago
) );

// Get currently blocked IPs (active blocks only)
$blocked_ips = (int) $wpdb->get_var(
	"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_blocked_ips 
	WHERE (permanent = 1) OR (expires_at IS NOT NULL AND expires_at > NOW())"
);

$failed_class = $failed_attempts > 10 ? 'bearmor-value-critical' : ( $failed_attempts > 5 ? 'bearmor-value-warning' : 'bearmor-value-good' );
$blocked_class = $blocked_ips > 0 ? 'bearmor-value-good' : 'bearmor-value-good'; // Green = we're protecting!
?>

<div class="bearmor-widget">
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-admin-users"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Login Activity</h3>
		<div style="display: flex; gap: 20px; margin: 10px 0;">
			<div style="flex: 1;">
				<p class="bearmor-widget-value <?php echo esc_attr( $failed_class ); ?>" style="margin: 0; font-size: 28px;"><?php echo esc_html( $failed_attempts ); ?></p>
				<p style="margin: 5px 0 0 0; font-size: 11px; color: #666;">Failed (24h)</p>
			</div>
			<div style="flex: 1;">
				<p class="bearmor-widget-value <?php echo esc_attr( $blocked_class ); ?>" style="margin: 0; font-size: 28px; color: #d63638;"><?php echo esc_html( $blocked_ips ); ?></p>
				<p style="margin: 5px 0 0 0; font-size: 11px; color: #666;">Blocked</p>
			</div>
		</div>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-login-security' ) ); ?>" class="bearmor-widget-action">View Details</a>
	</div>
</div>
