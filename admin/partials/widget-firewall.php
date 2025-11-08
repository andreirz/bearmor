<?php
/**
 * Firewall Widget
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if Pro feature is available
$is_pro = Bearmor_License::is_pro();

// Get firewall blocks from last 24 hours (only if pro)
global $wpdb;
$blocked_requests = 0;
if ( $is_pro ) {
	$blocked_requests = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_firewall_blocks 
			WHERE blocked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
		)
	);
	$blocked_requests = $blocked_requests ? intval( $blocked_requests ) : 0;
}

// Set color based on count
if ( $blocked_requests === 0 ) {
	$value_class = 'bearmor-value-good';
} elseif ( $blocked_requests < 50 ) {
	$value_class = 'bearmor-value-warning';
} else {
	$value_class = 'bearmor-value-critical';
}

// Get the Security Logs page URL
$security_logs_url = admin_url( 'admin.php?page=bearmor-security-logs' );
?>

<div class="bearmor-widget <?php echo ! $is_pro ? 'bearmor-widget-pro' : ''; ?>">
	<?php if ( ! $is_pro ) : ?>
		<div class="bearmor-pro-badge">PRO</div>
	<?php endif; ?>
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-shield-alt"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Firewall</h3>
		<?php if ( $is_pro ) : ?>
			<p class="bearmor-widget-value <?php echo esc_attr( $value_class ); ?>"><?php echo esc_html( number_format( $blocked_requests ) ); ?></p>
			<p class="bearmor-widget-label">Blocked requests (24h)</p>
			<a href="<?php echo esc_url( $security_logs_url ); ?>" class="bearmor-widget-action">View Details</a>
		<?php else : ?>
			<p class="bearmor-widget-description">Advanced firewall protection with real-time threat blocking</p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-settings' ) ); ?>" class="bearmor-widget-action bearmor-upgrade-btn">Upgrade to Pro</a>
		<?php endif; ?>
	</div>
</div>
