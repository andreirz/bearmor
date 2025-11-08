<?php
/**
 * Login Anomalies Widget
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get critical anomalies count (score >= 80)
global $wpdb;
$critical_anomalies = (int) $wpdb->get_var(
	"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_anomalies 
	WHERE anomaly_score >= 80 
	AND status = 'new'"
);

// Get all new anomalies count
$all_anomalies = (int) $wpdb->get_var(
	"SELECT COUNT(*) FROM {$wpdb->prefix}bearmor_login_anomalies 
	WHERE status = 'new'"
);

$value_class = $critical_anomalies > 0 ? 'bearmor-value-critical' : ( $all_anomalies > 0 ? 'bearmor-value-warning' : 'bearmor-value-good' );
?>

<div class="bearmor-widget">
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-warning"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Login Anomalies</h3>
		<p class="bearmor-widget-value <?php echo esc_attr( $value_class ); ?>"><?php echo esc_html( $all_anomalies ); ?></p>
		<p class="bearmor-widget-label">Suspicious logins detected</p>
		<?php if ( $critical_anomalies > 0 ) : ?>
			<p style="margin: 8px 0 0 0; font-size: 12px; color: #d63638;">
				<strong>🚨 <?php echo esc_html( $critical_anomalies ); ?> critical alert<?php echo $critical_anomalies > 1 ? 's' : ''; ?></strong>
			</p>
		<?php endif; ?>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-login-anomalies' ) ); ?>" class="bearmor-widget-action">View Details</a>
	</div>
</div>
