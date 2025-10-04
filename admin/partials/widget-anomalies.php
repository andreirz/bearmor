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

// Get anomalies count (placeholder)
$anomalies = 0;
$value_class = $anomalies > 0 ? 'bearmor-value-critical' : 'bearmor-value-good';
?>

<div class="bearmor-widget">
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-warning"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Login Anomalies</h3>
		<p class="bearmor-widget-value <?php echo esc_attr( $value_class ); ?>"><?php echo esc_html( $anomalies ); ?></p>
		<p class="bearmor-widget-label">Suspicious logins detected</p>
		<a href="#" class="bearmor-widget-action">View Details</a>
	</div>
</div>
