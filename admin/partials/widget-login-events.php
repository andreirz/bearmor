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

// Get login events (placeholder)
$failed_attempts = 0;
$value_class = $failed_attempts > 10 ? 'bearmor-value-critical' : ( $failed_attempts > 5 ? 'bearmor-value-warning' : 'bearmor-value-good' );
?>

<div class="bearmor-widget">
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-admin-users"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Login Activity</h3>
		<p class="bearmor-widget-value <?php echo esc_attr( $value_class ); ?>"><?php echo esc_html( $failed_attempts ); ?></p>
		<p class="bearmor-widget-label">Failed attempts (24h)</p>
		<a href="#" class="bearmor-widget-action">View Details</a>
	</div>
</div>
