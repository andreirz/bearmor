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

// Get firewall blocks (placeholder)
$blocked_requests = 0;
$value_class = 'bearmor-value-good';
?>

<div class="bearmor-widget">
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-shield-alt"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Firewall</h3>
		<p class="bearmor-widget-value <?php echo esc_attr( $value_class ); ?>"><?php echo esc_html( $blocked_requests ); ?></p>
		<p class="bearmor-widget-label">Blocked requests (24h)</p>
		<a href="#" class="bearmor-widget-action">View Details</a>
	</div>
</div>
