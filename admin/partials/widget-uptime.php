<?php
/**
 * Uptime Widget (Paid)
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Check if Pro is enabled (placeholder)
$is_pro = false;
?>

<div class="bearmor-widget bearmor-widget-pro">
	<div class="bearmor-pro-badge">PRO</div>
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-clock"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>Uptime Monitoring</h3>
		<?php if ( $is_pro ) : ?>
			<p class="bearmor-widget-value bearmor-value-good">99.9%</p>
			<p class="bearmor-widget-label">Uptime (30 days)</p>
			<a href="#" class="bearmor-widget-action">View Details</a>
		<?php else : ?>
			<p class="bearmor-widget-description">24/7 uptime monitoring with instant alerts</p>
			<a href="#" class="bearmor-widget-action bearmor-upgrade-btn">Upgrade to Pro</a>
		<?php endif; ?>
	</div>
</div>
