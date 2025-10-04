<?php
/**
 * File Changes Widget
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Get file changes count (real data)
$file_changes = Bearmor_Checksum::get_changed_count();
$value_class = $file_changes > 0 ? 'bearmor-value-critical' : 'bearmor-value-good';
?>

<div class="bearmor-widget">
	<div class="bearmor-widget-icon">
		<span class="dashicons dashicons-media-document"></span>
	</div>
	<div class="bearmor-widget-content">
		<h3>File Changes</h3>
		<p class="bearmor-widget-value <?php echo esc_attr( $value_class ); ?>"><?php echo esc_html( $file_changes ); ?></p>
		<p class="bearmor-widget-label">Modified files detected</p>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=bearmor-file-changes' ) ); ?>" class="bearmor-widget-action">View Details</a>
	</div>
</div>
