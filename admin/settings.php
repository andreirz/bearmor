<?php
/**
 * Settings View
 *
 * @package Bearmor_Security
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Save settings
if ( isset( $_POST['bearmor_save_settings'] ) && check_admin_referer( 'bearmor_settings' ) ) {
	$settings = get_option( 'bearmor_settings', array() );
	$settings['scan_schedule'] = sanitize_text_field( $_POST['scan_schedule'] );
	$settings['notification_email'] = sanitize_email( $_POST['notification_email'] );
	$settings['auto_quarantine'] = isset( $_POST['auto_quarantine'] ) ? true : false;
	$settings['auto_disable_vulnerable'] = isset( $_POST['auto_disable_vulnerable'] ) ? true : false;
	update_option( 'bearmor_settings', $settings );
	echo '<div class="notice notice-success"><p>Settings saved!</p></div>';
}

// Apply recommended hardening
if ( isset( $_POST['bearmor_apply_hardening'] ) && check_admin_referer( 'bearmor_settings' ) ) {
	// Placeholder for hardening actions (will be implemented in 1G)
	echo '<div class="notice notice-success"><p>Recommended hardening will be applied in future updates.</p></div>';
}

$settings = get_option( 'bearmor_settings', array() );
?>

<div class="wrap">
	<h1>Bearmor Security Settings</h1>
	<form method="post">
		<?php wp_nonce_field( 'bearmor_settings' ); ?>
		
		<h2>General Settings</h2>
		<table class="form-table">
			<tr>
				<th>Scan Schedule</th>
				<td>
					<select name="scan_schedule">
						<option value="manual" <?php selected( $settings['scan_schedule'], 'manual' ); ?>>Manual</option>
						<option value="daily" <?php selected( $settings['scan_schedule'], 'daily' ); ?>>Daily</option>
						<option value="weekly" <?php selected( $settings['scan_schedule'], 'weekly' ); ?>>Weekly</option>
					</select>
				</td>
			</tr>
			<tr>
				<th>Notification Email</th>
				<td>
					<input type="email" name="notification_email" value="<?php echo esc_attr( $settings['notification_email'] ); ?>" class="regular-text">
				</td>
			</tr>
		</table>

		<h2>Automated Actions</h2>
		<p class="description">⚠️ Warning: These actions will execute automatically without confirmation.</p>
		<table class="form-table">
			<tr>
				<th>Auto-Quarantine Malware</th>
				<td>
					<label>
						<input type="checkbox" name="auto_quarantine" value="1" <?php checked( ! empty( $settings['auto_quarantine'] ) ); ?>>
						Automatically quarantine detected malware files
					</label>
				</td>
			</tr>
			<tr>
				<th>Auto-Disable Vulnerable Plugins</th>
				<td>
					<label>
						<input type="checkbox" name="auto_disable_vulnerable" value="1" <?php checked( ! empty( $settings['auto_disable_vulnerable'] ) ); ?>>
						Automatically disable plugins with critical vulnerabilities (Pro feature)
					</label>
				</td>
			</tr>
		</table>

		<p>
			<button type="submit" name="bearmor_save_settings" class="button button-primary">Save & Apply</button>
			<button type="submit" name="bearmor_apply_hardening" class="button button-secondary" style="margin-left: 10px;">Apply Recommended Hardening</button>
		</p>
	</form>
</div>
